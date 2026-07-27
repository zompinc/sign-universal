using System.Buffers.Binary;

namespace SignUniversal.Core.Authenticode;

/// <summary>
/// The subset of the PE/COFF headers that Authenticode cares about: the two field
/// ranges the digest must skip, the section table, and the attribute-certificate
/// data directory where the signature is anchored.
/// </summary>
/// <remarks>
/// PE32 and PE32+ differ only in the optional header's standard fields (PE32+ drops
/// <c>BaseOfData</c> and widens <c>ImageBase</c> and the four stack/heap sizes), so
/// <c>SizeOfHeaders</c> and <c>CheckSum</c> land at the same optional-header offsets
/// in both, while the data directories do not.
/// </remarks>
internal sealed class PeHeaders
{
    private const int DosHeaderSize = 0x40;
    private const int DosSignature = 0x5A4D;              // "MZ"
    private const int LfaNewOffset = 0x3C;
    private const uint PeSignature = 0x00004550;          // "PE\0\0"
    private const int CoffHeaderSize = 24;                // PE signature (4) + COFF header (20)
    private const int SectionHeaderSize = 40;
    private const int Pe32Magic = 0x10B;
    private const int Pe32PlusMagic = 0x20B;
    private const int CheckSumOffsetInOptionalHeader = 64;
    private const int SizeOfHeadersOffsetInOptionalHeader = 60;
    private const int CertificateDirectoryIndex = 4;
    private const int DataDirectoryEntrySize = 8;

    private PeHeaders(
        bool isPe32Plus,
        long checkSumFieldOffset,
        long certificateDirectoryOffset,
        long certificateTableOffset,
        long certificateTableSize,
        long sizeOfHeaders,
        IReadOnlyList<PeSection> sections)
    {
        IsPe32Plus = isPe32Plus;
        CheckSumFieldOffset = checkSumFieldOffset;
        CertificateDirectoryOffset = certificateDirectoryOffset;
        CertificateTableOffset = certificateTableOffset;
        CertificateTableSize = certificateTableSize;
        SizeOfHeaders = sizeOfHeaders;
        Sections = sections;
    }

    /// <summary>Gets a value indicating whether the image uses the PE32+ optional header.</summary>
    public bool IsPe32Plus { get; }

    /// <summary>Gets the file offset of the optional header's 4-byte <c>CheckSum</c> field.</summary>
    public long CheckSumFieldOffset { get; }

    /// <summary>Gets the file offset of the 8-byte attribute-certificate data directory entry.</summary>
    public long CertificateDirectoryOffset { get; }

    /// <summary>Gets the file offset of the attribute certificate table, or 0 when unsigned.</summary>
    /// <remarks>
    /// Unlike every other data directory, this entry holds a file offset rather than an RVA.
    /// </remarks>
    public long CertificateTableOffset { get; }

    /// <summary>Gets the size in bytes of the attribute certificate table, or 0 when unsigned.</summary>
    public long CertificateTableSize { get; }

    /// <summary>Gets the combined size of all headers, rounded up to the file alignment.</summary>
    public long SizeOfHeaders { get; }

    /// <summary>Gets the sections that occupy space in the file, in file order.</summary>
    public IReadOnlyList<PeSection> Sections { get; }

    /// <summary>Parses the headers of a PE image.</summary>
    /// <param name="peImage">A readable, seekable stream positioned anywhere.</param>
    /// <returns>The parsed headers.</returns>
    /// <exception cref="InvalidDataException">The stream is not a well-formed PE image.</exception>
    public static PeHeaders Read(Stream peImage)
    {
        ArgumentNullException.ThrowIfNull(peImage);

        if (!peImage.CanRead || !peImage.CanSeek)
        {
            throw new ArgumentException("The PE image stream must be readable and seekable.", nameof(peImage));
        }

        long fileLength = peImage.Length;
        byte[] dosHeader = ReadAt(peImage, 0, DosHeaderSize, "DOS header");

        if (BinaryPrimitives.ReadUInt16LittleEndian(dosHeader) != DosSignature)
        {
            throw new InvalidDataException("Not a PE image: the file does not start with the 'MZ' signature.");
        }

        uint peOffset = BinaryPrimitives.ReadUInt32LittleEndian(dosHeader.AsSpan(LfaNewOffset));
        byte[] coffHeader = ReadAt(peImage, peOffset, CoffHeaderSize, "COFF header");

        if (BinaryPrimitives.ReadUInt32LittleEndian(coffHeader) != PeSignature)
        {
            throw new InvalidDataException("Not a PE image: the 'PE\\0\\0' signature is missing.");
        }

        int sectionCount = BinaryPrimitives.ReadUInt16LittleEndian(coffHeader.AsSpan(6));
        int optionalHeaderSize = BinaryPrimitives.ReadUInt16LittleEndian(coffHeader.AsSpan(20));
        long optionalHeaderOffset = peOffset + CoffHeaderSize;
        byte[] optionalHeader = ReadAt(peImage, optionalHeaderOffset, optionalHeaderSize, "optional header");

        int magic = optionalHeaderSize >= 2 ? BinaryPrimitives.ReadUInt16LittleEndian(optionalHeader) : 0;
        bool isPe32Plus = magic switch
        {
            Pe32Magic => false,
            Pe32PlusMagic => true,
            _ => throw new InvalidDataException(
                $"Unsupported optional header magic 0x{magic:X}; expected PE32 (0x10B) or PE32+ (0x20B)."),
        };

        // NumberOfRvaAndSizes sits just past the loader flags; the data directories follow it.
        int rvaCountOffset = isPe32Plus ? 108 : 92;
        int dataDirectoriesOffset = isPe32Plus ? 112 : 96;
        int certificateDirectoryInOptionalHeader =
            dataDirectoriesOffset + (CertificateDirectoryIndex * DataDirectoryEntrySize);

        if (optionalHeaderSize < certificateDirectoryInOptionalHeader + DataDirectoryEntrySize)
        {
            throw new InvalidDataException(
                "The optional header is too small to contain an attribute-certificate data directory.");
        }

        uint numberOfRvaAndSizes = BinaryPrimitives.ReadUInt32LittleEndian(optionalHeader.AsSpan(rvaCountOffset));
        if (numberOfRvaAndSizes <= CertificateDirectoryIndex)
        {
            throw new NotSupportedException(
                "The image declares no attribute-certificate data directory, so a signature cannot be anchored. " +
                "Growing the data directory table is not supported.");
        }

        long sizeOfHeaders = BinaryPrimitives.ReadUInt32LittleEndian(
            optionalHeader.AsSpan(SizeOfHeadersOffsetInOptionalHeader));
        if (sizeOfHeaders > fileLength)
        {
            throw new InvalidDataException(
                $"SizeOfHeaders ({sizeOfHeaders}) extends past the end of the file ({fileLength}).");
        }

        long certificateDirectoryOffset = optionalHeaderOffset + certificateDirectoryInOptionalHeader;
        if (certificateDirectoryOffset + DataDirectoryEntrySize > sizeOfHeaders)
        {
            throw new InvalidDataException(
                "The attribute-certificate data directory lies outside the region covered by SizeOfHeaders.");
        }

        uint certificateTableOffset = BinaryPrimitives.ReadUInt32LittleEndian(
            optionalHeader.AsSpan(certificateDirectoryInOptionalHeader));
        uint certificateTableSize = BinaryPrimitives.ReadUInt32LittleEndian(
            optionalHeader.AsSpan(certificateDirectoryInOptionalHeader + 4));

        if (certificateTableSize != 0 && certificateTableOffset + (long)certificateTableSize > fileLength)
        {
            throw new InvalidDataException("The attribute certificate table extends past the end of the file.");
        }

        byte[] sectionTable = ReadAt(
            peImage,
            optionalHeaderOffset + optionalHeaderSize,
            sectionCount * SectionHeaderSize,
            "section table");

        List<PeSection> sections = new(sectionCount);
        for (int i = 0; i < sectionCount; i++)
        {
            ReadOnlySpan<byte> header = sectionTable.AsSpan(i * SectionHeaderSize, SectionHeaderSize);
            uint rawSize = BinaryPrimitives.ReadUInt32LittleEndian(header[16..]);
            uint rawOffset = BinaryPrimitives.ReadUInt32LittleEndian(header[20..]);

            // The digest skips sections with no file content (.bss and friends).
            if (rawSize == 0)
            {
                continue;
            }

            if (rawOffset + (long)rawSize > fileLength)
            {
                throw new InvalidDataException(
                    $"Section {i} spans [{rawOffset}, {rawOffset + (long)rawSize}), past the end of the file ({fileLength}).");
            }

            sections.Add(new PeSection(rawOffset, rawSize));
        }

        // The Authenticode digest walks sections in file order, not section-table order.
        sections.Sort(static (left, right) => left.Offset.CompareTo(right.Offset));

        return new PeHeaders(
            isPe32Plus,
            optionalHeaderOffset + CheckSumOffsetInOptionalHeader,
            certificateDirectoryOffset,
            certificateTableOffset,
            certificateTableSize,
            sizeOfHeaders,
            sections);
    }

    private static byte[] ReadAt(Stream stream, long offset, int count, string what)
    {
        if (offset < 0 || count < 0 || offset + count > stream.Length)
        {
            throw new InvalidDataException(
                $"Malformed PE image: the {what} at offset {offset} ({count} bytes) does not fit in the file.");
        }

        byte[] buffer = new byte[count];
        stream.Position = offset;
        stream.ReadExactly(buffer);
        return buffer;
    }
}

/// <summary>A section's footprint in the file.</summary>
/// <param name="Offset">The file offset of the section's raw data (<c>PointerToRawData</c>).</param>
/// <param name="Size">The size of the section's raw data (<c>SizeOfRawData</c>).</param>
internal readonly record struct PeSection(long Offset, long Size);
