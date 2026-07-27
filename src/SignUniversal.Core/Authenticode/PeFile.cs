using System.Buffers.Binary;
using System.Formats.Asn1;
using System.Security.Cryptography;

namespace SignUniversal.Core.Authenticode;

/// <summary>
/// Reads a PE image, computes its Authenticode digest, and embeds a signature into
/// the attribute certificate table.
/// </summary>
/// <remarks>
/// <para>
/// The digest follows the 15-step walk in "Windows Authenticode Portable Executable
/// Signature Format": hash the headers while skipping the optional-header
/// <c>CheckSum</c> field and the attribute-certificate data directory entry, then
/// hash each section in file order, then hash whatever trails the last section apart
/// from the certificate table itself. Those exclusions are what let a signature be
/// appended to a file without invalidating its own digest.
/// </para>
/// <para>
/// Page hashes are deferred; the signature carries a plain file digest.
/// </para>
/// </remarks>
public static class PeFile
{
    /// <summary>WIN_CERT_REVISION_2_0 — the only revision Authenticode uses.</summary>
    private const ushort WinCertificateRevision2 = 0x0200;

    /// <summary>WIN_CERT_TYPE_PKCS_SIGNED_DATA.</summary>
    private const ushort WinCertificateTypePkcsSignedData = 0x0002;

    /// <summary>Size of the WIN_CERTIFICATE header that prefixes the PKCS#7 blob.</summary>
    private const int WinCertificateHeaderSize = 8;

    /// <summary>Attribute certificate entries start on an 8-byte boundary.</summary>
    private const int CertificateAlignment = 8;

    private const int CopyBufferSize = 64 * 1024;

    /// <summary>Computes the Authenticode digest of a PE image.</summary>
    /// <param name="peImage">The PE image stream.</param>
    /// <param name="hashAlgorithm">The digest algorithm.</param>
    /// <returns>The Authenticode digest.</returns>
    /// <exception cref="InvalidDataException">The stream is not a well-formed PE image.</exception>
    public static byte[] ComputeAuthenticodeDigest(Stream peImage, HashAlgorithmName hashAlgorithm)
    {
        ArgumentNullException.ThrowIfNull(peImage);

        PeHeaders headers = PeHeaders.Read(peImage);
        long fileLength = peImage.Length;

        using IncrementalHash hash = IncrementalHash.CreateHash(hashAlgorithm);
        byte[] buffer = new byte[CopyBufferSize];

        // Everything up to the checksum, then everything between the checksum and the
        // certificate directory entry, then the rest of the headers. The two gaps are the
        // fields that signing itself rewrites.
        AppendRange(peImage, hash, buffer, 0, headers.CheckSumFieldOffset);
        AppendRange(peImage, hash, buffer, headers.CheckSumFieldOffset + 4, headers.CertificateDirectoryOffset);
        AppendRange(peImage, hash, buffer, headers.CertificateDirectoryOffset + 8, headers.SizeOfHeaders);

        long hashedBytes = headers.SizeOfHeaders;

        // Sections are hashed in file order. Any alignment padding between them is skipped:
        // only the bytes SizeOfRawData accounts for are covered.
        foreach (PeSection section in headers.Sections)
        {
            AppendRange(peImage, hash, buffer, section.Offset, section.Offset + section.Size);
            hashedBytes += section.Size;
        }

        // Trailing data (appended resources, our own alignment padding) is hashed too —
        // everything except the attribute certificate table.
        long trailingLength = fileLength - headers.CertificateTableSize - hashedBytes;
        if (trailingLength > 0)
        {
            AppendRange(peImage, hash, buffer, hashedBytes, hashedBytes + trailingLength);
        }

        return hash.GetHashAndReset();
    }

    /// <summary>
    /// Normalizes an image so a signature can be appended: removes an existing
    /// signature and pads the file to an 8-byte boundary.
    /// </summary>
    /// <param name="peImage">A readable, writable, seekable PE image stream.</param>
    /// <remarks>
    /// Idempotent. Call this before <see cref="ComputeAuthenticodeDigest"/>, because the
    /// padding it adds is itself covered by the digest.
    /// </remarks>
    /// <exception cref="NotSupportedException">
    /// The image carries an existing certificate table that is not at the end of the file,
    /// so it cannot be removed without moving unrelated data.
    /// </exception>
    public static void PrepareForSigning(Stream peImage)
    {
        ArgumentNullException.ThrowIfNull(peImage);
        EnsureWritable(peImage);

        PeHeaders headers = PeHeaders.Read(peImage);

        if (headers.CertificateTableSize != 0)
        {
            if (headers.CertificateTableOffset + headers.CertificateTableSize != peImage.Length)
            {
                throw new NotSupportedException(
                    "The existing attribute certificate table is not at the end of the file; " +
                    "removing it would move unrelated data.");
            }

            peImage.SetLength(headers.CertificateTableOffset);
            WriteCertificateDirectory(peImage, headers.CertificateDirectoryOffset, offset: 0, size: 0);
        }

        long padding = (CertificateAlignment - (peImage.Length % CertificateAlignment)) % CertificateAlignment;
        if (padding > 0)
        {
            peImage.Position = peImage.Length;
            peImage.Write(new byte[padding]);
        }

        peImage.Flush();
    }

    /// <summary>
    /// Appends a PKCS#7 SignedData blob as the image's attribute certificate table,
    /// points the data directory at it, and refreshes the PE checksum.
    /// </summary>
    /// <param name="peImage">A readable, writable, seekable PE image stream.</param>
    /// <param name="signedData">The DER-encoded SignedData to embed.</param>
    /// <exception cref="InvalidOperationException">
    /// The image has not been through <see cref="PrepareForSigning"/>.
    /// </exception>
    public static void EmbedSignature(Stream peImage, ReadOnlySpan<byte> signedData)
    {
        ArgumentNullException.ThrowIfNull(peImage);
        EnsureWritable(peImage);

        if (signedData.IsEmpty)
        {
            throw new ArgumentException("The SignedData blob is empty.", nameof(signedData));
        }

        PeHeaders headers = PeHeaders.Read(peImage);

        if (headers.CertificateTableSize != 0)
        {
            throw new InvalidOperationException(
                "The image is already signed. Call PrepareForSigning first to replace the signature.");
        }

        long tableOffset = peImage.Length;
        if (tableOffset % CertificateAlignment != 0)
        {
            throw new InvalidOperationException(
                "The image is not 8-byte aligned. Call PrepareForSigning before embedding a signature.");
        }

        int entryLength = checked(WinCertificateHeaderSize + signedData.Length);
        int paddedLength = (entryLength + (CertificateAlignment - 1)) & ~(CertificateAlignment - 1);

        if (tableOffset + paddedLength > uint.MaxValue)
        {
            throw new NotSupportedException(
                "The signed image would exceed 4 GB, which the attribute certificate directory cannot address.");
        }

        // WIN_CERTIFICATE { dwLength, wRevision, wCertificateType, bCertificate[] }.
        // dwLength covers the header and the 8-byte alignment padding — matching signtool,
        // whose output always has dwLength equal to the data directory's Size.
        Span<byte> entryHeader = stackalloc byte[WinCertificateHeaderSize];
        BinaryPrimitives.WriteUInt32LittleEndian(entryHeader, (uint)paddedLength);
        BinaryPrimitives.WriteUInt16LittleEndian(entryHeader[4..], WinCertificateRevision2);
        BinaryPrimitives.WriteUInt16LittleEndian(entryHeader[6..], WinCertificateTypePkcsSignedData);

        peImage.Position = tableOffset;
        peImage.Write(entryHeader);
        peImage.Write(signedData);

        if (paddedLength > entryLength)
        {
            peImage.Write(new byte[paddedLength - entryLength]);
        }

        WriteCertificateDirectory(peImage, headers.CertificateDirectoryOffset, (uint)tableOffset, (uint)paddedLength);

        // The checksum is excluded from the Authenticode digest, so it can be refreshed last.
        uint checksum = ComputeChecksum(peImage);
        Span<byte> checksumBytes = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(checksumBytes, checksum);
        peImage.Position = headers.CheckSumFieldOffset;
        peImage.Write(checksumBytes);
        peImage.Flush();
    }

    /// <summary>Reads the PKCS#7 SignedData embedded in a PE image, if any.</summary>
    /// <param name="peImage">The PE image stream.</param>
    /// <returns>The DER-encoded SignedData, or <see langword="null"/> when the image is unsigned.</returns>
    /// <exception cref="InvalidDataException">The certificate table is not a usable Authenticode entry.</exception>
    public static byte[]? ReadEmbeddedSignature(Stream peImage)
    {
        ArgumentNullException.ThrowIfNull(peImage);

        PeHeaders headers = PeHeaders.Read(peImage);
        if (headers.CertificateTableSize == 0)
        {
            return null;
        }

        if (headers.CertificateTableSize < WinCertificateHeaderSize)
        {
            throw new InvalidDataException("The attribute certificate table is too small to hold a WIN_CERTIFICATE.");
        }

        byte[] entry = new byte[headers.CertificateTableSize];
        peImage.Position = headers.CertificateTableOffset;
        peImage.ReadExactly(entry);

        ushort certificateType = BinaryPrimitives.ReadUInt16LittleEndian(entry.AsSpan(6));
        if (certificateType != WinCertificateTypePkcsSignedData)
        {
            throw new InvalidDataException(
                $"Unsupported attribute certificate type 0x{certificateType:X4}; expected PKCS#7 SignedData (0x0002).");
        }

        // The entry is zero-padded to an 8-byte boundary; trim to the DER value so the
        // result can be handed straight to SignedCms.
        ReadOnlySpan<byte> body = entry.AsSpan(WinCertificateHeaderSize);
        AsnDecoder.ReadSequence(body, AsnEncodingRules.BER, out _, out _, out int consumed);
        return body[..consumed].ToArray();
    }

    /// <summary>Computes the PE header checksum over the whole file.</summary>
    /// <param name="peImage">The PE image stream.</param>
    /// <returns>The value the optional header's <c>CheckSum</c> field should hold.</returns>
    /// <remarks>
    /// A 16-bit ones-complement sum of the file with the checksum field itself treated as
    /// zero, plus the file length. Windows only enforces it for kernel-mode images, but
    /// signtool keeps it current and so do we.
    /// </remarks>
    public static uint ComputeChecksum(Stream peImage)
    {
        ArgumentNullException.ThrowIfNull(peImage);

        PeHeaders headers = PeHeaders.Read(peImage);
        long fileLength = peImage.Length;
        long checkSumOffset = headers.CheckSumFieldOffset;

        uint sum = 0;
        byte[] buffer = new byte[CopyBufferSize];
        long position = 0;
        int carryByte = -1;

        peImage.Position = 0;
        while (position < fileLength)
        {
            int read = peImage.Read(buffer, 0, (int)Math.Min(buffer.Length, fileLength - position));
            if (read == 0)
            {
                break;
            }

            for (int i = 0; i < read; i++)
            {
                long offset = position + i;
                byte value = offset >= checkSumOffset && offset < checkSumOffset + 4 ? (byte)0 : buffer[i];

                if (carryByte < 0)
                {
                    carryByte = value;
                    continue;
                }

                sum = Fold(sum + (uint)(carryByte | (value << 8)));
                carryByte = -1;
            }

            position += read;
        }

        if (carryByte >= 0)
        {
            sum = Fold(sum + (uint)carryByte);
        }

        sum = Fold(sum);
        return (uint)(sum + (ulong)fileLength);

        static uint Fold(uint value) => (value & 0xFFFF) + (value >> 16);
    }

    private static void WriteCertificateDirectory(Stream peImage, long directoryOffset, uint offset, uint size)
    {
        Span<byte> entry = stackalloc byte[8];
        BinaryPrimitives.WriteUInt32LittleEndian(entry, offset);
        BinaryPrimitives.WriteUInt32LittleEndian(entry[4..], size);
        peImage.Position = directoryOffset;
        peImage.Write(entry);
    }

    private static void AppendRange(Stream peImage, IncrementalHash hash, byte[] buffer, long start, long end)
    {
        if (end <= start)
        {
            return;
        }

        peImage.Position = start;
        long remaining = end - start;
        while (remaining > 0)
        {
            int read = peImage.Read(buffer, 0, (int)Math.Min(buffer.Length, remaining));
            if (read == 0)
            {
                throw new InvalidDataException(
                    $"Malformed PE image: expected {remaining} more bytes before offset {end}.");
            }

            hash.AppendData(buffer, 0, read);
            remaining -= read;
        }
    }

    private static void EnsureWritable(Stream peImage)
    {
        if (!peImage.CanWrite || !peImage.CanSeek || !peImage.CanRead)
        {
            throw new ArgumentException(
                "The PE image stream must be readable, writable, and seekable.", nameof(peImage));
        }
    }
}
