using System.Buffers.Binary;

namespace SignUniversal.Core.Tests;

/// <summary>
/// Builds minimal but structurally valid PE images, deterministically, so digest
/// behaviour can be pinned down for layouts a compiler will not readily produce —
/// PE32+, and headers separated from the first section by alignment padding.
/// </summary>
internal static class SyntheticPe
{
    public const int SizeOfHeaders = 0x200;
    public const int SectionSize = 0x200;
    public const int ChecksumPlaceholder = unchecked((int)0xDEADBEEF);

    private const int PeHeaderOffset = 0x80;
    private const int OptionalHeaderOffset = PeHeaderOffset + 24;
    private const int SectionHeaderSize = 40;
    private const int SectionCount = 2;

    /// <summary>Builds a two-section image.</summary>
    /// <param name="pe32Plus">Emit a PE32+ optional header instead of PE32.</param>
    /// <param name="headerGap">Bytes of unowned padding between the headers and the first section.</param>
    /// <param name="trailingBytes">Bytes appended after the last section.</param>
    /// <returns>The image bytes.</returns>
    public static byte[] Build(bool pe32Plus, int headerGap = 0, int trailingBytes = 0)
    {
        int firstSection = SizeOfHeaders + headerGap;
        int length = firstSection + (SectionCount * SectionSize) + trailingBytes;

        // Non-zero filler everywhere, so a range that is wrongly included or excluded
        // changes the digest instead of hashing as zeros either way.
        byte[] image = new byte[length];
        for (int i = 0; i < image.Length; i++)
        {
            image[i] = (byte)((i * 37) ^ 0x5A);
        }

        Span<byte> span = image;
        span[..PeHeaderOffset].Clear();
        BinaryPrimitives.WriteUInt16LittleEndian(span, 0x5A4D);                          // "MZ"
        BinaryPrimitives.WriteUInt32LittleEndian(span[0x3C..], PeHeaderOffset);          // e_lfanew

        int optionalHeaderSize = pe32Plus ? 0xF0 : 0xE0;
        BinaryPrimitives.WriteUInt32LittleEndian(span[PeHeaderOffset..], 0x00004550);    // "PE\0\0"
        BinaryPrimitives.WriteUInt16LittleEndian(span[(PeHeaderOffset + 4)..], pe32Plus ? (ushort)0x8664 : (ushort)0x014C);
        BinaryPrimitives.WriteUInt16LittleEndian(span[(PeHeaderOffset + 6)..], SectionCount);
        BinaryPrimitives.WriteUInt32LittleEndian(span[(PeHeaderOffset + 8)..], 0x11223344);
        BinaryPrimitives.WriteUInt32LittleEndian(span[(PeHeaderOffset + 12)..], 0);
        BinaryPrimitives.WriteUInt32LittleEndian(span[(PeHeaderOffset + 16)..], 0);
        BinaryPrimitives.WriteUInt16LittleEndian(span[(PeHeaderOffset + 20)..], (ushort)optionalHeaderSize);
        BinaryPrimitives.WriteUInt16LittleEndian(span[(PeHeaderOffset + 22)..], 0x2022);

        Span<byte> optional = span.Slice(OptionalHeaderOffset, optionalHeaderSize);
        optional.Clear();
        BinaryPrimitives.WriteUInt16LittleEndian(optional, pe32Plus ? (ushort)0x20B : (ushort)0x10B);
        BinaryPrimitives.WriteUInt32LittleEndian(optional[32..], 0x1000);                // SectionAlignment
        BinaryPrimitives.WriteUInt32LittleEndian(optional[36..], 0x200);                 // FileAlignment
        BinaryPrimitives.WriteUInt32LittleEndian(optional[56..], 0x3000);                // SizeOfImage
        BinaryPrimitives.WriteUInt32LittleEndian(optional[60..], SizeOfHeaders);
        BinaryPrimitives.WriteInt32LittleEndian(optional[64..], ChecksumPlaceholder);    // CheckSum

        // NumberOfRvaAndSizes; the 16 directory entries that follow stay zeroed, which is
        // what an unsigned image looks like.
        BinaryPrimitives.WriteUInt32LittleEndian(optional[(pe32Plus ? 108 : 92)..], 16);

        int sectionTable = OptionalHeaderOffset + optionalHeaderSize;
        for (int i = 0; i < SectionCount; i++)
        {
            Span<byte> header = span.Slice(sectionTable + (i * SectionHeaderSize), SectionHeaderSize);
            header.Clear();
            ".text\0\0\0"u8.CopyTo(header);
            header[1] = (byte)('a' + i);
            BinaryPrimitives.WriteUInt32LittleEndian(header[8..], SectionSize);                       // VirtualSize
            BinaryPrimitives.WriteUInt32LittleEndian(header[12..], (uint)(0x1000 * (i + 1)));         // VirtualAddress
            BinaryPrimitives.WriteUInt32LittleEndian(header[16..], SectionSize);                      // SizeOfRawData
            BinaryPrimitives.WriteUInt32LittleEndian(header[20..], (uint)(firstSection + (i * SectionSize)));
        }

        return image;
    }

    /// <summary>Gets the file offset of the first section's raw data.</summary>
    /// <param name="headerGap">The gap the image was built with.</param>
    /// <returns>The offset.</returns>
    public static int FirstSectionOffset(int headerGap) => SizeOfHeaders + headerGap;

    /// <summary>Gets the file offset of the optional header's <c>CheckSum</c> field.</summary>
    public static int ChecksumFieldOffset => OptionalHeaderOffset + 64;

    /// <summary>Gets the file offset of the attribute-certificate data directory entry.</summary>
    /// <param name="pe32Plus">Whether the image uses a PE32+ optional header.</param>
    /// <returns>The offset.</returns>
    public static int CertificateDirectoryOffset(bool pe32Plus) =>
        OptionalHeaderOffset + (pe32Plus ? 112 : 96) + (4 * 8);
}
