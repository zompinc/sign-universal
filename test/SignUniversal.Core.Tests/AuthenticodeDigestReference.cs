using System.Buffers.Binary;

namespace SignUniversal.Core.Tests;

/// <summary>
/// A second, deliberately naive implementation of the Authenticode digest, transcribed
/// straight from the 15-step procedure in "Windows Authenticode Portable Executable
/// Signature Format".
/// </summary>
/// <remarks>
/// <para>
/// It shares no code with <see cref="SignUniversal.Core.Authenticode.PeFile"/> and is
/// written for obviousness rather than efficiency: whole file in memory, no streaming, no
/// reuse. That is the point — it exists to disagree with the engine when the engine is
/// wrong, and the engine's streaming walk is where a transcription slip would hide.
/// </para>
/// <para>
/// Its own credibility comes from the corpus check in <c>PeDigestTests</c>: pointed at a
/// directory of already-signed binaries, it recomputes each digest and finds it inside
/// that file's own signature. That sweep is what originally settled the questions the
/// specification leaves ambiguous.
/// </para>
/// </remarks>
internal static class AuthenticodeDigestReference
{
    /// <summary>Computes the Authenticode digest of an in-memory PE image.</summary>
    /// <param name="image">The whole file.</param>
    /// <param name="hashAlgorithm">The digest algorithm.</param>
    /// <returns>The digest.</returns>
    public static byte[] ComputeDigest(byte[] image, HashAlgorithmName hashAlgorithm)
    {
        PeLayout layout = PeLayout.Read(image);

        using IncrementalHash hash = IncrementalHash.CreateHash(hashAlgorithm);

        // Headers, minus the checksum field and the certificate directory entry.
        hash.AppendData(image, 0, layout.ChecksumOffset);
        hash.AppendData(
            image,
            layout.ChecksumOffset + 4,
            layout.CertificateDirectoryOffset - (layout.ChecksumOffset + 4));
        hash.AppendData(
            image,
            layout.CertificateDirectoryOffset + 8,
            layout.SizeOfHeaders - (layout.CertificateDirectoryOffset + 8));

        int hashed = layout.SizeOfHeaders;

        foreach ((int offset, int size) in layout.Sections.OrderBy(section => section.Offset))
        {
            hash.AppendData(image, offset, size);
            hashed += size;
        }

        // Trailing data, except the certificate table itself.
        int trailing = image.Length - layout.CertificateTableSize - hashed;
        if (trailing > 0)
        {
            hash.AppendData(image, hashed, trailing);
        }

        return hash.GetHashAndReset();
    }

    /// <summary>Reads the attribute certificate table of a signed image.</summary>
    /// <param name="image">The whole file.</param>
    /// <returns>The table bytes, or <see langword="null"/> when the image is unsigned.</returns>
    public static byte[]? TryReadCertificateTable(byte[] image)
    {
        PeLayout layout = PeLayout.Read(image);

        if (layout.CertificateTableSize == 0)
        {
            return null;
        }

        return image.AsSpan(layout.CertificateTableOffset, layout.CertificateTableSize).ToArray();
    }

    private readonly record struct PeLayout(
        int ChecksumOffset,
        int CertificateDirectoryOffset,
        int CertificateTableOffset,
        int CertificateTableSize,
        int SizeOfHeaders,
        IReadOnlyList<(int Offset, int Size)> Sections)
    {
        public static PeLayout Read(byte[] image)
        {
            if (image.Length < 0x40 || BinaryPrimitives.ReadUInt16LittleEndian(image) != 0x5A4D)
            {
                throw new InvalidDataException("not a PE image");
            }

            int pe = (int)BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(0x3C));
            if (BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(pe)) != 0x00004550)
            {
                throw new InvalidDataException("not a PE image");
            }

            int sectionCount = BinaryPrimitives.ReadUInt16LittleEndian(image.AsSpan(pe + 6));
            int optionalHeaderSize = BinaryPrimitives.ReadUInt16LittleEndian(image.AsSpan(pe + 20));
            int optional = pe + 24;

            int magic = BinaryPrimitives.ReadUInt16LittleEndian(image.AsSpan(optional));
            bool pe32Plus = magic switch
            {
                0x10B => false,
                0x20B => true,
                _ => throw new InvalidDataException($"unsupported optional header magic 0x{magic:X}"),
            };

            int directories = optional + (pe32Plus ? 112 : 96);
            int rvaCount = (int)BinaryPrimitives.ReadUInt32LittleEndian(
                image.AsSpan(optional + (pe32Plus ? 108 : 92)));

            if (rvaCount <= 4)
            {
                throw new InvalidDataException("no attribute-certificate data directory");
            }

            int certificateDirectory = directories + (4 * 8);
            List<(int Offset, int Size)> sections = [];
            int sectionTable = optional + optionalHeaderSize;

            for (int i = 0; i < sectionCount; i++)
            {
                int entry = sectionTable + (i * 40);
                int rawSize = (int)BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(entry + 16));
                int rawOffset = (int)BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(entry + 20));

                if (rawSize > 0)
                {
                    sections.Add((rawOffset, rawSize));
                }
            }

            return new PeLayout(
                optional + 64,
                certificateDirectory,
                (int)BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(certificateDirectory)),
                (int)BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(certificateDirectory + 4)),
                (int)BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(optional + 60)),
                sections);
        }
    }
}
