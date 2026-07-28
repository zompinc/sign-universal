using System.Buffers.Binary;
using System.Text;
using OpenMcdf;

namespace SignUniversal.Core.Msi;

/// <summary>
/// Reads an MSI package, computes its Authenticode digest, and writes the signature
/// into the <c>DigitalSignature</c> stream.
/// </summary>
/// <remarks>
/// <para>
/// An MSI is an OLE compound file, so unlike a PE image there is no offset arithmetic:
/// the digest covers the streams themselves. The order is what matters, and it is not
/// the order the streams appear in the file — they are sorted by the raw bytes of their
/// UTF-16LE names. That distinction is real, because MSI mangles table names into code
/// points around U+3800–U+4800, where byte order and code-unit order disagree.
/// </para>
/// <para>
/// The digest is: the <c>MsiDigitalSignatureEx</c> pre-hash if the package has one,
/// then every other stream in that order except the two signature streams, then the root
/// storage's CLSID. Established against a Microsoft-signed package by recomputing its
/// digest and matching the one inside its own signature.
/// </para>
/// </remarks>
public static class MsiFile
{
    /// <summary>The stream holding the PKCS#7 signature. The name starts with U+0005.</summary>
    public const string SignatureStreamName = "\u0005DigitalSignature";

    /// <summary>The stream holding the pre-hash over the package's metadata.</summary>
    /// <remarks>
    /// Written only when signing with the extended option. When present it is covered by
    /// the digest, so it cannot be added or dropped without re-signing.
    /// </remarks>
    public const string ExtendedSignatureStreamName = "\u0005MsiDigitalSignatureEx";

    /// <summary>Computes the Authenticode digest of an MSI compound file.</summary>
    /// <param name="compoundFile">The MSI file stream.</param>
    /// <param name="hashAlgorithm">The digest algorithm.</param>
    /// <returns>The Authenticode digest.</returns>
    public static byte[] ComputeAuthenticodeDigest(Stream compoundFile, HashAlgorithmName hashAlgorithm)
    {
        ArgumentNullException.ThrowIfNull(compoundFile);

        compoundFile.Position = 0;
        using RootStorage root = RootStorage.Open(compoundFile, StorageModeFlags.LeaveOpen);

        using IncrementalHash hash = IncrementalHash.CreateHash(hashAlgorithm);

        // The pre-hash comes first when the package carries one.
        if (root.EnumerateEntries().Any(entry => entry.Name == ExtendedSignatureStreamName))
        {
            hash.AppendData(ReadStream(root, ExtendedSignatureStreamName));
        }

        AppendStorage(hash, root);

        // The root storage's class identifier closes the digest.
        hash.AppendData(root.EntryInfo.CLSID.ToByteArray());

        return hash.GetHashAndReset();
    }

    /// <summary>
    /// Computes the pre-hash over the package's metadata — what goes in the
    /// <c>MsiDigitalSignatureEx</c> stream.
    /// </summary>
    /// <param name="compoundFile">The MSI file stream.</param>
    /// <param name="hashAlgorithm">The digest algorithm.</param>
    /// <returns>The pre-hash.</returns>
    /// <remarks>
    /// <para>
    /// Where the main digest covers stream <em>contents</em>, this covers their
    /// <em>descriptions</em>: names, sizes, class identifiers, state bits, and timestamps.
    /// Together they mean a package cannot be altered by rearranging or renaming its parts
    /// any more than by editing them.
    /// </para>
    /// <para>
    /// The layout was derived by reproducing the pre-hash signtool itself wrote for a
    /// package, then confirmed against a second, unrelated signed package. It reads the
    /// directory entries directly because the fields it needs — state bits especially —
    /// are not surfaced by the compound-file reader.
    /// </para>
    /// </remarks>
    public static byte[] ComputeMetadataPreHash(Stream compoundFile, HashAlgorithmName hashAlgorithm)
    {
        ArgumentNullException.ThrowIfNull(compoundFile);

        List<byte[]> directory = ReadDirectoryEntries(compoundFile);

        byte[]? root = directory.FirstOrDefault(entry => entry[EntryTypeOffset] == RootEntryType)
            ?? throw new InvalidDataException("The compound file has no root directory entry.");

        using IncrementalHash hash = IncrementalHash.CreateHash(hashAlgorithm);

        // The root contributes only its identity, not a name.
        hash.AppendData(root, ClassIdOffset, ClassIdLength);
        hash.AppendData(root, StateBitsOffset, StateBitsLength);

        IEnumerable<byte[]> ordered = directory
            .Where(entry => entry[EntryTypeOffset] is StorageEntryType or StreamEntryType)
            .Where(entry => EntryName(entry) is not (SignatureStreamName or ExtendedSignatureStreamName))
            .OrderBy(EntryName, Utf16NameComparer.Instance);

        foreach (byte[] entry in ordered)
        {
            hash.AppendData(entry, 0, NameLength(entry));

            if (entry[EntryTypeOffset] == StorageEntryType)
            {
                hash.AppendData(entry, ClassIdOffset, ClassIdLength);
            }
            else
            {
                hash.AppendData(entry, StreamSizeOffset, 4);
            }

            hash.AppendData(entry, StateBitsOffset, StateBitsLength);
            hash.AppendData(entry, CreationTimeOffset, 8);
            hash.AppendData(entry, ModifiedTimeOffset, 8);
        }

        return hash.GetHashAndReset();
    }

    /// <summary>Reads the PKCS#7 SignedData embedded in an MSI, if any.</summary>
    /// <param name="compoundFile">The MSI file stream.</param>
    /// <returns>The DER-encoded SignedData, or <see langword="null"/> when unsigned.</returns>
    public static byte[]? ReadEmbeddedSignature(Stream compoundFile)
    {
        ArgumentNullException.ThrowIfNull(compoundFile);

        compoundFile.Position = 0;
        using RootStorage root = RootStorage.Open(compoundFile, StorageModeFlags.LeaveOpen);

        return root.ContainsEntry(SignatureStreamName) ? ReadStream(root, SignatureStreamName) : null;
    }

    /// <summary>Removes any signature streams, leaving the package ready to be signed.</summary>
    /// <param name="compoundFile">A readable, writable MSI file stream.</param>
    /// <remarks>Idempotent. Call before computing the digest, since the pre-hash is covered by it.</remarks>
    public static void PrepareForSigning(Stream compoundFile)
    {
        ArgumentNullException.ThrowIfNull(compoundFile);

        compoundFile.Position = 0;
        using RootStorage root = RootStorage.Open(compoundFile, StorageModeFlags.LeaveOpen);

        foreach (string name in new[] { SignatureStreamName, ExtendedSignatureStreamName })
        {
            if (root.ContainsEntry(name))
            {
                root.Delete(name);
            }
        }

        // Non-transacted storage writes through to the underlying stream; Flush pushes the
        // directory changes out without waiting for disposal.
        root.Flush(consolidate: false);
    }

    /// <summary>Computes the metadata pre-hash and writes it into the package.</summary>
    /// <param name="compoundFile">A readable, writable MSI file stream.</param>
    /// <param name="hashAlgorithm">The digest algorithm.</param>
    /// <returns>The pre-hash that was written.</returns>
    /// <remarks>
    /// Must happen before the digest is computed, because the digest covers this stream's
    /// contents. signtool writes one unconditionally, so packages we sign carry one too.
    /// </remarks>
    public static byte[] WriteMetadataPreHash(Stream compoundFile, HashAlgorithmName hashAlgorithm)
    {
        ArgumentNullException.ThrowIfNull(compoundFile);

        byte[] preHash = ComputeMetadataPreHash(compoundFile, hashAlgorithm);

        compoundFile.Position = 0;
        using (RootStorage root = RootStorage.Open(compoundFile, StorageModeFlags.LeaveOpen))
        {
            if (root.ContainsEntry(ExtendedSignatureStreamName))
            {
                root.Delete(ExtendedSignatureStreamName);
            }

            using (CfbStream stream = root.CreateStream(ExtendedSignatureStreamName))
            {
                stream.Write(preHash, 0, preHash.Length);
            }

            root.Flush(consolidate: false);
        }

        return preHash;
    }

    /// <summary>Writes a PKCS#7 SignedData blob into the package's signature stream.</summary>
    /// <param name="compoundFile">A readable, writable MSI file stream.</param>
    /// <param name="signedData">The DER-encoded SignedData to embed.</param>
    public static void EmbedSignature(Stream compoundFile, byte[] signedData)
    {
        ArgumentNullException.ThrowIfNull(compoundFile);
        ArgumentNullException.ThrowIfNull(signedData);

        compoundFile.Position = 0;
        using RootStorage root = RootStorage.Open(compoundFile, StorageModeFlags.LeaveOpen);

        if (root.ContainsEntry(SignatureStreamName))
        {
            root.Delete(SignatureStreamName);
        }

        using (CfbStream stream = root.CreateStream(SignatureStreamName))
        {
            stream.Write(signedData, 0, signedData.Length);
        }

        root.Flush(consolidate: false);
    }

    /// <summary>
    /// Hashes one storage's streams in name order, descending into child storages as it
    /// goes.
    /// </summary>
    /// <remarks>
    /// The walk is recursive because a compound file is a tree. Packages carrying
    /// transforms or embedded storages have one; the flat ones do not, which is exactly
    /// how a non-recursive walk can look correct against a sample and be wrong in general.
    /// </remarks>
    private static void AppendStorage(IncrementalHash hash, Storage storage)
    {
        IEnumerable<EntryInfo> ordered = storage.EnumerateEntries()
            .Where(entry => entry.Name != SignatureStreamName && entry.Name != ExtendedSignatureStreamName)
            .OrderBy(entry => entry.Name, Utf16NameComparer.Instance);

        foreach (EntryInfo entry in ordered)
        {
            if (entry.Type == EntryType.Storage)
            {
                AppendStorage(hash, storage.OpenStorage(entry.Name));
            }
            else
            {
                hash.AppendData(ReadStream(storage, entry.Name));
            }
        }
    }

    private const int DirectoryEntrySize = 128;
    private const int NameLengthOffset = 0x40;
    private const int EntryTypeOffset = 0x42;
    private const int ClassIdOffset = 0x50;
    private const int ClassIdLength = 16;
    private const int StateBitsOffset = 0x60;
    private const int StateBitsLength = 4;
    private const int CreationTimeOffset = 0x64;
    private const int ModifiedTimeOffset = 0x6C;
    private const int StreamSizeOffset = 0x78;
    private const byte StorageEntryType = 1;
    private const byte StreamEntryType = 2;
    private const byte RootEntryType = 5;

    private static int NameLength(byte[] entry) =>
        Math.Max(0, BinaryPrimitives.ReadUInt16LittleEndian(entry.AsSpan(NameLengthOffset)) - 2);

    private static string EntryName(byte[] entry) =>
        Encoding.Unicode.GetString(entry, 0, NameLength(entry));

    /// <summary>Walks the compound file's directory chain and returns the raw entries.</summary>
    private static List<byte[]> ReadDirectoryEntries(Stream compoundFile)
    {
        byte[] header = new byte[512];
        compoundFile.Position = 0;
        compoundFile.ReadExactly(header);

        int sectorSize = 1 << BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(0x1E));
        uint sector = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(0x30));

        List<byte[]> entries = [];
        HashSet<uint> visited = [];
        byte[] buffer = new byte[sectorSize];

        while (sector < 0xFFFFFFF0 && visited.Add(sector))
        {
            compoundFile.Position = (long)(sector + 1) * sectorSize;
            compoundFile.ReadExactly(buffer);

            for (int offset = 0; offset + DirectoryEntrySize <= sectorSize; offset += DirectoryEntrySize)
            {
                if (buffer[offset + EntryTypeOffset] != 0)
                {
                    entries.Add(buffer.AsSpan(offset, DirectoryEntrySize).ToArray());
                }
            }

            sector = NextSector(compoundFile, header, sectorSize, sector);
        }

        return entries;
    }

    /// <summary>Follows the FAT to the next sector in a chain.</summary>
    /// <remarks>
    /// Only the 109 FAT sector pointers in the header are consulted. That covers packages
    /// into the hundreds of megabytes; a larger one would need the DIFAT chain, and is
    /// rejected rather than silently mis-hashed.
    /// </remarks>
    private static uint NextSector(Stream compoundFile, byte[] header, int sectorSize, uint sector)
    {
        int perSector = sectorSize / 4;
        int fatIndex = (int)(sector / perSector);

        if (fatIndex >= 109)
        {
            throw new NotSupportedException(
                "The package's directory extends beyond the header's FAT pointers; DIFAT chains are not supported yet.");
        }

        uint fatSector = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(0x4C + (4 * fatIndex)));
        byte[] slot = new byte[4];
        compoundFile.Position = ((long)(fatSector + 1) * sectorSize) + (4 * (sector % perSector));
        compoundFile.ReadExactly(slot);
        return BinaryPrimitives.ReadUInt32LittleEndian(slot);
    }

    private static byte[] ReadStream(Storage storage, string name)
    {
        using CfbStream stream = storage.OpenStream(name);
        byte[] buffer = new byte[stream.Length];
        stream.ReadExactly(buffer);
        return buffer;
    }

    /// <summary>
    /// Orders names by the raw bytes of their UTF-16LE encoding, then by length.
    /// </summary>
    /// <remarks>
    /// Not the same as ordinal string comparison. Ordinal compares 16-bit code units;
    /// this compares the little-endian bytes, so the low half of each unit is weighed
    /// first. For MSI's mangled names the two orders genuinely differ.
    /// </remarks>
    private sealed class Utf16NameComparer : IComparer<string>
    {
        public static readonly Utf16NameComparer Instance = new();

        public int Compare(string? x, string? y)
        {
            byte[] left = Encoding.Unicode.GetBytes(x ?? string.Empty);
            byte[] right = Encoding.Unicode.GetBytes(y ?? string.Empty);

            int shared = Math.Min(left.Length, right.Length);
            for (int i = 0; i < shared; i++)
            {
                if (left[i] != right[i])
                {
                    return left[i] - right[i];
                }
            }

            return left.Length - right.Length;
        }
    }
}
