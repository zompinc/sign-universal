using System.Security.Cryptography;
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

        List<EntryInfo> entries = root.EnumerateEntries().ToList();

        // The pre-hash comes first when the package carries one.
        if (entries.Any(entry => entry.Name == ExtendedSignatureStreamName))
        {
            hash.AppendData(ReadStream(root, ExtendedSignatureStreamName));
        }

        IEnumerable<EntryInfo> streams = entries
            .Where(entry => entry.Type == EntryType.Stream)
            .Where(entry => entry.Name != SignatureStreamName && entry.Name != ExtendedSignatureStreamName)
            .OrderBy(entry => entry.Name, Utf16NameComparer.Instance);

        foreach (EntryInfo entry in streams)
        {
            hash.AppendData(ReadStream(root, entry.Name));
        }

        // The root storage's class identifier closes the digest.
        hash.AppendData(root.EntryInfo.CLSID.ToByteArray());

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
