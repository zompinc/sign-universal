using System.Security.Cryptography;

namespace SignUniversal.Core.Authenticode;

/// <summary>
/// Reads a PE image, computes its Authenticode digest, and embeds a signature into
/// the attribute certificate table.
/// </summary>
/// <remarks>
/// Placeholder. This is the first real milestone of the port: hash the file while
/// skipping the optional-header checksum field and the certificate-table directory
/// + table, wrap the PKCS#7 in a <c>WIN_CERTIFICATE</c>, append with 8-byte
/// alignment, fix the data directory, and recompute the PE checksum. PE32 and PE32+
/// both handled; page hashes deferred.
/// </remarks>
public static class PeFile
{
    /// <summary>Computes the Authenticode digest of a PE image.</summary>
    /// <param name="peImage">The PE image stream.</param>
    /// <param name="hashAlgorithm">The digest algorithm.</param>
    /// <returns>The Authenticode digest.</returns>
    public static byte[] ComputeAuthenticodeDigest(Stream peImage, HashAlgorithmName hashAlgorithm) =>
        throw new NotImplementedException(
            "PE Authenticode hashing is not implemented yet (roadmap: PE embedding milestone).");
}
