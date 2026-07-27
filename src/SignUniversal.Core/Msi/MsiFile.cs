using System.Security.Cryptography;

namespace SignUniversal.Core.Msi;

/// <summary>
/// Signs an MSI (an OLE compound file) by computing the digest over its streams in
/// the defined order and writing the <c>\x05DigitalSignature</c> (and extended
/// <c>\x05MsiDigitalSignatureEx</c>) streams.
/// </summary>
/// <remarks>
/// Placeholder. Will use <c>OpenMcdf</c> for the compound-file container so only the
/// MSI-specific digest ordering and signature-stream layout need porting. The
/// extended pre-hash (<c>MsiDigitalSignatureEx</c>) is the fiddliest correctness
/// risk in the whole project and gets the heaviest test coverage.
/// </remarks>
public static class MsiFile
{
    /// <summary>Computes the Authenticode digest of an MSI compound file.</summary>
    /// <param name="compoundFile">The MSI file stream.</param>
    /// <param name="hashAlgorithm">The digest algorithm.</param>
    /// <returns>The Authenticode digest.</returns>
    public static byte[] ComputeAuthenticodeDigest(Stream compoundFile, HashAlgorithmName hashAlgorithm) =>
        throw new NotImplementedException(
            "MSI signing is not implemented yet (roadmap: MSI milestone; container via OpenMcdf).");
}
