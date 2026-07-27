using System.Security.Cryptography;
using SignUniversal.Core.Signing;

namespace SignUniversal.Core.Authenticode;

/// <summary>
/// Signs a PE image end to end: normalize, digest, sign the digest through the
/// backend, embed the result in the attribute certificate table.
/// </summary>
public static class PeSigner
{
    /// <summary>Signs a PE image in place.</summary>
    /// <param name="peImage">A readable, writable, seekable PE image stream.</param>
    /// <param name="signer">The backend holding the private key.</param>
    /// <param name="hashAlgorithm">The digest algorithm.</param>
    /// <param name="timestampUrl">The RFC 3161 authority, or <see langword="null"/> to skip timestamping.</param>
    /// <returns>The Authenticode digest that was signed.</returns>
    public static byte[] Sign(
        Stream peImage,
        IRemoteSigner signer,
        HashAlgorithmName hashAlgorithm,
        Uri? timestampUrl = null)
    {
        ArgumentNullException.ThrowIfNull(peImage);
        ArgumentNullException.ThrowIfNull(signer);

        // Order matters: padding to the 8-byte boundary happens before the digest,
        // because those pad bytes sit in front of the certificate table and are hashed.
        PeFile.PrepareForSigning(peImage);

        byte[] digest = PeFile.ComputeAuthenticodeDigest(peImage, hashAlgorithm);
        byte[] signedData = AuthenticodeSignedDataBuilder.Build(signer, digest, hashAlgorithm, timestampUrl);

        PeFile.EmbedSignature(peImage, signedData);
        return digest;
    }

    /// <summary>Signs a PE file in place.</summary>
    /// <param name="path">The path of the file to sign.</param>
    /// <param name="signer">The backend holding the private key.</param>
    /// <param name="hashAlgorithm">The digest algorithm.</param>
    /// <param name="timestampUrl">The RFC 3161 authority, or <see langword="null"/> to skip timestamping.</param>
    /// <returns>The Authenticode digest that was signed.</returns>
    public static byte[] SignFile(
        string path,
        IRemoteSigner signer,
        HashAlgorithmName hashAlgorithm,
        Uri? timestampUrl = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);

        using FileStream stream = new(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        return Sign(stream, signer, hashAlgorithm, timestampUrl);
    }
}
