using SignUniversal.Authenticode;

namespace SignUniversal.Msi;

/// <summary>
/// Signs an MSI package end to end: strip any previous signature, digest, sign the
/// digest through the backend, write the signature stream.
/// </summary>
public static class MsiSigner
{
    /// <summary>Signs an MSI package in place.</summary>
    /// <param name="compoundFile">A readable, writable, seekable MSI stream.</param>
    /// <param name="signer">The backend holding the private key.</param>
    /// <param name="hashAlgorithm">The digest algorithm.</param>
    /// <param name="timestampUrl">The RFC 3161 authority, or <see langword="null"/> to skip timestamping.</param>
    /// <returns>The Authenticode digest that was signed.</returns>
    public static byte[] Sign(
        Stream compoundFile,
        IRemoteSigner signer,
        HashAlgorithmName hashAlgorithm,
        Uri? timestampUrl = null)
    {
        ArgumentNullException.ThrowIfNull(compoundFile);
        ArgumentNullException.ThrowIfNull(signer);

        // The pre-hash stream is itself covered by the digest, so any previous signature
        // has to go before the digest is taken rather than after.
        MsiFile.PrepareForSigning(compoundFile);

        // Then a fresh pre-hash over the package's metadata, which the digest covers in
        // turn. signtool writes one unconditionally and Windows rejects the signature
        // without it, so this is not optional.
        MsiFile.WriteMetadataPreHash(compoundFile, hashAlgorithm);

        byte[] digest = MsiFile.ComputeAuthenticodeDigest(compoundFile, hashAlgorithm);
        byte[] signedData = AuthenticodeSignedDataBuilder.Build(
            signer, digest, hashAlgorithm, timestampUrl, timestampTimeout: null, subject: SignedSubject.Msi);

        MsiFile.EmbedSignature(compoundFile, signedData);
        return digest;
    }

    /// <summary>Signs an MSI file in place.</summary>
    /// <param name="path">The path of the package to sign.</param>
    /// <param name="signer">The backend holding the private key.</param>
    /// <param name="hashAlgorithm">The digest algorithm.</param>
    /// <param name="timestampUrl">The RFC 3161 authority, or <see langword="null"/> to skip timestamping.</param>
    /// <returns>The Authenticode digest that was signed.</returns>
    /// <remarks>
    /// Signing happens on a copy that replaces the original only on success, so a backend
    /// that fails partway cannot leave a package stripped of the signature it had.
    /// </remarks>
    public static byte[] SignFile(
        string path,
        IRemoteSigner signer,
        HashAlgorithmName hashAlgorithm,
        Uri? timestampUrl = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);

        string temporaryPath = path + ".signing";

        try
        {
            File.Copy(path, temporaryPath, overwrite: true);

            byte[] digest;
            using (FileStream stream = new(temporaryPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
            {
                digest = Sign(stream, signer, hashAlgorithm, timestampUrl);
            }

            File.Move(temporaryPath, path, overwrite: true);
            return digest;
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }
    }
}
