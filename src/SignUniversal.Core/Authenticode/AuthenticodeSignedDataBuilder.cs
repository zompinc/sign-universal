using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using SignUniversal.Core.Signing;

namespace SignUniversal.Core.Authenticode;

/// <summary>
/// Builds an Authenticode PKCS#7 SignedData blob over a precomputed file digest,
/// signing through an <see cref="IRemoteSigner"/> so the private key never enters
/// the process.
/// </summary>
/// <remarks>
/// This is where the port is dramatically smaller than jsign: the CMS SignedData
/// assembly, signed-attribute handling, and signature encoding are all provided by
/// <see cref="SignedCms"/>/<see cref="CmsSigner"/>. Our only contribution is the
/// Authenticode content type, the <see cref="SpcIndirectData"/> payload, and the
/// remote-key seam.
/// </remarks>
public static class AuthenticodeSignedDataBuilder
{
    /// <summary>
    /// Produces the DER-encoded SignedData for the given digest, signed by
    /// <paramref name="signer"/>.
    /// </summary>
    /// <param name="signer">The backend holding the private key.</param>
    /// <param name="authenticodeDigest">The Authenticode digest of the subject file.</param>
    /// <param name="hashAlgorithm">The digest/signature hash algorithm.</param>
    /// <returns>The encoded PKCS#7 SignedData.</returns>
    public static byte[] Build(
        IRemoteSigner signer,
        ReadOnlySpan<byte> authenticodeDigest,
        HashAlgorithmName hashAlgorithm)
    {
        ArgumentNullException.ThrowIfNull(signer);

        byte[] spcContent = SpcIndirectData.EncodeForPeImage(authenticodeDigest, hashAlgorithm);

        ContentInfo contentInfo = new(new Oid(AuthenticodeOids.SpcIndirectDataObjId), spcContent);
        SignedCms signedCms = new(contentInfo, detached: false);

        using RemoteSigningRsa remoteRsa = new(signer);

        // Pass the private key SEPARATELY (not via CopyWithPrivateKey). On Linux/OpenSSL,
        // CopyWithPrivateKey eagerly exports private parameters, which a remote key cannot
        // provide; this overload signs through the supplied key's SignHash instead — the
        // one operation we delegate to the backend.
        CmsSigner cmsSigner = new(SubjectIdentifierType.IssuerAndSerialNumber, signer.Certificate, remoteRsa)
        {
            DigestAlgorithm = new Oid(AuthenticodeOids.DigestOid(hashAlgorithm)),
            IncludeOption = X509IncludeOption.EndCertOnly,
        };

        signedCms.ComputeSignature(cmsSigner);
        return signedCms.Encode();
    }

    /// <summary>
    /// Verifies that an encoded SignedData blob has a valid signature over its
    /// content. Signature-only (no chain/trust) — suitable for the spike and for
    /// round-trip tests with self-signed certificates.
    /// </summary>
    /// <param name="encodedSignedData">The DER-encoded SignedData.</param>
    /// <returns><see langword="true"/> if the signature verifies.</returns>
    public static bool VerifySignatureOnly(byte[] encodedSignedData)
    {
        ArgumentNullException.ThrowIfNull(encodedSignedData);

        SignedCms signedCms = new();
        signedCms.Decode(encodedSignedData);

        try
        {
            signedCms.CheckSignature(verifySignatureOnly: true);
            return true;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }
}
