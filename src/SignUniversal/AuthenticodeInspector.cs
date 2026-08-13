using System.Security.Cryptography.Pkcs;
using SignUniversal.Authenticode;
using SignUniversal.Msi;

namespace SignUniversal;

/// <summary>
/// Reports what an Authenticode signature on a PE image or MSI package carries.
/// </summary>
/// <remarks>
/// It answers "is this signature intact and does it cover these bytes", not "should this
/// signature be trusted". Trust depends on certificate chains and local policy, and
/// <c>signtool verify /pa</c> already answers it properly.
/// </remarks>
public static class AuthenticodeInspector
{
    /// <summary>Inspects the Authenticode signature on a file.</summary>
    /// <param name="path">The file to inspect.</param>
    /// <param name="isMsi">Whether the file is an MSI package rather than a PE image.</param>
    /// <returns>What the file's signature says about itself.</returns>
    public static SignatureReport Inspect(string path, bool isMsi)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);

        string format = isMsi ? "MSI package" : "PE image";

        using FileStream stream = File.OpenRead(path);
        byte[]? signature = isMsi
            ? MsiFile.ReadEmbeddedSignature(stream)
            : PeFile.ReadEmbeddedSignature(stream);

        if (signature is null)
        {
            return SignatureReport.WithoutSignature(format);
        }

        SignedCms cms = new();
        cms.Decode(signature);

        // Authenticode names the digest algorithm in the signer info, so the file is
        // rehashed with whatever was used rather than an assumed SHA-256.
        HashAlgorithmName digestAlgorithm = DigestAlgorithmOf(cms);
        byte[] digest = isMsi
            ? MsiFile.ComputeAuthenticodeDigest(stream, digestAlgorithm)
            : PeFile.ComputeAuthenticodeDigest(stream, digestAlgorithm);

        bool covers = Convert.ToHexString(signature).Contains(
            Convert.ToHexString(digest), StringComparison.OrdinalIgnoreCase);

        return new SignatureReport(
            format,
            IsSigned: true,
            Signer: cms.SignerInfos[0].Certificate?.Subject,
            EmbeddedCertificates: cms.Certificates.Count,
            SignatureValid: AuthenticodeSignedDataBuilder.VerifySignatureOnly(signature),
            CoversFile: covers,
            Timestamp: AuthenticodeTimestamp.TryGetTimestamp(cms)?.TokenInfo.Timestamp);
    }

    /// <summary>Reports whether a file already carries an Authenticode signature.</summary>
    /// <param name="path">The file to examine.</param>
    /// <param name="isMsi">Whether the file is an MSI package rather than a PE image.</param>
    /// <returns><see langword="true"/> if a signature is present.</returns>
    /// <remarks>
    /// Presence, not trust: this reports that a signature is there, not that it validates or
    /// chains anywhere. That is the only answer available off Windows, and it is the one a
    /// caller needs when the question is "would signing this clobber somebody else's
    /// signature" - Authenticode keeps a single primary signature, so it would.
    /// </remarks>
    public static bool HasSignature(string path, bool isMsi)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);

        using FileStream stream = File.OpenRead(path);
        byte[]? signature = isMsi
            ? MsiFile.ReadEmbeddedSignature(stream)
            : PeFile.ReadEmbeddedSignature(stream);

        return signature is not null;
    }

    private static HashAlgorithmName DigestAlgorithmOf(SignedCms cms) =>
        cms.SignerInfos[0].DigestAlgorithm.Value switch
        {
            "2.16.840.1.101.3.4.2.2" => HashAlgorithmName.SHA384,
            "2.16.840.1.101.3.4.2.3" => HashAlgorithmName.SHA512,
            "1.3.14.3.2.26" => HashAlgorithmName.SHA1,
            _ => HashAlgorithmName.SHA256,
        };
}
