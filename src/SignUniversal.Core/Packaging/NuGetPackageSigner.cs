using NuGet.Common;
using NuGet.Packaging.Signing;
// Both libraries define HashAlgorithmName, so neither is left implicit here.
using NuGetHashAlgorithmName = NuGet.Common.HashAlgorithmName;
using SystemHashAlgorithmName = System.Security.Cryptography.HashAlgorithmName;

namespace SignUniversal.Core.Packaging;

/// <summary>
/// Author-signs a NuGet package with a key that never leaves the backend.
/// </summary>
/// <remarks>
/// <para>
/// Unlike the Authenticode work, almost none of this format is reimplemented. NuGet's
/// client libraries are cross-platform and are the reference implementation for package
/// hashing and for the zip surgery that inserts <c>.signature.p7s</c>; they are used
/// as-is. The gap this class fills is narrower and more stubborn: <c>dotnet nuget sign</c>
/// can only use a certificate whose private key is local, so a key held in Trusted
/// Signing or Key Vault is unreachable - see <see cref="RemoteKeySignatureProvider"/>.
/// </para>
/// <para>
/// Timestamping is not optional in practice. Trusted Signing issues certificates that
/// expire in about three days, so an untimestamped signature stops verifying almost
/// immediately.
/// </para>
/// </remarks>
public static class NuGetPackageSigner
{
    /// <summary>The timestamp authority used when none is specified.</summary>
    /// <remarks>
    /// DigiCert rather than Microsoft's, deliberately. See <see cref="TrustedSigningTimestampUrl"/>.
    /// </remarks>
    public const string DefaultTimestampUrl = "http://timestamp.digicert.com";

    /// <summary>The timestamp authority Microsoft documents for Trusted Signing.</summary>
    /// <remarks>
    /// Not the default, because it does not work on a stock Linux agent. Its responses
    /// carry only the leaf and intermediate, and the root they chain to - Microsoft
    /// Identity Verification Root Certificate Authority 2020 - is absent from the usual
    /// Linux trust stores, so the chain cannot be built and signing fails outright.
    /// DigiCert's responses include the full chain to a root Ubuntu already trusts. Use
    /// this one only where that root has been installed.
    /// </remarks>
    public const string TrustedSigningTimestampUrl = "http://timestamp.acs.microsoft.com";

    /// <summary>Signs a package, writing the result to a separate file.</summary>
    /// <param name="inputPath">The package to sign.</param>
    /// <param name="outputPath">Where to write the signed package.</param>
    /// <param name="signer">The backend holding the private key.</param>
    /// <param name="hashAlgorithm">The signature digest algorithm.</param>
    /// <param name="timestampUrl">The RFC 3161 authority, or <see langword="null"/> to skip timestamping.</param>
    /// <param name="overwrite">Whether to replace an existing signature.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A task that completes when the package is signed.</returns>
    public static async Task SignAsync(
        string inputPath,
        string outputPath,
        IRemoteSigner signer,
        SystemHashAlgorithmName hashAlgorithm,
        Uri? timestampUrl,
        bool overwrite = true,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(inputPath);
        ArgumentException.ThrowIfNullOrEmpty(outputPath);
        ArgumentNullException.ThrowIfNull(signer);

        ITimestampProvider? timestampProvider =
            timestampUrl is null ? null : new Rfc3161TimestampProvider(timestampUrl);

        RemoteKeySignatureProvider signatureProvider = new(signer, timestampProvider);

        // SignPackageRequest.Dispose() disposes the certificate it was given, so it gets a
        // copy. Handing it the backend's own certificate would leave the signer unusable
        // after one package - and signing a directory of packages is the normal case.
        using X509Certificate2 certificate = new(signer.Certificate.RawData);
        using AuthorSignPackageRequest request = new(certificate, MapHashAlgorithm(hashAlgorithm));

        // NuGet builds the chain against the machine's trust store, which knows nothing
        // about the CAs a short-lived certificate is issued from. Seeding the backend's
        // own chain here is what gets the intermediates embedded in the signature - without
        // them the package signs cleanly and then fails to verify on someone else's machine.
        foreach (X509Certificate2 issuer in signer.GetCertificateChain(cancellationToken))
        {
            if (!string.Equals(issuer.Thumbprint, certificate.Thumbprint, StringComparison.OrdinalIgnoreCase))
            {
                request.AdditionalCertificates.Add(new X509Certificate2(issuer.RawData));
            }
        }

        using SigningOptions options = SigningOptions.CreateFromFilePaths(
            inputPath, outputPath, overwrite, signatureProvider, NullLogger.Instance);

        await SigningUtility.SignAsync(options, request, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Signs a package in place.</summary>
    /// <param name="packagePath">The package to sign.</param>
    /// <param name="signer">The backend holding the private key.</param>
    /// <param name="hashAlgorithm">The signature digest algorithm.</param>
    /// <param name="timestampUrl">The RFC 3161 authority, or <see langword="null"/> to skip timestamping.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A task that completes when the package is signed.</returns>
    /// <remarks>
    /// NuGet reads and writes the package as two separate streams, so signing happens
    /// through a temporary file that replaces the original only on success.
    /// </remarks>
    public static async Task SignFileAsync(
        string packagePath,
        IRemoteSigner signer,
        SystemHashAlgorithmName hashAlgorithm,
        Uri? timestampUrl,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(packagePath);

        string temporaryPath = packagePath + ".signing";

        try
        {
            await SignAsync(
                packagePath,
                temporaryPath,
                signer,
                hashAlgorithm,
                timestampUrl,
                overwrite: true,
                cancellationToken).ConfigureAwait(false);

            File.Move(temporaryPath, packagePath, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }
    }

    private static NuGetHashAlgorithmName MapHashAlgorithm(SystemHashAlgorithmName hashAlgorithm) => hashAlgorithm.Name switch
    {
        "SHA256" => NuGetHashAlgorithmName.SHA256,
        "SHA384" => NuGetHashAlgorithmName.SHA384,
        "SHA512" => NuGetHashAlgorithmName.SHA512,
        _ => throw new NotSupportedException(
            $"NuGet package signing supports SHA256, SHA384, and SHA512; '{hashAlgorithm.Name}' is not one of them."),
    };
}
