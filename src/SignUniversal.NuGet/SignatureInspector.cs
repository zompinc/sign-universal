using NuGet.Packaging;
using NuGet.Packaging.Signing;

namespace SignUniversal;

/// <summary>
/// Reports what a signed file carries, whatever its format.
/// </summary>
/// <remarks>
/// <para>
/// This lives here rather than in the CLI because format dispatch is logic, and logic in
/// a command-line entry point is logic no test reaches. The first version of this shipped
/// inside the CLI and could not read a NuGet package at all: it sent everything that was
/// not an MSI to the PE parser, which the test suite had no way to notice.
/// </para>
/// <para>
/// It answers "is this signature intact and does it cover these bytes", not "should this
/// signature be trusted". Trust depends on certificate chains and local policy, and
/// <c>signtool verify /pa</c> and <c>dotnet nuget verify</c> already answer it properly.
/// </para>
/// <para>
/// The Authenticode half lives in <see cref="AuthenticodeInspector"/>, in the SignUniversal
/// package, so that inspecting a PE image does not require NuGet's client libraries.
/// </para>
/// </remarks>
public static class SignatureInspector
{
    /// <summary>Inspects the signature on a file.</summary>
    /// <param name="path">The file to inspect.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>What the file's signature says about itself.</returns>
    public static async Task<SignatureReport> InspectAsync(string path, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);

        string extension = Path.GetExtension(path);

        if (extension.Equals(".nupkg", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".snupkg", StringComparison.OrdinalIgnoreCase))
        {
            return await InspectPackageAsync(path, cancellationToken).ConfigureAwait(false);
        }

        bool isMsi = extension.Equals(".msi", StringComparison.OrdinalIgnoreCase);
        return AuthenticodeInspector.Inspect(path, isMsi);
    }

    private static async Task<SignatureReport> InspectPackageAsync(string path, CancellationToken cancellationToken)
    {
        const string format = "NuGet package";

        using FileStream stream = File.OpenRead(path);
        using PackageArchiveReader reader = new(stream);

        PrimarySignature? signature = await reader
            .GetPrimarySignatureAsync(cancellationToken)
            .ConfigureAwait(false);

        if (signature is null)
        {
            return SignatureReport.WithoutSignature(format);
        }

        // NuGet owns the definition of what a package signature covers, and it is not the
        // hash of the whole archive: GetArchiveHashAsync includes the signature file itself
        // and so never matches. ValidateIntegrityAsync is the real check, and letting NuGet
        // perform it avoids reimplementing a canonicalisation we would get subtly wrong.
        bool covers;
        try
        {
            await reader
                .ValidateIntegrityAsync(signature.SignatureContent, cancellationToken)
                .ConfigureAwait(false);
            covers = true;
        }
        catch (SignatureException)
        {
            covers = false;
        }
        catch (CryptographicException)
        {
            covers = false;
        }

        bool valid;
        try
        {
            signature.SignedCms.CheckSignature(verifySignatureOnly: true);
            valid = true;
        }
        catch (CryptographicException)
        {
            valid = false;
        }

        return new SignatureReport(
            format,
            IsSigned: true,
            Signer: signature.SignerInfo.Certificate?.Subject,
            EmbeddedCertificates: signature.SignedCms.Certificates.Count,
            SignatureValid: valid,
            CoversFile: covers,
            Timestamp: signature.Timestamps.Count > 0 ? signature.Timestamps[0].GeneralizedTime : null);
    }
}
