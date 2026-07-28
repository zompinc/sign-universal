using System.IO.Compression;
using SignUniversal.Packaging;

namespace SignUniversal.Core.Tests;

/// <summary>
/// NuGet package signing with a key the process never holds.
/// </summary>
/// <remarks>
/// The gate here is <c>dotnet nuget verify</c> - NuGet's own client passing judgement on
/// our output. It runs everywhere, so unlike the Authenticode signtool gate this one
/// actually executes on the Linux machine that produced the signature.
/// </remarks>
public sealed class NuGetSigningTests
{
    private const string SignatureEntry = ".signature.p7s";

    [Test]
    public async Task Sign_ProducesAPackageNuGetAccepts()
    {
        using TemporaryDirectory directory = new();
        string package = TestPackage.Create(directory.Path);
        using LocalKeyRemoteSigner signer = new();

        await NuGetPackageSigner.SignFileAsync(package, signer, HashAlgorithmName.SHA256, timestampUrl: null);

        NuGetVerifyResult result = NuGetVerifyHarness.Verify(package);

        result.FoundAuthorSignature.Should().BeTrue("NuGet must parse our signature:\n{0}", result.Output);

        // The test certificate is self-signed, so it can never chain to NuGet's root
        // bundle. Everything short of trust must pass, which is what proves the format.
        result.RejectedOnlyForUntrustedRoot.Should().BeTrue(
            "NuGet rejected the package for something other than an untrusted root:\n{0}", result.Output);
    }

    [Test]
    public async Task Sign_ReachesThePrivateKeyOnlyThroughTheRemoteSeam()
    {
        using TemporaryDirectory directory = new();
        string package = TestPackage.Create(directory.Path);
        using LocalKeyRemoteSigner signer = new();

        await NuGetPackageSigner.SignFileAsync(package, signer, HashAlgorithmName.SHA256, timestampUrl: null);

        // The certificate handed to NuGet is public-only, so a signature can only exist
        // if the key operation was delegated.
        signer.SignHashCallCount.Should().BeGreaterThan(0);
        signer.Certificate.HasPrivateKey.Should().BeFalse();
    }

    [Test]
    public async Task Sign_EmbedsACmsSignatureFromTheSigningCertificate()
    {
        using TemporaryDirectory directory = new();
        string package = TestPackage.Create(directory.Path);
        using LocalKeyRemoteSigner signer = new();

        await NuGetPackageSigner.SignFileAsync(package, signer, HashAlgorithmName.SHA256, timestampUrl: null);

        using ZipArchive archive = ZipFile.OpenRead(package);
        ZipArchiveEntry? signature = archive.GetEntry(SignatureEntry);
        signature.Should().NotBeNull("a signed package carries {0}", SignatureEntry);

        using MemoryStream buffer = new();
        using (Stream entryStream = signature!.Open())
        {
            entryStream.CopyTo(buffer);
        }

        SignedCms cms = new();
        cms.Decode(buffer.ToArray());
        cms.SignerInfos.Count.Should().Be(1);
        cms.SignerInfos[0].Certificate!.Thumbprint.Should().Be(signer.Certificate.Thumbprint);
        cms.CheckSignature(verifySignatureOnly: true);
    }

    [Test]
    public async Task TamperedPackage_IsRejected()
    {
        using TemporaryDirectory directory = new();
        string package = TestPackage.Create(directory.Path);
        using LocalKeyRemoteSigner signer = new();

        await NuGetPackageSigner.SignFileAsync(package, signer, HashAlgorithmName.SHA256, timestampUrl: null);
        TestPackage.Tamper(package);

        NuGetVerifyResult result = NuGetVerifyHarness.Verify(package);

        // Proves the gate above is load-bearing rather than reporting trust errors on
        // anything it is handed.
        result.ReportedIntegrityFailure.Should().BeTrue(
            "NuGet must notice the package changed after signing:\n{0}", result.Output);
    }

    [Test]
    public async Task Sign_Twice_ReplacesTheExistingSignature()
    {
        using TemporaryDirectory directory = new();
        string package = TestPackage.Create(directory.Path);
        using LocalKeyRemoteSigner first = new();
        using LocalKeyRemoteSigner second = new();

        await NuGetPackageSigner.SignFileAsync(package, first, HashAlgorithmName.SHA256, timestampUrl: null);
        await NuGetPackageSigner.SignFileAsync(package, second, HashAlgorithmName.SHA256, timestampUrl: null);

        using ZipArchive archive = ZipFile.OpenRead(package);
        archive.Entries.Count(entry => entry.FullName == SignatureEntry).Should().Be(1);

        NuGetVerifyResult result = NuGetVerifyHarness.Verify(package);
        result.RejectedOnlyForUntrustedRoot.Should().BeTrue(result.Output);
    }

    [Test]
    public async Task Sign_MultiplePackages_WithOneSigner()
    {
        // The shape of a real CI step: one signing session, a directory of packages.
        using TemporaryDirectory directory = new();
        using LocalKeyRemoteSigner signer = new();

        string first = TestPackage.Create(directory.Path);
        string second = Path.Combine(directory.Path, "second.nupkg");
        File.Copy(first, second);

        await NuGetPackageSigner.SignFileAsync(first, signer, HashAlgorithmName.SHA256, timestampUrl: null);
        await NuGetPackageSigner.SignFileAsync(second, signer, HashAlgorithmName.SHA256, timestampUrl: null);

        NuGetVerifyHarness.Verify(first).RejectedOnlyForUntrustedRoot.Should().BeTrue();
        NuGetVerifyHarness.Verify(second).RejectedOnlyForUntrustedRoot.Should().BeTrue();
    }

    [Test]
    public async Task Sign_UsesTheCertificateTheBackendExposes()
    {
        // What --export-certificate writes is the backend's certificate, and a gallery that
        // requires registration matches on that certificate's fingerprint. So the one the
        // backend exposes has to be the one that ends up in the signature.
        using TemporaryDirectory directory = new();
        string package = TestPackage.Create(directory.Path);
        using LocalKeyRemoteSigner signer = new();

        await NuGetPackageSigner.SignFileAsync(package, signer, HashAlgorithmName.SHA256, timestampUrl: null);

        using ZipArchive archive = ZipFile.OpenRead(package);
        using MemoryStream buffer = new();
        using (Stream entryStream = archive.GetEntry(SignatureEntry)!.Open())
        {
            entryStream.CopyTo(buffer);
        }

        SignedCms cms = new();
        cms.Decode(buffer.ToArray());

        cms.SignerInfos[0].Certificate!.RawData.Should().Equal(
            signer.Certificate.RawData,
            "the exported certificate must be the one that signed");
    }

    [Test]
    public async Task Sign_RejectsAnUnsupportedHashAlgorithm()
    {
        using TemporaryDirectory directory = new();
        string package = TestPackage.Create(directory.Path);
        using LocalKeyRemoteSigner signer = new();

        Func<Task> sign = () =>
            NuGetPackageSigner.SignFileAsync(package, signer, HashAlgorithmName.SHA1, timestampUrl: null);

        await sign.Should().ThrowAsync<NotSupportedException>();
    }
}
