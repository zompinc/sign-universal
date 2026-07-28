using SignUniversal;
using SignUniversal.Msi;
using SignUniversal.Packaging;

namespace SignUniversal.Core.Tests;

/// <summary>
/// Inspection across every format the tool signs.
/// </summary>
/// <remarks>
/// These exist because the first version of this logic lived in the CLI, where no test
/// reached it, and could not read a NuGet package at all - it sent everything that was not
/// an MSI to the PE parser. The suite was 52 tests green throughout. A format table with
/// no test per format is how that happens, so there is one per format here.
/// </remarks>
public sealed class SignatureInspectorTests
{
    [Test]
    public async Task Inspect_ReadsASignedNuGetPackage()
    {
        using TemporaryDirectory directory = new();
        string package = TestPackage.Create(directory.Path);
        using LocalKeyRemoteSigner signer = new();
        await NuGetPackageSigner.SignFileAsync(package, signer, HashAlgorithmName.SHA256, timestampUrl: null);

        SignatureReport report = await SignatureInspector.InspectAsync(package);

        report.Format.Should().Be("NuGet package");
        report.IsSigned.Should().BeTrue();
        report.Signer.Should().Contain("SignUniversal Test");
        report.SignatureValid.Should().BeTrue();
        report.CoversFile.Should().BeTrue();
    }

    [Test]
    public async Task Inspect_ReadsASignedPeImage()
    {
        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "signed.dll");
        File.WriteAllBytes(path, SyntheticPe.Build(pe32Plus: false, headerGap: 0, trailingBytes: 5));
        using LocalKeyRemoteSigner signer = new();
        PeSigner.SignFile(path, signer, HashAlgorithmName.SHA256);

        SignatureReport report = await SignatureInspector.InspectAsync(path);

        report.Format.Should().Be("PE image");
        report.IsSigned.Should().BeTrue();
        report.SignatureValid.Should().BeTrue();
        report.CoversFile.Should().BeTrue();
        report.Timestamp.Should().BeNull("this one was signed without an authority");
    }

    [Test]
    public async Task Inspect_ReadsASignedMsi()
    {
        using TemporaryDirectory directory = new();
        string path = CreateMsi(directory.Path);
        using LocalKeyRemoteSigner signer = new();
        MsiSigner.SignFile(path, signer, HashAlgorithmName.SHA256);

        SignatureReport report = await SignatureInspector.InspectAsync(path);

        report.Format.Should().Be("MSI package");
        report.IsSigned.Should().BeTrue();
        report.SignatureValid.Should().BeTrue();
        report.CoversFile.Should().BeTrue();
    }

    [Test]
    public async Task Inspect_ReportsAnUnsignedFile()
    {
        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "bare.dll");
        File.WriteAllBytes(path, SyntheticPe.Build(pe32Plus: false));

        SignatureReport report = await SignatureInspector.InspectAsync(path);

        report.IsSigned.Should().BeFalse();
        report.CoversFile.Should().BeFalse();
    }

    [Test]
    public async Task Inspect_NoticesAPeImageChangedAfterSigning()
    {
        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "signed.dll");
        File.WriteAllBytes(path, SyntheticPe.Build(pe32Plus: false, headerGap: 0, trailingBytes: 5));
        using LocalKeyRemoteSigner signer = new();
        PeSigner.SignFile(path, signer, HashAlgorithmName.SHA256);

        // A byte inside a section: covered by the digest, untouched by the signature.
        byte[] image = File.ReadAllBytes(path);
        image[SyntheticPe.FirstSectionOffset(headerGap: 0) + 9] ^= 0xFF;
        File.WriteAllBytes(path, image);

        SignatureReport report = await SignatureInspector.InspectAsync(path);

        report.SignatureValid.Should().BeTrue("the signature itself is untouched");
        report.CoversFile.Should().BeFalse("but it no longer describes this file");
    }

    [Test]
    public async Task Inspect_NoticesAPackageChangedAfterSigning()
    {
        using TemporaryDirectory directory = new();
        string package = TestPackage.Create(directory.Path);
        using LocalKeyRemoteSigner signer = new();
        await NuGetPackageSigner.SignFileAsync(package, signer, HashAlgorithmName.SHA256, timestampUrl: null);

        // Early in the file, inside the payload entry's data: the signature is appended
        // after the content, so this cannot disturb the signature itself.
        byte[] bytes = File.ReadAllBytes(package);
        bytes[2048] ^= 0xFF;
        File.WriteAllBytes(package, bytes);

        SignatureReport report = await SignatureInspector.InspectAsync(package);

        report.SignatureValid.Should().BeTrue("the signature itself is untouched");
        report.CoversFile.Should().BeFalse("but it no longer describes this package");
    }

    private static string CreateMsi(string directory)
    {
        string path = Path.Combine(directory, "test.msi");

        using (OpenMcdf.RootStorage root = OpenMcdf.RootStorage.Create(path))
        {
            using (OpenMcdf.CfbStream stream = root.CreateStream("Table"))
            {
                stream.Write("contents"u8.ToArray(), 0, 8);
            }

            root.Flush(consolidate: false);
        }

        return path;
    }
}
