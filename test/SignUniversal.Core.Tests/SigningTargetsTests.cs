using SignUniversal.Cli;
using SignUniversal.Msi;
using SignUniversal.Packaging;

namespace SignUniversal.Core.Tests;

/// <summary>
/// Covers which files a run leaves alone when asked to skip the ones already signed.
/// </summary>
/// <remarks>
/// The cost of getting this wrong is not a failed build - it is a green one that quietly
/// replaced Microsoft's signature on <c>System.*.dll</c> with ours, because Authenticode
/// keeps a single primary signature and the caller handed us the whole publish output.
/// </remarks>
public sealed class SigningTargetsTests
{
    [Test]
    public void PartitionBySignature_KeepsBackTheOnesAlreadySigned()
    {
        using TemporaryDirectory directory = new();
        string vendor = WritePeImage(directory.Path, "vendor.dll");
        string ours = WritePeImage(directory.Path, "ours.dll");
        using LocalKeyRemoteSigner signer = new();
        PeSigner.SignFile(vendor, signer, HashAlgorithmName.SHA256);

        (List<string> toSign, List<string> alreadySigned) = SigningTargets.PartitionBySignature([vendor, ours]);

        toSign.Should().Equal(ours);
        alreadySigned.Should().Equal(vendor);
    }

    [Test]
    public void PartitionBySignature_SkipsASignedMsi()
    {
        // The issue that asked for this called MSI a format with no Authenticode signature
        // to preserve. It has one, in the same sense a PE does, so it is treated the same:
        // a flag named --skip-signed that re-signs a signed MSI would be a trap.
        using TemporaryDirectory directory = new();
        string package = CreateMsi(directory.Path);
        using LocalKeyRemoteSigner signer = new();
        MsiSigner.SignFile(package, signer, HashAlgorithmName.SHA256);

        (List<string> toSign, List<string> alreadySigned) = SigningTargets.PartitionBySignature([package]);

        toSign.Should().BeEmpty();
        alreadySigned.Should().Equal(package);
    }

    [Test]
    public async Task PartitionBySignature_NeverHoldsBackANuGetPackage()
    {
        // Package signing is a different mechanism with its own rules, and nothing hands
        // out pre-signed packages to be re-signed by accident.
        using TemporaryDirectory directory = new();
        string package = TestPackage.Create(directory.Path);
        using LocalKeyRemoteSigner signer = new();
        await NuGetPackageSigner.SignFileAsync(package, signer, HashAlgorithmName.SHA256, timestampUrl: null);

        (List<string> toSign, List<string> alreadySigned) = SigningTargets.PartitionBySignature([package]);

        toSign.Should().Equal(package);
        alreadySigned.Should().BeEmpty();
    }

    [Test]
    public void PartitionBySignature_KeepsTheOrderItWasGiven()
    {
        // Signing order is the order the caller resolved, so a run stays reproducible.
        using TemporaryDirectory directory = new();
        string first = WritePeImage(directory.Path, "a.dll");
        string second = WritePeImage(directory.Path, "b.dll");
        string third = WritePeImage(directory.Path, "c.dll");

        (List<string> toSign, _) = SigningTargets.PartitionBySignature([first, second, third]);

        toSign.Should().Equal(first, second, third);
    }

    [Test]
    public void PartitionBySignature_TreatsAnUnsignedImageAsWork()
    {
        using TemporaryDirectory directory = new();
        string bare = WritePeImage(directory.Path, "bare.dll");

        (List<string> toSign, List<string> alreadySigned) = SigningTargets.PartitionBySignature([bare]);

        toSign.Should().Equal(bare);
        alreadySigned.Should().BeEmpty();
    }

    private static string WritePeImage(string directory, string name)
    {
        string path = Path.Combine(directory, name);
        File.WriteAllBytes(path, SyntheticPe.Build(pe32Plus: false, headerGap: 0, trailingBytes: 5));
        return path;
    }

    private static string CreateMsi(string directory)
    {
        string path = Path.Combine(directory, "installer.msi");

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
