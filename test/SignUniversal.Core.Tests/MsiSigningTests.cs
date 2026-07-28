using OpenMcdf;
using SignUniversal.Msi;

namespace SignUniversal.Core.Tests;

/// <summary>
/// MSI signing: the digest over the compound file's streams, and the signature written
/// back into it.
/// </summary>
/// <remarks>
/// The synthetic package here is deterministic but small. The check that matters is
/// <c>Digest_MatchesTheOne_InsideARealSignedPackage</c>, which needs an actual
/// Microsoft-signed MSI and is opt-in through <c>SIGNUNIVERSAL_MSI_ORACLE</c> - the same
/// arrangement the PE corpus uses, and for the same reason: the algorithm was derived
/// from that comparison, so it is the thing worth re-running.
/// </remarks>
public sealed class MsiSigningTests
{
    [Test]
    public void Digest_MatchesTheOne_InsideARealSignedPackage()
    {
        string? oracle = Environment.GetEnvironmentVariable("SIGNUNIVERSAL_MSI_ORACLE");
        Skip.Unless(
            !string.IsNullOrEmpty(oracle) && File.Exists(oracle),
            "set SIGNUNIVERSAL_MSI_ORACLE to a signed .msi");

        using FileStream package = File.OpenRead(oracle!);
        byte[] signature = MsiFile.ReadEmbeddedSignature(package)!;
        signature.Should().NotBeNull("the oracle must itself be signed");

        byte[] digest = MsiFile.ComputeAuthenticodeDigest(package, HashAlgorithmName.SHA256);

        Convert.ToHexString(signature).Should().Contain(
            Convert.ToHexString(digest),
            "the digest we compute must be the one the publisher signed");
    }

    [Test]
    public void SpcIndirectData_NamesTheSubjectAsAnMsi()
    {
        byte[] digest = Convert.FromHexString(
            "64adfc4ce71aa29814e123ae447d243868b27d79feed122dfc3fbbbea95fa9b4");

        byte[] encoded = SpcIndirectData.EncodeForMsi(digest, HashAlgorithmName.SHA256);

        // Byte for byte what a Microsoft-signed package carries: SpcSipInfo with version 2
        // - not 1 - the MSI SIP GUID, and five zeroes.
        Convert.ToHexString(encoded).ToLowerInvariant().Should().Be(
            "30673032060a2b06010401823702011e30240201020410f1100c0000000000c000000000000046"
            + "02010002010002010002010002010030" + "31300d0609608648016503040201050004206"
            + "4adfc4ce71aa29814e123ae447d243868b27d79feed122dfc3fbbbea95fa9b4");
    }

    [Test]
    public void Sign_EmbedsASignatureOverTheDigest()
    {
        using TemporaryDirectory directory = new();
        string path = CreatePackage(directory.Path);
        using LocalKeyRemoteSigner signer = new();

        byte[] digest = MsiSigner.SignFile(path, signer, HashAlgorithmName.SHA256);

        using FileStream package = File.OpenRead(path);
        byte[]? signature = MsiFile.ReadEmbeddedSignature(package);

        signature.Should().NotBeNull();
        AuthenticodeSignedDataBuilder.VerifySignatureOnly(signature!).Should().BeTrue();
        Convert.ToHexString(signature!).Should().Contain(Convert.ToHexString(digest));
    }

    [Test]
    public void Sign_LeavesTheDigestUnchanged()
    {
        using TemporaryDirectory directory = new();
        string path = CreatePackage(directory.Path);
        using LocalKeyRemoteSigner signer = new();

        byte[] signed = MsiSigner.SignFile(path, signer, HashAlgorithmName.SHA256);

        using FileStream package = File.OpenRead(path);
        MsiFile.ComputeAuthenticodeDigest(package, HashAlgorithmName.SHA256)
            .Should().Equal(signed, "writing the signature stream must not change what it covers");
    }

    [Test]
    public void Sign_Twice_ReplacesTheExistingSignature()
    {
        using TemporaryDirectory directory = new();
        string path = CreatePackage(directory.Path);
        using LocalKeyRemoteSigner first = new();
        using LocalKeyRemoteSigner second = new();

        MsiSigner.SignFile(path, first, HashAlgorithmName.SHA256);
        MsiSigner.SignFile(path, second, HashAlgorithmName.SHA256);

        using FileStream package = File.OpenRead(path);
        byte[]? signature = MsiFile.ReadEmbeddedSignature(package);

        SignedCms cms = new();
        cms.Decode(signature!);
        cms.SignerInfos[0].Certificate!.Thumbprint.Should().Be(second.Certificate.Thumbprint);
    }

    [Test]
    public void Sign_KeepsThePackageReadable()
    {
        using TemporaryDirectory directory = new();
        string path = CreatePackage(directory.Path);
        using LocalKeyRemoteSigner signer = new();

        MsiSigner.SignFile(path, signer, HashAlgorithmName.SHA256);

        using RootStorage root = RootStorage.OpenRead(path);
        root.EnumerateEntries().Select(entry => entry.Name)
            .Should().Contain(MsiFile.SignatureStreamName)
            .And.Contain(StreamNames);
    }

    [Test]
    public void PreHash_MatchesTheOne_InsideARealSignedPackage()
    {
        string? oracle = Environment.GetEnvironmentVariable("SIGNUNIVERSAL_MSI_ORACLE");
        Skip.Unless(
            !string.IsNullOrEmpty(oracle) && File.Exists(oracle),
            "set SIGNUNIVERSAL_MSI_ORACLE to a signed .msi carrying a pre-hash");

        using FileStream package = File.OpenRead(oracle!);
        using RootStorage root = RootStorage.OpenRead(oracle!);

        Skip.Unless(
            root.ContainsEntry(MsiFile.ExtendedSignatureStreamName),
            "the oracle package carries no pre-hash stream");

        byte[] stored;
        using (CfbStream stream = root.OpenStream(MsiFile.ExtendedSignatureStreamName))
        {
            stored = new byte[stream.Length];
            stream.ReadExactly(stored);
        }

        MsiFile.ComputeMetadataPreHash(package, HashAlgorithmName.SHA256)
            .Should().Equal(stored, "the pre-hash covers metadata the publisher also hashed");
    }

    [Test]
    public void Sign_WritesThePreHashTheDigestCovers()
    {
        using TemporaryDirectory directory = new();
        string path = CreatePackage(directory.Path);
        using LocalKeyRemoteSigner signer = new();

        MsiSigner.SignFile(path, signer, HashAlgorithmName.SHA256);

        using RootStorage root = RootStorage.OpenRead(path);
        root.ContainsEntry(MsiFile.ExtendedSignatureStreamName).Should().BeTrue(
            "Windows rejects the signature outright when the pre-hash is missing");
    }

    [Test]
    public void SignedPackage_IsAcceptedBySigntool()
    {
        // The gate MSI has been missing. CI authors a real installer with WiX so signtool
        // has something valid to judge; a hand-built compound file would be rejected for
        // not being an installer database, which would prove nothing about the signature.
        string? fixture = Environment.GetEnvironmentVariable("SIGNUNIVERSAL_MSI_FIXTURE");
        bool available = !string.IsNullOrEmpty(fixture) && File.Exists(fixture) && SigntoolHarness.IsAvailable;

        if (!available)
        {
            Environment.GetEnvironmentVariable("SIGNUNIVERSAL_REQUIRE_SIGNTOOL").Should().BeNullOrEmpty(
                "signtool verification was required, but signtool or the MSI fixture is missing");
            Skip.Test("set SIGNUNIVERSAL_MSI_FIXTURE to an .msi and run on Windows");
        }

        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "signed.msi");
        File.Copy(fixture!, path);

        using (LocalKeyRemoteSigner signer = new())
        {
            MsiSigner.SignFile(path, signer, HashAlgorithmName.SHA256);
        }

        SigntoolResult result = SigntoolHarness.Verify(path);

        result.FoundSignature.Should().BeTrue(
            "signtool must find the signature stream we wrote:\n{0}", result.Output);

        // Self-signed, so trust cannot succeed; everything short of it must.
        (result.Succeeded || result.RejectedOnlyForUntrustedRoot).Should().BeTrue(
            "signtool rejected the MSI signature for a reason other than an untrusted root:\n"
            + result.Output);
    }

    private static readonly string[] StreamNames = ["䡀䆒䑲", "䄦㢥", "Table"];

    /// <summary>
    /// Builds a small compound file shaped like an MSI: the database class identifier, and
    /// stream names in the mangled range MSI uses, where UTF-16LE byte order and code-unit
    /// order disagree.
    /// </summary>
    private static string CreatePackage(string directory)
    {
        string path = Path.Combine(directory, "test.msi");

        using (RootStorage root = RootStorage.Create(path))
        {
            foreach (string name in StreamNames)
            {
                using CfbStream stream = root.CreateStream(name);
                byte[] content = System.Text.Encoding.UTF8.GetBytes($"contents of {name}");
                stream.Write(content, 0, content.Length);
            }

            root.Flush(consolidate: false);
        }

        return path;
    }
}
