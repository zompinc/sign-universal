using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using FluentAssertions;
using OpenMcdf;
using SignUniversal.Core.Authenticode;
using SignUniversal.Core.Msi;
using TUnit.Core;

namespace SignUniversal.Core.Tests;

/// <summary>
/// MSI signing: the digest over the compound file's streams, and the signature written
/// back into it.
/// </summary>
/// <remarks>
/// The synthetic package here is deterministic but small. The check that matters is
/// <c>Digest_MatchesTheOne_InsideARealSignedPackage</c>, which needs an actual
/// Microsoft-signed MSI and is opt-in through <c>SIGNUNIVERSAL_MSI_ORACLE</c> — the same
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
        // — not 1 — the MSI SIP GUID, and five zeroes.
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
