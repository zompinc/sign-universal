using System.Buffers.Binary;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using FluentAssertions;
using SignUniversal.Core.Authenticode;
using TUnit.Core;

namespace SignUniversal.Core.Tests;

/// <summary>
/// End-to-end PE signing: the certificate table an image ends up carrying, and the
/// invariant the whole format rests on — embedding a signature must not change the
/// digest that signature covers.
/// </summary>
/// <remarks>
/// The subject is this test run's own <c>SignUniversal.Core.dll</c>: a real
/// compiler-produced PE, so the tests exercise a genuine section layout rather than a
/// hand-built one. Structural assertions read the result back through
/// <see cref="PEReader"/> — an in-box parser independent of ours.
/// </remarks>
public sealed class PeSigningTests
{
    [Test]
    public void Sign_LeavesTheDigestUnchanged()
    {
        using MemoryStream image = LoadRealPeImage();
        using LocalKeyRemoteSigner signer = new();

        byte[] before = PeFile.ComputeAuthenticodeDigest(image, HashAlgorithmName.SHA256);
        byte[] signed = PeSigner.Sign(image, signer, HashAlgorithmName.SHA256);
        byte[] after = PeFile.ComputeAuthenticodeDigest(image, HashAlgorithmName.SHA256);

        // Signing rewrites the checksum and the certificate directory entry, and appends
        // the certificate table. None of it may perturb the digest.
        signed.Should().Equal(before);
        after.Should().Equal(before);
    }

    [Test]
    public void Sign_EmbedsASignatureOverTheDigest()
    {
        using MemoryStream image = LoadRealPeImage();
        using LocalKeyRemoteSigner signer = new();

        byte[] digest = PeSigner.Sign(image, signer, HashAlgorithmName.SHA256);
        byte[]? signature = PeFile.ReadEmbeddedSignature(image);

        signature.Should().NotBeNull();
        AuthenticodeSignedDataBuilder.VerifySignatureOnly(signature!).Should().BeTrue();
        Convert.ToHexString(signature!).Should().Contain(
            Convert.ToHexString(digest),
            "the SpcIndirectData must carry the digest of the file it is embedded in");
    }

    [Test]
    public void Sign_ProducesAWellFormedCertificateTable()
    {
        using MemoryStream image = LoadRealPeImage();
        using LocalKeyRemoteSigner signer = new();
        PeSigner.Sign(image, signer, HashAlgorithmName.SHA256);

        image.Position = 0;
        using PEReader reader = new(image, PEStreamOptions.LeaveOpen);
        DirectoryEntry directory = reader.PEHeaders.PEHeader!.CertificateTableDirectory;

        // This directory's "RVA" is really a file offset, and entries are 8-byte aligned.
        directory.Size.Should().BeGreaterThan(0);
        (directory.RelativeVirtualAddress % 8).Should().Be(0);
        (directory.RelativeVirtualAddress + directory.Size).Should().Be((int)image.Length);

        byte[] entry = new byte[8];
        image.Position = directory.RelativeVirtualAddress;
        image.ReadExactly(entry);

        // dwLength covers the header and the alignment padding, matching signtool's output.
        BinaryPrimitives.ReadUInt32LittleEndian(entry).Should().Be((uint)directory.Size);
        BinaryPrimitives.ReadUInt16LittleEndian(entry.AsSpan(4)).Should().Be(0x0200, "WIN_CERT_REVISION_2_0");
        BinaryPrimitives.ReadUInt16LittleEndian(entry.AsSpan(6)).Should().Be(0x0002, "WIN_CERT_TYPE_PKCS_SIGNED_DATA");
    }

    [Test]
    public void Sign_RefreshesTheChecksum()
    {
        using MemoryStream image = LoadRealPeImage();
        using LocalKeyRemoteSigner signer = new();
        PeSigner.Sign(image, signer, HashAlgorithmName.SHA256);

        image.Position = 0;
        using PEReader reader = new(image, PEStreamOptions.LeaveOpen);
        uint stored = reader.PEHeaders.PEHeader!.CheckSum;

        stored.Should().NotBe(0);
        stored.Should().Be(PeFile.ComputeChecksum(image));
    }

    [Test]
    public void Sign_Twice_ReplacesTheExistingSignature()
    {
        using MemoryStream image = LoadRealPeImage();
        using LocalKeyRemoteSigner first = new();
        using LocalKeyRemoteSigner second = new();

        PeSigner.Sign(image, first, HashAlgorithmName.SHA256);
        long lengthAfterFirst = image.Length;
        byte[]? firstSignature = PeFile.ReadEmbeddedSignature(image);

        PeSigner.Sign(image, second, HashAlgorithmName.SHA256);
        byte[]? secondSignature = PeFile.ReadEmbeddedSignature(image);

        // The old table is removed rather than left behind, so the file does not grow by a
        // second signature's worth.
        image.Length.Should().BeCloseTo(lengthAfterFirst, 64);
        secondSignature.Should().NotBeNull();
        secondSignature.Should().NotEqual(firstSignature);
        AuthenticodeSignedDataBuilder.VerifySignatureOnly(secondSignature!).Should().BeTrue();

        byte[] digest = PeFile.ComputeAuthenticodeDigest(image, HashAlgorithmName.SHA256);
        Convert.ToHexString(secondSignature!).Should().Contain(Convert.ToHexString(digest));
    }

    [Test]
    public void Sign_Pe32Plus_RoundTrips()
    {
        using MemoryStream image = new();
        image.Write(SyntheticPe.Build(pe32Plus: true, headerGap: 0x200, trailingBytes: 5));
        using LocalKeyRemoteSigner signer = new();

        byte[] digest = PeSigner.Sign(image, signer, HashAlgorithmName.SHA384);

        // The 5 trailing bytes leave the image unaligned; padding must land before the
        // certificate table and inside the digest.
        (image.Length % 8).Should().Be(0);
        PeFile.ComputeAuthenticodeDigest(image, HashAlgorithmName.SHA384).Should().Equal(digest);

        byte[]? signature = PeFile.ReadEmbeddedSignature(image);
        AuthenticodeSignedDataBuilder.VerifySignatureOnly(signature!).Should().BeTrue();
        Convert.ToHexString(signature!).Should().Contain(Convert.ToHexString(digest));
    }

    [Test]
    public void SignedImage_IsAcceptedBySigntool()
    {
        if (!SigntoolHarness.IsAvailable)
        {
            // CI sets this on the Windows leg so the gate cannot pass by never running —
            // a silently skipped correctness gate is worse than no gate, because the build
            // still goes green.
            Environment.GetEnvironmentVariable("SIGNUNIVERSAL_REQUIRE_SIGNTOOL").Should().BeNullOrEmpty(
                "signtool verification was required but unavailable: {0}", SigntoolHarness.UnavailableReason);

            // Elsewhere the offline checks above stand in. Skipping visibly rather than
            // returning quietly keeps the summary honest about what actually ran.
            Skip.Test(SigntoolHarness.UnavailableReason);
        }

        string path = Path.Combine(Path.GetTempPath(), $"sign-universal-{Guid.NewGuid():N}.dll");
        try
        {
            // Timestamp when a live authority is allowed. That strengthens this gate for
            // free: a malformed timestamp attribute would change signtool's verdict away
            // from the untrusted-root-only outcome asserted below.
            Uri? timestampUrl = Environment.GetEnvironmentVariable("SIGNUNIVERSAL_TIMESTAMP_TESTS") == "1"
                ? new Uri(AuthenticodeTimestamp.DefaultTimestampUrl)
                : null;

            using (MemoryStream image = LoadRealPeImage())
            using (LocalKeyRemoteSigner signer = new())
            {
                PeSigner.Sign(image, signer, HashAlgorithmName.SHA256, timestampUrl);
                File.WriteAllBytes(path, image.ToArray());
            }

            SigntoolResult result = SigntoolHarness.Verify(path);

            result.FoundSignature.Should().BeTrue(
                "signtool must parse the certificate table we wrote:\n{0}", result.Output);

            // The test certificate is self-signed, so chain validation cannot succeed here.
            // Everything short of trust must, which is what proves the format is right.
            (result.Succeeded || result.RejectedOnlyForUntrustedRoot).Should().BeTrue(
                "signtool rejected the signature for a reason other than an untrusted root "
                + $"(timestamped: {result.IsTimestamped}):\n{result.Output}");
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Test]
    public void SignFile_WhenSigningFails_LeavesTheExistingSignatureIntact()
    {
        // Preparing an image strips the signature it already had, so a backend that fails
        // afterwards — an expired key, a lost network, a rejected credential — must not be
        // able to leave an artifact behind with no signature at all.
        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "signed.dll");
        File.WriteAllBytes(path, LoadRealPeImage().ToArray());

        using LocalKeyRemoteSigner signer = new();
        PeSigner.SignFile(path, signer, HashAlgorithmName.SHA256);
        byte[] signed = File.ReadAllBytes(path);

        Action failedResign = () => PeSigner.SignFile(
            path, signer, HashAlgorithmName.SHA256, new Uri("http://localhost:1/timestamp"));

        failedResign.Should().Throw<CryptographicException>();
        File.ReadAllBytes(path).Should().Equal(signed, "a failed re-sign must not damage the file");
    }

    private static MemoryStream LoadRealPeImage()
    {
        string location = typeof(PeFile).Assembly.Location;
        MemoryStream stream = new();
        stream.Write(File.ReadAllBytes(location));
        return stream;
    }
}
