using System.Security.Cryptography.X509Certificates;

namespace SignUniversal.Core.Tests;

/// <summary>
/// RFC 3161 timestamping for Authenticode — what lets a signature outlive the
/// certificate that made it.
/// </summary>
/// <remarks>
/// The interesting test needs a live timestamp authority, so it is opt-in through
/// <c>SIGNUNIVERSAL_TIMESTAMP_TESTS</c> and enabled in CI. Leaving it on by default would
/// make every local run depend on someone else's uptime.
/// </remarks>
public sealed class AuthenticodeTimestampTests
{
    private const string SignatureTimestampOid = "1.3.6.1.4.1.311.3.3.1";

    private static bool LiveAuthorityEnabled =>
        Environment.GetEnvironmentVariable("SIGNUNIVERSAL_TIMESTAMP_TESTS") == "1";

    [Test]
    public void Sign_WithoutATimestamp_AttachesNothing()
    {
        SignedCms cms = Decode(SignPeImage(timestampUrl: null));

        cms.SignerInfos[0].UnsignedAttributes.Count.Should().Be(0);
        AuthenticodeTimestamp.TryGetTimestamp(cms).Should().BeNull();
    }

    [Test]
    public void Sign_WithATimestamp_AttachesATokenOverTheSignatureValue()
    {
        Skip.Unless(LiveAuthorityEnabled, "set SIGNUNIVERSAL_TIMESTAMP_TESTS=1 to exercise a live authority");

        SignedCms cms = Decode(SignPeImage(new Uri(AuthenticodeTimestamp.DefaultTimestampUrl)));

        // Authenticode keeps the token under Microsoft's own OID, not the id-aa-timeStampToken
        // that ordinary CMS uses. Every Microsoft-signed binary carries exactly this attribute.
        cms.SignerInfos[0].UnsignedAttributes
            .Cast<CryptographicAttributeObject>()
            .Should().ContainSingle(attribute => attribute.Oid.Value == SignatureTimestampOid);

        Rfc3161TimestampToken? token = AuthenticodeTimestamp.TryGetTimestamp(cms);
        token.Should().NotBeNull();

        // The authority attests to the signature value, so the imprint must be its hash and
        // the token must verify against it.
        byte[] imprint = SHA256.HashData(cms.SignerInfos[0].GetSignature());
        token!.TokenInfo.GetMessageHash().ToArray().Should().Equal(imprint);
        token.VerifySignatureForHash(imprint, HashAlgorithmName.SHA256, out X509Certificate2? authority)
            .Should().BeTrue();
        authority.Should().NotBeNull();

        token.TokenInfo.Timestamp.Should().BeCloseTo(DateTimeOffset.UtcNow, TimeSpan.FromMinutes(10));
    }

    [Test]
    public void Sign_WithATimestamp_LeavesTheSignatureItself_Valid()
    {
        Skip.Unless(LiveAuthorityEnabled, "set SIGNUNIVERSAL_TIMESTAMP_TESTS=1 to exercise a live authority");

        // Timestamping happens after the signature is computed and adds an unsigned
        // attribute, so it must not disturb what it countersigns.
        byte[] signature = SignPeImage(new Uri(AuthenticodeTimestamp.DefaultTimestampUrl));

        AuthenticodeSignedDataBuilder.VerifySignatureOnly(signature).Should().BeTrue();
    }

    [Test]
    public void Sign_WhenTheAuthorityIsUnreachable_FailsClearly()
    {
        using MemoryStream image = new();
        image.Write(SyntheticPe.Build(pe32Plus: false));
        using LocalKeyRemoteSigner signer = new();

        Action sign = () => PeSigner.Sign(
            image, signer, HashAlgorithmName.SHA256, new Uri("http://localhost:1/timestamp"));

        sign.Should().Throw<CryptographicException>().WithMessage("*could not be reached*");
    }

    private static byte[] SignPeImage(Uri? timestampUrl)
    {
        using MemoryStream image = new();
        image.Write(SyntheticPe.Build(pe32Plus: false, headerGap: 0, trailingBytes: 5));
        using LocalKeyRemoteSigner signer = new();

        PeSigner.Sign(image, signer, HashAlgorithmName.SHA256, timestampUrl);
        return PeFile.ReadEmbeddedSignature(image)!;
    }

    private static SignedCms Decode(byte[] signature)
    {
        SignedCms cms = new();
        cms.Decode(signature);
        return cms;
    }
}
