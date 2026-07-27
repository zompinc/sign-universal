using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using FluentAssertions;
using SignUniversal.Core.Authenticode;
using TUnit.Core;

namespace SignUniversal.Core.Tests;

/// <summary>
/// Locks in the two places Authenticode departs from stock CMS. Both are invisible to
/// <see cref="SignedCms"/>'s own verification and would only surface as a rejection
/// from Windows.
/// </summary>
public sealed class AuthenticodeContentTests
{
    /// <summary>
    /// The <c>SpcIndirectDataContent</c> of a Microsoft-signed binary, byte for byte.
    /// Everything before the digest is fixed structure, so our encoder must reproduce it
    /// exactly given the same digest.
    /// </summary>
    private const string MicrosoftReferenceContent =
        "304c3017060a2b06010401823702010f3009030100a004a2028000" +
        "3031300d060960864801650304020105000420" +
        "abc85a725c233b3efcd886f2b26de7926d13983efe6d8c4b8853b4f9cff23ab2";

    [Test]
    public void SpcIndirectData_MatchesMicrosoftsEncodingByteForByte()
    {
        byte[] digest = Convert.FromHexString(
            "abc85a725c233b3efcd886f2b26de7926d13983efe6d8c4b8853b4f9cff23ab2");

        byte[] encoded = SpcIndirectData.EncodeForPeImage(digest, HashAlgorithmName.SHA256);

        Convert.ToHexString(encoded).ToLowerInvariant().Should().Be(MicrosoftReferenceContent);
    }

    [Test]
    public void EncapsulatedContent_IsASequence_NotAnOctetString()
    {
        // RFC 5652 says OCTET STRING and SignedCms writes one; Authenticode embeds the
        // SpcIndirectDataContent SEQUENCE directly. Same value octets, different tag.
        (byte[] signedData, byte[] digest) = SignPeImage();

        ReadOnlyMemory<byte> content = ExtractEncapsulatedContent(signedData);

        content.Span[0].Should().Be(0x30, "the encapsulated content must be tagged SEQUENCE");
        content.ToArray().Should().Equal(SpcIndirectData.EncodeForPeImage(digest, HashAlgorithmName.SHA256));
    }

    [Test]
    public void MessageDigest_CoversTheContentValueOctets()
    {
        // Authenticode's messageDigest skips the SpcIndirectDataContent header — the
        // consequence of the content being an OCTET STRING that was retagged.
        (byte[] signedData, _) = SignPeImage();
        ReadOnlyMemory<byte> content = ExtractEncapsulatedContent(signedData);

        AsnDecoder.ReadSequence(
            content.Span, AsnEncodingRules.DER, out int valueOffset, out int valueLength, out _);
        byte[] expected = SHA256.HashData(content.Span.Slice(valueOffset, valueLength));

        SignedCms decoded = new();
        decoded.Decode(signedData);
        AsnEncodedData messageDigest = decoded.SignerInfos[0].SignedAttributes
            .Cast<CryptographicAttributeObject>()
            .Single(attribute => attribute.Oid.Value == "1.2.840.113549.1.9.4")
            .Values[0];

        byte[] actual = new AsnReader(messageDigest.RawData, AsnEncodingRules.BER).ReadOctetString();
        actual.Should().Equal(expected);
    }

    [Test]
    public void SignedAttributes_CarryTheStatementTypeMicrosoftUses()
    {
        (byte[] signedData, _) = SignPeImage();

        SignedCms decoded = new();
        decoded.Decode(signedData);
        CryptographicAttributeObject statementType = decoded.SignerInfos[0].SignedAttributes
            .Cast<CryptographicAttributeObject>()
            .Single(attribute => attribute.Oid.Value == "1.3.6.1.4.1.311.2.1.11");

        // SEQUENCE { OID 1.3.6.1.4.1.311.2.1.21 } — individualCodeSigning, byte for byte
        // what signtool emits.
        Convert.ToHexString(statementType.Values[0].RawData).ToLowerInvariant()
            .Should().Be("300c060a2b060104018237020115");
    }

    private static (byte[] SignedData, byte[] Digest) SignPeImage()
    {
        using MemoryStream image = new();
        image.Write(SyntheticPe.Build(pe32Plus: false, headerGap: 0, trailingBytes: 5));
        using LocalKeyRemoteSigner signer = new();

        byte[] digest = PeSigner.Sign(image, signer, HashAlgorithmName.SHA256);
        return (PeFile.ReadEmbeddedSignature(image)!, digest);
    }

    private static ReadOnlyMemory<byte> ExtractEncapsulatedContent(byte[] signedData)
    {
        Asn1Tag explicitContent = new(TagClass.ContextSpecific, 0, isConstructed: true);

        AsnReader contentInfo = new AsnReader(signedData, AsnEncodingRules.BER).ReadSequence();
        contentInfo.ReadObjectIdentifier();
        AsnReader signedDataReader = contentInfo.ReadSequence(explicitContent).ReadSequence();

        signedDataReader.ReadEncodedValue();    // version
        signedDataReader.ReadEncodedValue();    // digestAlgorithms

        AsnReader encapContentInfo = signedDataReader.ReadSequence();
        encapContentInfo.ReadObjectIdentifier();
        return encapContentInfo.ReadSequence(explicitContent).ReadEncodedValue();
    }
}
