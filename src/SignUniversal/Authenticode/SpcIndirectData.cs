namespace SignUniversal.Authenticode;

/// <summary>
/// Encodes the <c>SpcIndirectDataContent</c> structure that Authenticode uses as
/// the encapsulated content of its PKCS#7 SignedData.
/// </summary>
/// <remarks>
/// <code>
/// SpcIndirectDataContent ::= SEQUENCE {
///     data          SpcAttributeTypeAndOptionalValue,
///     messageDigest DigestInfo
/// }
/// SpcAttributeTypeAndOptionalValue ::= SEQUENCE {
///     type  OBJECT IDENTIFIER,
///     value [0] ANY OPTIONAL
/// }
/// DigestInfo ::= SEQUENCE {
///     digestAlgorithm AlgorithmIdentifier,
///     digest          OCTET STRING
/// }
/// SpcPeImageData ::= SEQUENCE {
///     flags SpcPeImageFlags DEFAULT { includeResources },
///     file  [0] EXPLICIT SpcLink
/// }
/// SpcLink ::= CHOICE {
///     url     [0] IMPLICIT IA5STRING,
///     moniker [1] IMPLICIT SpcSerializedObject,
///     file    [2] EXPLICIT SpcString
/// }
/// SpcString ::= CHOICE {
///     unicode [0] IMPLICIT BMPSTRING,
///     ascii   [1] IMPLICIT IA5STRING
/// }
/// </code>
/// The encoding mirrors what signtool emits for a PE image with no page hashes:
/// empty flags plus an empty unicode <c>SpcLink</c> file, i.e. the fixed prefix
/// <c>3009 030100 A004 A2028000</c>. jsign writes the string <c>&lt;&lt;&lt;Obsolete&gt;&gt;&gt;</c>
/// there instead; both are accepted, and matching Microsoft keeps byte diffs against
/// real signatures small.
/// </remarks>
public static class SpcIndirectData
{
    private static readonly Asn1Tag FileField = new(TagClass.ContextSpecific, 0, isConstructed: true);
    private static readonly Asn1Tag SpcLinkFile = new(TagClass.ContextSpecific, 2, isConstructed: true);
    private static readonly Asn1Tag SpcStringUnicode = new(TagClass.ContextSpecific, 0);

    /// <summary>
    /// The SIP identifier Windows uses for MSI packages, {000C10F1-0000-0000-C000-000000000046}
    /// in its little-endian GUID layout.
    /// </summary>
    private static readonly byte[] MsiSipGuid =
    [
        0xF1, 0x10, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
    ];

    /// <summary>Builds the DER-encoded <c>SpcIndirectDataContent</c> for an MSI package digest.</summary>
    /// <param name="authenticodeDigest">The Authenticode digest of the package.</param>
    /// <param name="hashAlgorithm">The algorithm used to compute the digest.</param>
    /// <returns>The DER encoding of the structure.</returns>
    /// <remarks>
    /// An MSI names its subject with <c>SpcSipInfo</c> rather than the <c>SpcPeImageData</c>
    /// a PE image uses. The shape is taken from Microsoft-signed packages: version 2 - not
    /// 1, which is the obvious guess - the MSI SIP GUID, and five zeroes.
    /// </remarks>
    public static byte[] EncodeForMsi(ReadOnlySpan<byte> authenticodeDigest, HashAlgorithmName hashAlgorithm)
    {
        AsnWriter writer = new(AsnEncodingRules.DER);

        using (writer.PushSequence())
        {
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier(AuthenticodeOids.SpcSipInfoObjId);

                using (writer.PushSequence())
                {
                    writer.WriteInteger(2);
                    writer.WriteOctetString(MsiSipGuid);

                    for (int i = 0; i < 5; i++)
                    {
                        writer.WriteInteger(0);
                    }
                }
            }

            WriteDigestInfo(writer, authenticodeDigest, hashAlgorithm);
        }

        return writer.Encode();
    }

    /// <summary>Builds the DER-encoded <c>SpcIndirectDataContent</c> for a PE image digest.</summary>
    /// <param name="authenticodeDigest">The Authenticode digest of the subject file.</param>
    /// <param name="hashAlgorithm">The algorithm used to compute the digest.</param>
    /// <returns>The DER encoding of the structure.</returns>
    public static byte[] EncodeForPeImage(ReadOnlySpan<byte> authenticodeDigest, HashAlgorithmName hashAlgorithm)
    {
        AsnWriter writer = new(AsnEncodingRules.DER);

        using (writer.PushSequence())
        {
            // data: SpcAttributeTypeAndOptionalValue { type = SPC_PE_IMAGE_DATAOBJ, value = SpcPeImageData }
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier(AuthenticodeOids.SpcPeImageDataObjId);

                using (writer.PushSequence())
                {
                    // flags: an empty BIT STRING, leaving SpcPeImageFlags at its default.
                    writer.WriteBitString(ReadOnlySpan<byte>.Empty);

                    using (writer.PushSequence(FileField))
                    using (writer.PushSequence(SpcLinkFile))
                    {
                        writer.WriteCharacterString(UniversalTagNumber.BMPString, string.Empty, SpcStringUnicode);
                    }
                }
            }

            WriteDigestInfo(writer, authenticodeDigest, hashAlgorithm);
        }

        return writer.Encode();
    }

    /// <summary>Writes <c>DigestInfo ::= SEQUENCE { AlgorithmIdentifier, OCTET STRING }</c>.</summary>
    private static void WriteDigestInfo(
        AsnWriter writer, ReadOnlySpan<byte> authenticodeDigest, HashAlgorithmName hashAlgorithm)
    {
        using (writer.PushSequence())
        {
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier(AuthenticodeOids.DigestOid(hashAlgorithm));
                writer.WriteNull();
            }

            writer.WriteOctetString(authenticodeDigest);
        }
    }
}
