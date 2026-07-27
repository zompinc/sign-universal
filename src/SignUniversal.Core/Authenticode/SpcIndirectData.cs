using System.Formats.Asn1;
using System.Security.Cryptography;

namespace SignUniversal.Core.Authenticode;

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

            // messageDigest: DigestInfo { AlgorithmIdentifier, OCTET STRING digest }
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

        return writer.Encode();
    }
}
