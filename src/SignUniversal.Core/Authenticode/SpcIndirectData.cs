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
/// </code>
/// The <c>SpcPeImageData</c> value is intentionally minimal here (flags only); the
/// full <c>SpcLink</c>/file field is filled in once the PE embedding path lands. The
/// digest and algorithm — the parts a verifier checks against the file — are real.
/// </remarks>
public static class SpcIndirectData
{
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

                // SpcPeImageData ::= SEQUENCE { flags SpcPeImageFlags DEFAULT { includeResources }, file [0] SpcLink }
                // Minimal placeholder: flags only. TODO: emit the SpcLink file field with the PE work.
                using (writer.PushSequence())
                {
                    writer.WriteBitString([0x00]);
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
