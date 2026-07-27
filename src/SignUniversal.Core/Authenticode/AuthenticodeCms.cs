using System.Formats.Asn1;

namespace SignUniversal.Core.Authenticode;

/// <summary>
/// Converts between the CMS encapsulation .NET produces and the one Authenticode
/// requires. The two differ by a single tag on the encapsulated content.
/// </summary>
/// <remarks>
/// <para>
/// RFC 5652 stores <c>eContent</c> as an OCTET STRING, and
/// <see cref="System.Security.Cryptography.Pkcs.SignedCms"/> always writes it that
/// way: <c>[0] { OCTET STRING value }</c>. Authenticode instead embeds the
/// <c>SpcIndirectDataContent</c> SEQUENCE directly: <c>[0] { SEQUENCE value }</c>.
/// </para>
/// <para>
/// The value octets are identical in both forms — only the tag changes — which is
/// also why Authenticode's <c>messageDigest</c> attribute covers the contents of
/// <c>SpcIndirectDataContent</c> rather than its full TLV. Feeding
/// <see cref="System.Security.Cryptography.Pkcs.SignedCms"/> those value octets
/// therefore yields exactly the digest Windows expects, and the signature stays valid
/// across the retag: it covers the signed attributes, not the encapsulation.
/// </para>
/// <para>
/// Both shapes were checked against Microsoft-signed binaries; the round trip is
/// byte-for-byte reversible.
/// </para>
/// </remarks>
internal static class AuthenticodeCms
{
    private static readonly Asn1Tag ExplicitContent = new(TagClass.ContextSpecific, 0, isConstructed: true);

    /// <summary>Retags encapsulated content from the CMS OCTET STRING form to the Authenticode SEQUENCE form.</summary>
    /// <param name="encodedSignedData">DER produced by <c>SignedCms.Encode</c>.</param>
    /// <returns>The same SignedData in Authenticode form.</returns>
    public static byte[] ToAuthenticodeForm(byte[] encodedSignedData) =>
        Retag(encodedSignedData, toAuthenticodeForm: true);

    /// <summary>Retags encapsulated content from the Authenticode SEQUENCE form back to the CMS OCTET STRING form.</summary>
    /// <param name="encodedSignedData">DER in Authenticode form.</param>
    /// <returns>The same SignedData in the shape <c>SignedCms.Decode</c> expects.</returns>
    public static byte[] ToCmsForm(byte[] encodedSignedData) =>
        Retag(encodedSignedData, toAuthenticodeForm: false);

    private static byte[] Retag(byte[] encodedSignedData, bool toAuthenticodeForm)
    {
        ArgumentNullException.ThrowIfNull(encodedSignedData);

        AsnReader contentInfo = new AsnReader(encodedSignedData, AsnEncodingRules.BER).ReadSequence();
        string contentType = contentInfo.ReadObjectIdentifier();
        AsnReader signedData = contentInfo.ReadSequence(ExplicitContent).ReadSequence();

        AsnWriter writer = new(AsnEncodingRules.DER);

        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier(contentType);

            using (writer.PushSequence(ExplicitContent))
            using (writer.PushSequence())
            {
                // SignedData ::= SEQUENCE { version, digestAlgorithms, encapContentInfo, ... }
                writer.WriteEncodedValue(signedData.ReadEncodedValue().Span);
                writer.WriteEncodedValue(signedData.ReadEncodedValue().Span);

                AsnReader encapContentInfo = signedData.ReadSequence();
                using (writer.PushSequence())
                {
                    writer.WriteObjectIdentifier(encapContentInfo.ReadObjectIdentifier());
                    RewriteContent(writer, encapContentInfo, toAuthenticodeForm);
                }

                // certificates, crls, signerInfos — carried through untouched.
                while (signedData.HasData)
                {
                    writer.WriteEncodedValue(signedData.ReadEncodedValue().Span);
                }
            }
        }

        return writer.Encode();
    }

    private static void RewriteContent(AsnWriter writer, AsnReader encapContentInfo, bool toAuthenticodeForm)
    {
        if (!encapContentInfo.HasData)
        {
            // Detached signature: there is no content to retag.
            return;
        }

        AsnReader content = encapContentInfo.ReadSequence(ExplicitContent);

        using (writer.PushSequence(ExplicitContent))
        {
            if (toAuthenticodeForm)
            {
                // OCTET STRING value -> SEQUENCE with the same value octets. The value is a
                // run of complete TLVs, so it is re-emitted one element at a time.
                AsnReader elements = new(content.ReadOctetString(), AsnEncodingRules.DER);
                using (writer.PushSequence())
                {
                    while (elements.HasData)
                    {
                        writer.WriteEncodedValue(elements.ReadEncodedValue().Span);
                    }
                }
            }
            else
            {
                AsnReader elements = content.ReadSequence();
                AsnWriter valueOctets = new(AsnEncodingRules.DER);
                while (elements.HasData)
                {
                    valueOctets.WriteEncodedValue(elements.ReadEncodedValue().Span);
                }

                writer.WriteOctetString(valueOctets.Encode());
            }
        }
    }
}
