namespace SignUniversal.Authenticode;

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
/// The value octets are identical in both forms - only the tag changes - which is
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
    /// <summary>The SignedData version Authenticode expects, regardless of what RFC 5652 says.</summary>
    private const int AuthenticodeSignedDataVersion = 1;

    private static readonly Asn1Tag ExplicitContent = new(TagClass.ContextSpecific, 0, isConstructed: true);
    private static readonly Asn1Tag SignedAttributes = new(TagClass.ContextSpecific, 0, isConstructed: true);

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
                ReadOnlySpan<byte> version = signedData.ReadEncodedValue().Span;
                if (toAuthenticodeForm)
                {
                    // RFC 5652 calls for version 3 when the content type is not id-data, and
                    // SignedCms obliges. Authenticode predates that and wants version 1;
                    // Windows rejects the message outright otherwise.
                    writer.WriteInteger(AuthenticodeSignedDataVersion);
                }
                else
                {
                    writer.WriteEncodedValue(version);
                }

                RewriteDigestAlgorithms(writer, signedData.ReadSetOf(), toAuthenticodeForm);

                AsnReader encapContentInfo = signedData.ReadSequence();
                using (writer.PushSequence())
                {
                    writer.WriteObjectIdentifier(encapContentInfo.ReadObjectIdentifier());
                    RewriteContent(writer, encapContentInfo, toAuthenticodeForm);
                }

                // certificates and crls are carried through untouched; the signer infos need
                // the same algorithm-identifier treatment as the digest algorithms above.
                List<byte[]> remaining = [];
                while (signedData.HasData)
                {
                    remaining.Add(signedData.ReadEncodedValue().ToArray());
                }

                for (int i = 0; i < remaining.Count - 1; i++)
                {
                    writer.WriteEncodedValue(remaining[i]);
                }

                if (remaining.Count > 0)
                {
                    RewriteSignerInfos(writer, remaining[^1], toAuthenticodeForm);
                }
            }
        }

        return writer.Encode();
    }

    /// <summary>
    /// Copies a SET OF AlgorithmIdentifier, supplying the explicit NULL parameters
    /// Authenticode expects.
    /// </summary>
    /// <remarks>
    /// RFC 5754 says the parameters SHOULD be absent for SHA-2, and .NET omits them.
    /// Every signature Windows produces carries them, and so do jsign and osslsigncode.
    /// </remarks>
    private static void RewriteDigestAlgorithms(AsnWriter writer, AsnReader algorithms, bool toAuthenticodeForm)
    {
        using (writer.PushSetOf())
        {
            while (algorithms.HasData)
            {
                RewriteAlgorithmIdentifier(writer, algorithms.ReadSequence(), toAuthenticodeForm);
            }
        }
    }

    private static void RewriteAlgorithmIdentifier(AsnWriter writer, AsnReader algorithm, bool toAuthenticodeForm)
    {
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier(algorithm.ReadObjectIdentifier());

            if (algorithm.HasData)
            {
                writer.WriteEncodedValue(algorithm.ReadEncodedValue().Span);
            }
            else if (toAuthenticodeForm)
            {
                writer.WriteNull();
            }
        }
    }

    /// <summary>Copies the signer infos, normalizing each one's digest algorithm.</summary>
    private static void RewriteSignerInfos(AsnWriter writer, byte[] encodedSignerInfos, bool toAuthenticodeForm)
    {
        AsnReader signerInfos = new AsnReader(encodedSignerInfos, AsnEncodingRules.BER).ReadSetOf();

        using (writer.PushSetOf())
        {
            while (signerInfos.HasData)
            {
                AsnReader signerInfo = signerInfos.ReadSequence();

                using (writer.PushSequence())
                {
                    // SignerInfo ::= SEQUENCE { version, sid, digestAlgorithm,
                    //                           [0] signedAttrs, signatureAlgorithm,
                    //                           signature, [1] unsignedAttrs }
                    writer.WriteEncodedValue(signerInfo.ReadEncodedValue().Span);
                    writer.WriteEncodedValue(signerInfo.ReadEncodedValue().Span);
                    RewriteAlgorithmIdentifier(writer, signerInfo.ReadSequence(), toAuthenticodeForm);

                    // signedAttrs is copied byte for byte: the signature covers its encoding,
                    // so rewriting so much as a length here would invalidate it.
                    if (signerInfo.HasData && signerInfo.PeekTag() == SignedAttributes)
                    {
                        writer.WriteEncodedValue(signerInfo.ReadEncodedValue().Span);
                    }

                    // rsaEncryption takes NULL parameters per RFC 8017, and Windows agrees.
                    RewriteAlgorithmIdentifier(writer, signerInfo.ReadSequence(), toAuthenticodeForm);

                    while (signerInfo.HasData)
                    {
                        writer.WriteEncodedValue(signerInfo.ReadEncodedValue().Span);
                    }
                }
            }
        }
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
