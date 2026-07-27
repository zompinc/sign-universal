using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using SignUniversal.Core.Signing;

namespace SignUniversal.Core.Authenticode;

/// <summary>
/// Builds an Authenticode PKCS#7 SignedData blob over a precomputed file digest,
/// signing through an <see cref="IRemoteSigner"/> so the private key never enters
/// the process.
/// </summary>
/// <remarks>
/// This is where the port is dramatically smaller than jsign: the CMS SignedData
/// assembly, signed-attribute handling, and signature encoding are all provided by
/// <see cref="SignedCms"/>/<see cref="CmsSigner"/>. Our only contribution is the
/// Authenticode content type, the <see cref="SpcIndirectData"/> payload, and the
/// remote-key seam.
/// </remarks>
public static class AuthenticodeSignedDataBuilder
{
    /// <summary>
    /// Produces the DER-encoded SignedData for the given digest, signed by
    /// <paramref name="signer"/>.
    /// </summary>
    /// <param name="signer">The backend holding the private key.</param>
    /// <param name="authenticodeDigest">The Authenticode digest of the subject file.</param>
    /// <param name="hashAlgorithm">The digest/signature hash algorithm.</param>
    /// <param name="timestampUrl">
    /// The RFC 3161 authority to countersign with, or <see langword="null"/> to leave the
    /// signature untimestamped — in which case it expires with the certificate.
    /// </param>
    /// <param name="timestampTimeout">How long to wait on the authority.</param>
    /// <param name="subject">What kind of file the digest describes.</param>
    /// <returns>The encoded PKCS#7 SignedData.</returns>
    public static byte[] Build(
        IRemoteSigner signer,
        ReadOnlySpan<byte> authenticodeDigest,
        HashAlgorithmName hashAlgorithm,
        Uri? timestampUrl = null,
        TimeSpan? timestampTimeout = null,
        SignedSubject subject = SignedSubject.PeImage)
    {
        ArgumentNullException.ThrowIfNull(signer);

        // The two subjects differ only in how they name themselves: a PE image carries
        // SpcPeImageData, an MSI carries SpcSipInfo. Everything below is identical.
        byte[] spcContent = subject switch
        {
            SignedSubject.PeImage => SpcIndirectData.EncodeForPeImage(authenticodeDigest, hashAlgorithm),
            SignedSubject.Msi => SpcIndirectData.EncodeForMsi(authenticodeDigest, hashAlgorithm),
            _ => throw new ArgumentOutOfRangeException(nameof(subject)),
        };

        // Authenticode's messageDigest attribute covers the *value octets* of
        // SpcIndirectDataContent, not its whole TLV — the encapsulated content is this
        // OCTET STRING with its tag swapped for a SEQUENCE (see AuthenticodeCms). Handing
        // SignedCms the value octets is what makes it compute the digest Windows expects.
        AsnDecoder.ReadSequence(spcContent, AsnEncodingRules.DER, out int valueOffset, out int valueLength, out _);
        byte[] spcValueOctets = spcContent[valueOffset..(valueOffset + valueLength)];

        ContentInfo contentInfo = new(new Oid(AuthenticodeOids.SpcIndirectDataObjId), spcValueOctets);
        SignedCms signedCms = new(contentInfo, detached: false);

        using RemoteSigningRsa remoteRsa = new(signer);

        // Pass the private key SEPARATELY (not via CopyWithPrivateKey). On Linux/OpenSSL,
        // CopyWithPrivateKey eagerly exports private parameters, which a remote key cannot
        // provide; this overload signs through the supplied key's SignHash instead — the
        // one operation we delegate to the backend.
        CmsSigner cmsSigner = new(SubjectIdentifierType.IssuerAndSerialNumber, signer.Certificate, remoteRsa)
        {
            DigestAlgorithm = new Oid(AuthenticodeOids.DigestOid(hashAlgorithm)),
            IncludeOption = X509IncludeOption.EndCertOnly,
        };

        // Every Authenticode signature in the wild carries this attribute, signtool's and
        // jsign's included. It is cheap, so we match rather than test what Windows tolerates.
        cmsSigner.SignedAttributes.Add(
            new AsnEncodedData(new Oid(AuthenticodeOids.SpcStatementTypeObjId), EncodeStatementType()));

        // EndCertOnly covers the signing certificate; the issuers above it have to be added
        // by hand. A backend that mints short-lived certificates is the only thing that can
        // supply them, since they chain to CAs the machine does not know.
        foreach (X509Certificate2 issuer in signer.GetCertificateChain())
        {
            if (!string.Equals(issuer.Thumbprint, signer.Certificate.Thumbprint, StringComparison.OrdinalIgnoreCase))
            {
                cmsSigner.Certificates.Add(issuer);
            }
        }

        signedCms.ComputeSignature(cmsSigner);

        if (timestampUrl is not null)
        {
            AuthenticodeTimestamp.Apply(
                signedCms, timestampUrl, hashAlgorithm, timestampTimeout ?? TimeSpan.FromSeconds(60));
        }

        return AuthenticodeCms.ToAuthenticodeForm(signedCms.Encode());
    }

    /// <summary>Encodes <c>SpcStatementType ::= SEQUENCE OF OBJECT IDENTIFIER</c>.</summary>
    private static byte[] EncodeStatementType()
    {
        AsnWriter writer = new(AsnEncodingRules.DER);

        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier(AuthenticodeOids.IndividualCodeSigningObjId);
        }

        return writer.Encode();
    }

    /// <summary>
    /// Verifies that an encoded SignedData blob has a valid signature over its
    /// content. Signature-only (no chain/trust) — suitable for the spike and for
    /// round-trip tests with self-signed certificates.
    /// </summary>
    /// <param name="encodedSignedData">The DER-encoded SignedData, in Authenticode form.</param>
    /// <returns><see langword="true"/> if the signature verifies.</returns>
    public static bool VerifySignatureOnly(byte[] encodedSignedData)
    {
        ArgumentNullException.ThrowIfNull(encodedSignedData);

        // SignedCms verifies against its own encapsulation, so the Authenticode SEQUENCE
        // has to go back to being an OCTET STRING first. The bytes it digests are the same.
        SignedCms signedCms = new();
        signedCms.Decode(AuthenticodeCms.ToCmsForm(encodedSignedData));

        try
        {
            signedCms.CheckSignature(verifySignatureOnly: true);
            return true;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }
}
