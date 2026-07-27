using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace SignUniversal.Core.Authenticode;

/// <summary>
/// Attaches an RFC 3161 timestamp to an Authenticode signature.
/// </summary>
/// <remarks>
/// <para>
/// A timestamp is what lets a signature outlive the certificate that made it. Without
/// one, the signature stops validating the moment the certificate expires — which for a
/// conventional certificate is years away, and for Azure Trusted Signing is about three
/// days.
/// </para>
/// <para>
/// Authenticode carries the token in an unsigned attribute on the signer info, under
/// Microsoft's own <c>szOID_RFC3161_counterSign</c> OID rather than the
/// <c>id-aa-timeStampToken</c> that ordinary CMS (and NuGet) uses. That detail was taken
/// from Microsoft-signed binaries, all of which carry exactly this attribute.
/// </para>
/// <para>
/// What the authority attests to is the signature value — the encrypted digest in the
/// signer info — not the file and not the signed attributes. Nothing this class does can
/// disturb the signature it timestamps.
/// </para>
/// </remarks>
public static class AuthenticodeTimestamp
{
    /// <summary>The timestamp authority used when none is specified.</summary>
    public const string DefaultTimestampUrl = "http://timestamp.digicert.com";

    /// <summary>SPC_RFC3161_OBJID — where Authenticode keeps its RFC 3161 token.</summary>
    internal const string Rfc3161CounterSignOid = "1.3.6.1.4.1.311.3.3.1";

    private static readonly MediaTypeHeaderValue TimestampQuery = new("application/timestamp-query");

    /// <summary>Timestamps the first signer of a SignedCms, in place.</summary>
    /// <param name="signedCms">The signature to timestamp.</param>
    /// <param name="timestampUrl">The RFC 3161 authority.</param>
    /// <param name="hashAlgorithm">The digest algorithm for the timestamp request.</param>
    /// <param name="timeout">How long to wait on the authority.</param>
    /// <exception cref="CryptographicException">The authority refused or returned an unusable response.</exception>
    public static void Apply(
        SignedCms signedCms,
        Uri timestampUrl,
        HashAlgorithmName hashAlgorithm,
        TimeSpan timeout)
    {
        ArgumentNullException.ThrowIfNull(signedCms);
        ArgumentNullException.ThrowIfNull(timestampUrl);

        SignerInfo signerInfo = signedCms.SignerInfos[0];

        // The authority timestamps the signature value, hashed — not the file.
        byte[] signature = signerInfo.GetSignature();
        byte[] messageImprint = Hash(signature, hashAlgorithm);

        Rfc3161TimestampRequest request = Rfc3161TimestampRequest.CreateFromHash(
            messageImprint,
            hashAlgorithm,
            requestedPolicyId: null,
            nonce: null,
            // Without the authority's certificate the token cannot be validated by anyone
            // who did not already have it.
            requestSignerCertificates: true);

        byte[] response = Post(timestampUrl, request.Encode(), timeout);

        Rfc3161TimestampToken token;
        try
        {
            token = request.ProcessResponse(response, out _);
        }
        catch (CryptographicException ex)
        {
            throw new CryptographicException(
                $"The timestamp authority at '{timestampUrl}' returned a response that could not be used: {ex.Message}",
                ex);
        }

        signerInfo.AddUnsignedAttribute(
            new AsnEncodedData(new Oid(Rfc3161CounterSignOid), token.AsSignedCms().Encode()));
    }

    /// <summary>Reads the RFC 3161 token attached to an Authenticode signature, if any.</summary>
    /// <param name="signedCms">The decoded signature.</param>
    /// <returns>The token, or <see langword="null"/> when the signature is not timestamped.</returns>
    public static Rfc3161TimestampToken? TryGetTimestamp(SignedCms signedCms)
    {
        ArgumentNullException.ThrowIfNull(signedCms);

        foreach (CryptographicAttributeObject attribute in signedCms.SignerInfos[0].UnsignedAttributes)
        {
            if (attribute.Oid.Value != Rfc3161CounterSignOid || attribute.Values.Count == 0)
            {
                continue;
            }

            if (Rfc3161TimestampToken.TryDecode(attribute.Values[0].RawData, out Rfc3161TimestampToken? token, out _))
            {
                return token;
            }
        }

        return null;
    }

    private static byte[] Hash(byte[] data, HashAlgorithmName hashAlgorithm)
    {
        using IncrementalHash hash = IncrementalHash.CreateHash(hashAlgorithm);
        hash.AppendData(data);
        return hash.GetHashAndReset();
    }

    private static byte[] Post(Uri timestampUrl, byte[] request, TimeSpan timeout)
    {
        using HttpClient client = new() { Timeout = timeout };
        using ByteArrayContent content = new(request);
        content.Headers.ContentType = TimestampQuery;

        using HttpRequestMessage message = new(HttpMethod.Post, timestampUrl) { Content = content };

        HttpResponseMessage response;
        try
        {
            // Synchronous on purpose: this keeps the signing pipeline free of async
            // plumbing for the one network call it makes.
            response = client.Send(message);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            throw new CryptographicException(
                $"The timestamp authority at '{timestampUrl}' could not be reached: {ex.Message}", ex);
        }

        using (response)
        {
            if (!response.IsSuccessStatusCode)
            {
                throw new CryptographicException(
                    $"The timestamp authority at '{timestampUrl}' responded with {(int)response.StatusCode} {response.ReasonPhrase}.");
            }

            using Stream stream = response.Content.ReadAsStream();
            using MemoryStream buffer = new();
            stream.CopyTo(buffer);
            return buffer.ToArray();
        }
    }
}
