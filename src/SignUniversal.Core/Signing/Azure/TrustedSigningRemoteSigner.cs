using global::Azure.Core;
using global::Azure.Developer.TrustedSigning.CryptoProvider;
using global::Azure.Identity;

namespace SignUniversal.Core.Signing.Azure;

/// <summary>
/// An <see cref="IRemoteSigner"/> backed by Azure Trusted Signing.
/// </summary>
/// <remarks>
/// <para>
/// Trusted Signing mints a short-lived certificate per signing session and keeps the
/// key in its own HSM; a digest goes out over HTTPS and a signature comes back. That is
/// exactly the shape of <see cref="IRemoteSigner"/>, so nothing above this class knows
/// the difference between it and a local key.
/// </para>
/// <para>
/// This uses <c>Azure.Developer.TrustedSigning.CryptoProvider</c>, a managed client, and
/// not <c>Microsoft.Trusted.Signing.Client</c>, which ships a native signtool Dlib and
/// only runs on Windows. That choice is the whole reason this tool can sign from Linux.
/// </para>
/// <para>
/// Certificates are valid for roughly three days, so signatures produced with this
/// backend must be timestamped or they stop verifying almost at once.
/// </para>
/// </remarks>
public sealed class TrustedSigningRemoteSigner : IRemoteSigner, IDisposable
{
    private readonly AzSignContext _context;

    /// <summary>Initializes a new instance.</summary>
    /// <param name="endpoint">The regional endpoint, e.g. <c>https://eus.codesigning.azure.net</c>.</param>
    /// <param name="accountName">The Trusted Signing account name.</param>
    /// <param name="certificateProfile">The certificate profile name.</param>
    /// <param name="credential">
    /// The credential to authenticate with; defaults to <see cref="DefaultAzureCredential"/>,
    /// which picks up the <c>AZURE_TENANT_ID</c>, <c>AZURE_CLIENT_ID</c>, and
    /// <c>AZURE_CLIENT_SECRET</c> variables a CI job typically supplies.
    /// </param>
    public TrustedSigningRemoteSigner(
        Uri endpoint,
        string accountName,
        string certificateProfile,
        TokenCredential? credential = null)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        ArgumentException.ThrowIfNullOrEmpty(accountName);
        ArgumentException.ThrowIfNullOrEmpty(certificateProfile);

        _context = new AzSignContext(
            credential ?? new DefaultAzureCredential(),
            accountName,
            certificateProfile,
            endpoint);

        // The certificate has to be known before signing: its hash goes into the signed
        // attributes, so it cannot be discovered from the response afterwards.
        Certificate = _context.GetSigningCertificate(CancellationToken.None);
    }

    /// <inheritdoc />
    public X509Certificate2 Certificate { get; }

    /// <inheritdoc />
    /// <remarks>
    /// Trusted Signing issues from CAs that chain to a root Linux trust stores do not
    /// carry, so the chain is fetched from the service rather than reconstructed locally.
    /// </remarks>
    public IReadOnlyList<X509Certificate2> GetCertificateChain(CancellationToken cancellationToken = default) =>
        _context.GetCertChain(cancellationToken);

    /// <inheritdoc />
    public byte[] SignHash(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
    {
        ArgumentNullException.ThrowIfNull(hash);

        // The service infers the digest algorithm from the digest length, and refuses to
        // sign with a certificate other than the one we already committed to.
        return _context.SignDigest(hash, padding, expectedSigningCert: Certificate);
    }

    /// <inheritdoc />
    public void Dispose() => Certificate.Dispose();
}
