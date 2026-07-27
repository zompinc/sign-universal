using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using global::Azure.Core;
using global::Azure.Identity;
using global::Azure.Security.KeyVault.Certificates;
using global::Azure.Security.KeyVault.Keys.Cryptography;

namespace SignUniversal.Core.Signing.Azure;

/// <summary>
/// An <see cref="IRemoteSigner"/> backed by a certificate in Azure Key Vault.
/// </summary>
/// <remarks>
/// <para>
/// The certificate's public half is read from the vault and the private key stays in it:
/// signing sends a digest to <c>CryptographyClient</c> and gets a signature back. A key
/// marked non-exportable, or backed by a managed HSM, never leaves Azure at all — and
/// nothing here would work any differently if it could.
/// </para>
/// <para>
/// Unlike Trusted Signing, a Key Vault certificate is long-lived and usually issued by a
/// public CA, so the usual chain and trust problems do not arise. Timestamping still
/// matters: it is what keeps a signature valid after the certificate expires.
/// </para>
/// </remarks>
public sealed class KeyVaultRemoteSigner : IRemoteSigner, IDisposable
{
    private readonly CryptographyClient _cryptography;

    /// <summary>Initializes a new instance.</summary>
    /// <param name="vaultUri">The vault, e.g. <c>https://my-vault.vault.azure.net</c>.</param>
    /// <param name="certificateName">The name of the certificate in the vault.</param>
    /// <param name="credential">
    /// The credential to authenticate with; defaults to <see cref="DefaultAzureCredential"/>,
    /// which reads the <c>AZURE_TENANT_ID</c>, <c>AZURE_CLIENT_ID</c>, and
    /// <c>AZURE_CLIENT_SECRET</c> variables a CI job typically supplies.
    /// </param>
    /// <exception cref="NotSupportedException">The certificate does not hold an RSA key.</exception>
    public KeyVaultRemoteSigner(Uri vaultUri, string certificateName, TokenCredential? credential = null)
    {
        ArgumentNullException.ThrowIfNull(vaultUri);
        ArgumentException.ThrowIfNullOrEmpty(certificateName);

        credential ??= new DefaultAzureCredential();

        CertificateClient certificates = new(vaultUri, credential);
        KeyVaultCertificateWithPolicy certificate = certificates.GetCertificate(certificateName);

        Certificate = new X509Certificate2(certificate.Cer);

        using (RSA? publicKey = Certificate.GetRSAPublicKey())
        {
            if (publicKey is null)
            {
                throw new NotSupportedException(
                    $"The certificate '{certificateName}' does not hold an RSA key; only RSA signing is supported today.");
            }
        }

        // KeyId points at the key behind the certificate, which is where signing happens.
        _cryptography = new CryptographyClient(certificate.KeyId, credential);
    }

    /// <inheritdoc />
    public X509Certificate2 Certificate { get; }

    /// <inheritdoc />
    /// <remarks>
    /// The vault hands back only the leaf. Key Vault certificates are normally issued by a
    /// public CA, so the issuers can be resolved locally — and embedding them is what lets
    /// someone else validate the signature without chasing the chain themselves.
    /// </remarks>
    public IReadOnlyList<X509Certificate2> GetCertificateChain(CancellationToken cancellationToken = default)
    {
        using X509Chain chain = new();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;

        if (!chain.Build(Certificate))
        {
            return [Certificate];
        }

        return chain.ChainElements
            .Select(element => new X509Certificate2(element.Certificate.RawData))
            .ToArray();
    }

    /// <inheritdoc />
    public byte[] SignHash(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
    {
        ArgumentNullException.ThrowIfNull(hash);

        return _cryptography.Sign(MapAlgorithm(hashAlgorithm, padding), hash).Signature;
    }

    /// <summary>Maps a hash algorithm and padding onto the vault's signature algorithm names.</summary>
    /// <param name="hashAlgorithm">The digest algorithm.</param>
    /// <param name="padding">The RSA padding.</param>
    /// <returns>The matching Key Vault algorithm.</returns>
    /// <exception cref="NotSupportedException">The combination has no Key Vault equivalent.</exception>
    internal static SignatureAlgorithm MapAlgorithm(HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
    {
        bool probabilistic = padding == RSASignaturePadding.Pss;

        return hashAlgorithm.Name switch
        {
            "SHA256" => probabilistic ? SignatureAlgorithm.PS256 : SignatureAlgorithm.RS256,
            "SHA384" => probabilistic ? SignatureAlgorithm.PS384 : SignatureAlgorithm.RS384,
            "SHA512" => probabilistic ? SignatureAlgorithm.PS512 : SignatureAlgorithm.RS512,
            _ => throw new NotSupportedException(
                $"Key Vault has no signature algorithm for {hashAlgorithm.Name} with {padding}."),
        };
    }

    /// <inheritdoc />
    public void Dispose() => Certificate.Dispose();
}
