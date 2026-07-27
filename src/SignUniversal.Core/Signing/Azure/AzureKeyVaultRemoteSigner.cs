namespace SignUniversal.Core.Signing.Azure;

/// <summary>
/// Placeholder for an <see cref="SignUniversal.Core.Signing.IRemoteSigner"/> backed
/// by Azure Key Vault / Azure Trusted Signing.
/// </summary>
/// <remarks>
/// Will use <c>Azure.Security.KeyVault.Keys.Cryptography.CryptographyClient</c> to
/// sign the digest inside the vault and <c>Azure.Identity.DefaultAzureCredential</c>
/// for CI-friendly authentication, so the private key never leaves the HSM. The
/// packages are already pinned in <c>Directory.Packages.props</c>; this is wired up
/// in the Azure milestone.
/// </remarks>
public static class AzureKeyVaultRemoteSigner
{
    // TODO(azure-milestone): implement IRemoteSigner via CryptographyClient.Sign +
    // DefaultAzureCredential. Map RSASignaturePadding -> SignatureAlgorithm (RS256/PS256).
}
