namespace SignUniversal.Signing;

/// <summary>
/// A signing backend whose private key lives remotely - Azure Key Vault, Azure
/// Trusted Signing, an HSM, a smart card, and so on.
/// </summary>
/// <remarks>
/// The key never leaves the backend. Only a precomputed digest is sent to be
/// signed, and only the raw signature comes back. This is the seam that lets the
/// same signing pipeline run on Linux, macOS, and Windows: everything up to and
/// including the digest is pure managed code; the private-key operation is the one
/// call that is delegated.
/// </remarks>
public interface IRemoteSigner
{
    /// <summary>
    /// Gets the signing certificate (public portion), ideally with any
    /// intermediate certificates the backend can supply for the chain.
    /// </summary>
    X509Certificate2 Certificate { get; }

    /// <summary>
    /// Gets the chain for <see cref="Certificate"/>, including the certificate itself.
    /// </summary>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The chain, or just the signing certificate when the backend has no more to offer.</returns>
    /// <remarks>
    /// Backends that mint short-lived certificates issue them from CAs a build agent has
    /// never heard of, so the chain cannot be reconstructed locally - it has to come from
    /// the backend. Signatures embed these certificates; without them a verifier has
    /// nothing to build a path from.
    /// </remarks>
    IReadOnlyList<X509Certificate2> GetCertificateChain(CancellationToken cancellationToken = default) =>
        [Certificate];

    /// <summary>
    /// Signs a precomputed <paramref name="hash"/> with RSA using the specified
    /// hash algorithm and padding, returning the raw signature bytes.
    /// </summary>
    /// <param name="hash">The digest to sign (already computed by the caller).</param>
    /// <param name="hashAlgorithm">The algorithm used to produce <paramref name="hash"/>.</param>
    /// <param name="padding">The RSA signature padding to apply.</param>
    /// <returns>The raw RSA signature.</returns>
    byte[] SignHash(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding);
}
