using System.Security.Cryptography.X509Certificates;

namespace SignUniversal.Cli;

/// <summary>
/// Installs a signing backend's root certificate into the current user's trust store.
/// </summary>
/// <remarks>
/// <para>
/// NuGet builds and validates the signing certificate's chain against the machine's
/// trust store before it will sign, and an untrusted root is fatal. Trusted Signing
/// issues from <c>Microsoft Identity Verification Root Certificate Authority 2020</c>,
/// which Linux trust stores do not carry - so signing fails on an otherwise perfectly
/// configured agent with nothing but "Certificate chain validation failed".
/// </para>
/// <para>
/// The root is taken from the chain the signing service itself returned over an
/// authenticated TLS connection, which is a far better provenance than downloading a
/// CA certificate over plain HTTP. It goes into the current user's store only - never
/// the machine's - and it is opt-in, because a signing tool that quietly adds trust
/// roots would be a poor citizen.
/// </para>
/// </remarks>
internal static class SigningRootTrust
{
    /// <summary>Adds the backend's root certificate to the current user's trust store.</summary>
    /// <param name="signer">The backend to take the chain from.</param>
    public static void Install(IRemoteSigner signer)
    {
        IReadOnlyList<X509Certificate2> chain = signer.GetCertificateChain();

        // Self-issued means the root; fall back to the end of the chain.
        X509Certificate2? root = chain.FirstOrDefault(certificate =>
            string.Equals(certificate.Subject, certificate.Issuer, StringComparison.Ordinal));

        if (root is null && chain.Count > 1)
        {
            root = chain[^1];
        }

        if (root is null)
        {
            Console.Error.WriteLine(
                "warning: the backend supplied no issuer chain, so there is no root to trust.");
            return;
        }

        using X509Store store = new(StoreName.Root, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadWrite);

        if (store.Certificates.Contains(root))
        {
            Console.WriteLine($"Root already trusted: {root.Subject}");
            return;
        }

        store.Add(root);
        Console.WriteLine($"Trusted root added to the current user's store: {root.Subject}");
    }
}
