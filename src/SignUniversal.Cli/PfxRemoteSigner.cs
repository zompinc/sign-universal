using System.Security.Cryptography.X509Certificates;

namespace SignUniversal.Cli;

/// <summary>
/// An <see cref="IRemoteSigner"/> backed by a local PKCS#12 (.pfx) file.
/// </summary>
/// <remarks>
/// A local key is obviously not a remote one - this backend exists so the signing
/// pipeline is usable and testable before the Azure milestone lands. It still routes
/// every private-key operation through
/// <see cref="SignHash(byte[], HashAlgorithmName, RSASignaturePadding)"/> and exposes
/// a public-only <see cref="Certificate"/>, so nothing downstream can tell the
/// difference between this and a key that lives in an HSM.
/// </remarks>
internal sealed class PfxRemoteSigner : IRemoteSigner, IDisposable
{
    private readonly X509Certificate2 _pkcs12;
    private readonly RSA _privateKey;

    public PfxRemoteSigner(string path, string? password)
    {
        // Ephemeral keys never touch the on-disk key store; macOS does not support them.
        X509KeyStorageFlags flags = OperatingSystem.IsMacOS()
            ? X509KeyStorageFlags.DefaultKeySet
            : X509KeyStorageFlags.EphemeralKeySet;

        _pkcs12 = new X509Certificate2(path, password, flags);
        _privateKey = _pkcs12.GetRSAPrivateKey()
            ?? throw new InvalidOperationException(
                $"'{path}' does not contain an RSA private key (only RSA signing is supported today).");

        Certificate = new X509Certificate2(_pkcs12.Export(X509ContentType.Cert));
    }

    public X509Certificate2 Certificate { get; }

    public byte[] SignHash(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding) =>
        _privateKey.SignHash(hash, hashAlgorithm, padding);

    public void Dispose()
    {
        _privateKey.Dispose();
        _pkcs12.Dispose();
        Certificate.Dispose();
    }
}
