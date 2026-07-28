using System.Security.Cryptography.X509Certificates;

namespace SignUniversal.Cli;

/// <summary>
/// An in-memory <see cref="IRemoteSigner"/> used by <c>self-test</c> to exercise the
/// remote-key pipeline without any cloud dependency.
/// </summary>
/// <remarks>
/// The exposed <see cref="Certificate"/> is deliberately public-only: the private
/// key is held separately and reached solely through
/// <see cref="SignHash(byte[], HashAlgorithmName, RSASignaturePadding)"/>, so a
/// passing self-test proves signing genuinely flows through the remote seam.
/// </remarks>
internal sealed class EphemeralRemoteSigner : IRemoteSigner, IDisposable
{
    private readonly RSA _privateKey;

    public EphemeralRemoteSigner()
    {
        _privateKey = RSA.Create(2048);

        CertificateRequest request = new(
            "CN=SignUniversal Self-Test",
            _privateKey,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        using X509Certificate2 full = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddYears(1));

        // Public-only copy: the private key lives only behind SignHash.
        Certificate = new X509Certificate2(full.Export(X509ContentType.Cert));
    }

    public X509Certificate2 Certificate { get; }

    public byte[] SignHash(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding) =>
        _privateKey.SignHash(hash, hashAlgorithm, padding);

    public void Dispose()
    {
        _privateKey.Dispose();
        Certificate.Dispose();
        GC.SuppressFinalize(this);
    }
}
