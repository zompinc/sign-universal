using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SignUniversal.Core.Signing;

namespace SignUniversal.Core.Tests;

/// <summary>
/// Test double for <see cref="IRemoteSigner"/>: a real RSA key stands in for the
/// remote backend, but <see cref="Certificate"/> is public-only, so a passing test
/// proves signing genuinely flows through <see cref="SignHash"/>.
/// </summary>
internal sealed class LocalKeyRemoteSigner : IRemoteSigner, IDisposable
{
    private readonly RSA _privateKey;

    public LocalKeyRemoteSigner()
    {
        _privateKey = RSA.Create(2048);

        CertificateRequest request = new(
            "CN=SignUniversal Test",
            _privateKey,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        using X509Certificate2 full = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddYears(1));

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
