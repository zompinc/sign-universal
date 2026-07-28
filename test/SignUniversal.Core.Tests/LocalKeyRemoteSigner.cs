using System.Security.Cryptography.X509Certificates;
using SignUniversal.Signing;

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

        // A realistic code-signing certificate. NuGet requires the code-signing EKU, and
        // it prefers the subject key identifier as the signer identifier when present -
        // so without these the tests would exercise a path production never takes.
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, critical: true));
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));
        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.3", "Code Signing")], critical: true));
        request.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));

        using X509Certificate2 full = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddYears(1));

        Certificate = new X509Certificate2(full.Export(X509ContentType.Cert));
    }

    public X509Certificate2 Certificate { get; }

    /// <summary>Gets the number of times the private key was reached through the remote seam.</summary>
    public int SignHashCallCount { get; private set; }

    public byte[] SignHash(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
    {
        SignHashCallCount++;
        return _privateKey.SignHash(hash, hashAlgorithm, padding);
    }

    public void Dispose()
    {
        _privateKey.Dispose();
        Certificate.Dispose();
        GC.SuppressFinalize(this);
    }
}
