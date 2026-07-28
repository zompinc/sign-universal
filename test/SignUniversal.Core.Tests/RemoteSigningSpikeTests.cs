namespace SignUniversal.Core.Tests;

/// <summary>
/// Locks in the de-risked core: an Authenticode PKCS#7 SignedData can be produced
/// with the private key held remotely (never exported), and it verifies.
/// </summary>
public sealed class RemoteSigningSpikeTests
{
    [Test]
    public void RemoteKeySigning_ProducesVerifiableSignedData()
    {
        using LocalKeyRemoteSigner signer = new();
        byte[] digest = SHA256.HashData("pretend this is a PE file"u8);

        byte[] signedData = AuthenticodeSignedDataBuilder.Build(signer, digest, HashAlgorithmName.SHA256);

        signedData.Should().NotBeEmpty();
        AuthenticodeSignedDataBuilder.VerifySignatureOnly(signedData).Should().BeTrue();
    }

    [Test]
    public void ExportingPrivateParameters_IsRefused()
    {
        // The remote key must never yield private material — the security invariant.
        using LocalKeyRemoteSigner signer = new();
        using SignUniversal.Core.Signing.RemoteSigningRsa rsa = new(signer);

        Action exportPrivate = () => rsa.ExportParameters(includePrivateParameters: true);

        exportPrivate.Should().Throw<CryptographicException>();
    }
}
