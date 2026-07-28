using Azure.Security.KeyVault.Keys.Cryptography;
using SignUniversal.Core.Signing.Azure;

namespace SignUniversal.Core.Tests;

/// <summary>
/// The part of the Key Vault backend that can be checked without a vault: the mapping
/// from .NET's hash algorithm and padding onto Key Vault's algorithm names.
/// </summary>
/// <remarks>
/// Getting this wrong produces a signature the vault computes happily and no verifier
/// accepts - PS256 where RS256 was meant is a valid signature over the wrong scheme.
/// </remarks>
public sealed class KeyVaultSignerTests
{
    [Test]
    [Arguments("SHA256", "RS256")]
    [Arguments("SHA384", "RS384")]
    [Arguments("SHA512", "RS512")]
    public void MapAlgorithm_Pkcs1_UsesTheRsaAlgorithms(string hash, string expected)
    {
        SignatureAlgorithm algorithm = KeyVaultRemoteSigner.MapAlgorithm(
            new HashAlgorithmName(hash), RSASignaturePadding.Pkcs1);

        algorithm.ToString().Should().Be(expected);
    }

    [Test]
    [Arguments("SHA256", "PS256")]
    [Arguments("SHA384", "PS384")]
    [Arguments("SHA512", "PS512")]
    public void MapAlgorithm_Pss_UsesTheProbabilisticAlgorithms(string hash, string expected)
    {
        SignatureAlgorithm algorithm = KeyVaultRemoteSigner.MapAlgorithm(
            new HashAlgorithmName(hash), RSASignaturePadding.Pss);

        algorithm.ToString().Should().Be(expected);
    }

    [Test]
    public void MapAlgorithm_RejectsAlgorithmsKeyVaultCannotSignWith()
    {
        Action map = () => KeyVaultRemoteSigner.MapAlgorithm(HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);

        map.Should().Throw<NotSupportedException>().WithMessage("*SHA1*");
    }
}
