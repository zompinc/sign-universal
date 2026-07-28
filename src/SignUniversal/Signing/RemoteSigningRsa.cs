namespace SignUniversal.Signing;

/// <summary>
/// An <see cref="RSA"/> whose signing operation is delegated to an
/// <see cref="IRemoteSigner"/>, while all public-key operations (size, public
/// parameters, hashing, verification) are served locally from the certificate's
/// public key.
/// </summary>
/// <remarks>
/// This is the crux of the whole design. Attach an instance to a public-only
/// certificate via <c>certificate.CopyWithPrivateKey(remoteRsa)</c> and hand that
/// certificate to <see cref="System.Security.Cryptography.Pkcs.CmsSigner"/>: the
/// managed PKCS#7 pipeline will hash the content, then call
/// <see cref="SignHash(byte[], HashAlgorithmName, RSASignaturePadding)"/>, which
/// forwards the digest to the remote backend. No private key material is ever
/// present in process - <see cref="ExportParameters"/> deliberately refuses to
/// return private parameters.
/// </remarks>
public sealed class RemoteSigningRsa : RSA
{
    private readonly IRemoteSigner _signer;
    private readonly RSA _publicKey;

    /// <summary>Initializes a new instance backed by the given remote signer.</summary>
    /// <param name="signer">The backend that performs the actual private-key signing.</param>
    public RemoteSigningRsa(IRemoteSigner signer)
    {
        ArgumentNullException.ThrowIfNull(signer);

        _signer = signer;
        _publicKey = signer.Certificate.GetRSAPublicKey()
            ?? throw new InvalidOperationException("The signing certificate does not contain an RSA public key.");
        KeySizeValue = _publicKey.KeySize;
    }

    /// <inheritdoc />
    public override RSAParameters ExportParameters(bool includePrivateParameters)
    {
        if (includePrivateParameters)
        {
            throw new CryptographicException(
                "The private key is held remotely and cannot be exported.");
        }

        return _publicKey.ExportParameters(includePrivateParameters: false);
    }

    /// <inheritdoc />
    public override void ImportParameters(RSAParameters parameters) =>
        throw new NotSupportedException("Importing key parameters is not supported for a remote key.");

    /// <inheritdoc />
    public override byte[] SignHash(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
    {
        ArgumentNullException.ThrowIfNull(hash);
        ArgumentNullException.ThrowIfNull(padding);

        return _signer.SignHash(hash, hashAlgorithm, padding);
    }

    /// <inheritdoc />
    public override bool VerifyHash(
        byte[] hash,
        byte[] signature,
        HashAlgorithmName hashAlgorithm,
        RSASignaturePadding padding) =>
        _publicKey.VerifyHash(hash, signature, hashAlgorithm, padding);

    /// <inheritdoc />
    protected override byte[] HashData(byte[] data, int offset, int count, HashAlgorithmName hashAlgorithm)
    {
        using IncrementalHash hash = IncrementalHash.CreateHash(hashAlgorithm);
        hash.AppendData(data, offset, count);
        return hash.GetHashAndReset();
    }

    /// <inheritdoc />
    protected override byte[] HashData(Stream data, HashAlgorithmName hashAlgorithm)
    {
        using IncrementalHash hash = IncrementalHash.CreateHash(hashAlgorithm);
        byte[] buffer = new byte[8192];
        int read;
        while ((read = data.Read(buffer, 0, buffer.Length)) > 0)
        {
            hash.AppendData(buffer, 0, read);
        }

        return hash.GetHashAndReset();
    }

    /// <inheritdoc />
    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _publicKey.Dispose();
        }

        base.Dispose(disposing);
    }
}
