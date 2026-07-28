using System.Security.Cryptography.Pkcs;
using NuGet.Common;
using NuGet.Packaging.Signing;

namespace SignUniversal.Core.Packaging;

/// <summary>
/// NuGet's signing pipeline, with the private-key operation redirected to an
/// <see cref="IRemoteSigner"/>.
/// </summary>
/// <remarks>
/// <para>
/// NuGet's own <c>X509SignatureProvider</c> signs with the private key attached to the
/// certificate, which a key in Trusted Signing or Key Vault cannot supply. This is a
/// drop-in replacement: everything about the signature - the signer identifier, the
/// signed attributes, the certificate chain, the digest algorithm - still comes from
/// <see cref="SigningUtility"/>, so the output stays whatever NuGet says is correct.
/// Only the key differs.
/// </para>
/// <para>
/// The interesting line is <see cref="CmsSigner.PrivateKey"/>. Assigning the delegating
/// RSA is the same trick the Authenticode path uses: it makes
/// <see cref="SignedCms.ComputeSignature(CmsSigner)"/> call <c>SignHash</c> instead of
/// reaching for private material the process does not have.
/// </para>
/// </remarks>
internal sealed class RemoteKeySignatureProvider : ISignatureProvider
{
    private readonly IRemoteSigner _signer;
    private readonly ITimestampProvider? _timestampProvider;

    /// <summary>Initializes a new instance.</summary>
    /// <param name="signer">The backend holding the private key.</param>
    /// <param name="timestampProvider">The timestamp authority, or <see langword="null"/> to skip timestamping.</param>
    public RemoteKeySignatureProvider(IRemoteSigner signer, ITimestampProvider? timestampProvider)
    {
        ArgumentNullException.ThrowIfNull(signer);

        _signer = signer;
        _timestampProvider = timestampProvider;
    }

    /// <inheritdoc />
    public async Task<PrimarySignature> CreatePrimarySignatureAsync(
        SignPackageRequest request,
        SignatureContent signatureContent,
        ILogger logger,
        CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(signatureContent);

        CmsSigner cmsSigner = SigningUtility.CreateCmsSigner(request, logger);

        using (RemoteSigningRsa remoteRsa = new(_signer))
        {
            cmsSigner.PrivateKey = remoteRsa;

            SignedCms cms = new(new ContentInfo(signatureContent.GetBytes()));
            cms.ComputeSignature(cmsSigner);

            PrimarySignature signature = PrimarySignature.Load(cms);

            if (_timestampProvider is null)
            {
                return signature;
            }

            // The timestamp is taken over the signature value, hashed - not over the
            // signature bytes themselves.
            byte[] hashedMessage = request.TimestampHashAlgorithm.ComputeHash(signature.GetSignatureValue());
            TimestampRequest timestampRequest = new(
                SigningSpecifications.V1,
                hashedMessage,
                request.TimestampHashAlgorithm,
                SignaturePlacement.PrimarySignature);

            return await _timestampProvider
                .TimestampSignatureAsync(signature, timestampRequest, logger, token)
                .ConfigureAwait(false);
        }
    }

    /// <inheritdoc />
    public Task<PrimarySignature> CreateRepositoryCountersignatureAsync(
        RepositorySignPackageRequest request,
        PrimarySignature primarySignature,
        ILogger logger,
        CancellationToken token) =>
        throw new NotSupportedException(
            "Repository countersignatures are a nuget.org-side operation; this tool produces author signatures.");
}
