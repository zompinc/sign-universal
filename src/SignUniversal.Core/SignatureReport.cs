namespace SignUniversal.Core;

/// <summary>What a file's signature says about itself.</summary>
/// <param name="Format">The format that was inspected.</param>
/// <param name="IsSigned">Whether the file carries a signature at all.</param>
/// <param name="Signer">The signing certificate's subject, when one is embedded.</param>
/// <param name="EmbeddedCertificates">How many certificates the signature carries.</param>
/// <param name="SignatureValid">Whether the signature itself is intact.</param>
/// <param name="CoversFile">Whether the signature covers the bytes currently on disk.</param>
/// <param name="Timestamp">When a timestamp authority countersigned it, if one did.</param>
/// <remarks>
/// <see cref="CoversFile"/> is the interesting one: a signature can be perfectly intact
/// and describe a file that has since changed.
/// </remarks>
public sealed record SignatureReport(
    string Format,
    bool IsSigned,
    string? Signer,
    int EmbeddedCertificates,
    bool SignatureValid,
    bool CoversFile,
    DateTimeOffset? Timestamp)
{
    /// <summary>Creates a report for a file that carries no signature.</summary>
    /// <param name="format">The format that was inspected.</param>
    /// <returns>The report.</returns>
    public static SignatureReport WithoutSignature(string format) =>
        new(
            format,
            IsSigned: false,
            Signer: null,
            EmbeddedCertificates: 0,
            SignatureValid: false,
            CoversFile: false,
            Timestamp: null);
}
