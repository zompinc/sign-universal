namespace SignUniversal.Core.Tests;

/// <summary>The outcome of a <c>signtool verify</c> run.</summary>
/// <param name="ExitCode">The process exit code.</param>
/// <param name="Output">Everything the tool wrote to stdout and stderr.</param>
internal sealed record SigntoolResult(int ExitCode, string Output)
{
    /// <summary>Gets a value indicating whether signtool fully verified the file.</summary>
    public bool Succeeded => ExitCode == 0;

    /// <summary>Gets a value indicating whether signtool found and parsed a signature at all.</summary>
    /// <remarks>
    /// A malformed certificate table shows up here: signtool reports the file as unsigned
    /// rather than failing a later validation step.
    /// </remarks>
    public bool FoundSignature =>
        !Contains("No signature found") &&
        !Contains("is not signed") &&
        !Contains("0x800B0100");

    /// <summary>
    /// Gets a value indicating whether the only thing signtool objected to was an
    /// untrusted certificate chain — the expected verdict for a self-signed test key.
    /// </summary>
    public bool RejectedOnlyForUntrustedRoot =>
        FoundSignature &&
        (Contains("0x800B0109") || Contains("terminated in a root certificate which is not trusted"));

    private bool Contains(string value) => Output.Contains(value, StringComparison.OrdinalIgnoreCase);
}
