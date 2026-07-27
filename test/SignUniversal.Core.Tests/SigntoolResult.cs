using System.Text.RegularExpressions;

namespace SignUniversal.Core.Tests;

/// <summary>The outcome of a <c>signtool verify</c> run.</summary>
/// <param name="ExitCode">The process exit code.</param>
/// <param name="Output">Everything the tool wrote to stdout and stderr.</param>
internal sealed partial record SigntoolResult(int ExitCode, string Output)
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
        (Contains("0x800B0109") || Contains("terminated in a root"));

    /// <summary>
    /// Gets the output with every run of whitespace collapsed to a single space.
    /// </summary>
    /// <remarks>
    /// signtool wraps its diagnostics across lines at unpredictable points, so matching
    /// against the raw text silently misses messages that are plainly there.
    /// </remarks>
    private string Flattened => Whitespace().Replace(Output, " ");

    private bool Contains(string value) => Flattened.Contains(value, StringComparison.OrdinalIgnoreCase);

    [GeneratedRegex(@"\s+")]
    private static partial Regex Whitespace();
}
