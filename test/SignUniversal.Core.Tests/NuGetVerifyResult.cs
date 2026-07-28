namespace SignUniversal.Core.Tests;

/// <summary>The outcome of a <c>dotnet nuget verify</c> run.</summary>
/// <param name="ExitCode">The process exit code.</param>
/// <param name="Output">Everything the tool wrote to stdout and stderr.</param>
internal sealed record NuGetVerifyResult(int ExitCode, string Output)
{
    /// <summary>Gets a value indicating whether NuGet fully verified the package.</summary>
    public bool Succeeded => ExitCode == 0;

    /// <summary>Gets a value indicating whether NuGet found and parsed an author signature.</summary>
    public bool FoundAuthorSignature => Contains("Signature type: Author");

    /// <summary>
    /// Gets a value indicating whether the signature itself is intact - that is, NuGet
    /// raised no complaint about the signature or package contents, only about trust.
    /// </summary>
    /// <remarks>
    /// A self-signed test certificate can never chain to NuGet's root bundle, so the
    /// untrusted-root verdict (NU3018/NU3042) is the best outcome available and the one
    /// that proves the format is right. Integrity failures (NU3008) and invalid
    /// signatures (NU3011/NU3012) are genuine defects and are excluded here.
    /// </remarks>
    public bool RejectedOnlyForUntrustedRoot =>
        FoundAuthorSignature &&
        !Contains("NU3008") &&
        !Contains("NU3011") &&
        !Contains("NU3012") &&
        (Contains("NU3018") || Contains("NU3042"));

    /// <summary>Gets a value indicating whether NuGet reported tampering or an invalid signature.</summary>
    public bool ReportedIntegrityFailure =>
        Contains("NU3008") || Contains("NU3011") || Contains("NU3012");

    private bool Contains(string value) => Output.Contains(value, StringComparison.OrdinalIgnoreCase);
}
