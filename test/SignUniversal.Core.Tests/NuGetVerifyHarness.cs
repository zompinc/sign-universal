using System.Diagnostics;

namespace SignUniversal.Core.Tests;

/// <summary>
/// Verifies a signed package with <c>dotnet nuget verify</c> - NuGet's own client
/// deciding whether our signature is acceptable.
/// </summary>
/// <remarks>
/// The counterpart to <see cref="SigntoolHarness"/> for packages, with one large
/// advantage: NuGet's verifier is cross-platform, so unlike the Authenticode gate this
/// one runs on the same Linux machine that produced the signature.
/// </remarks>
internal static class NuGetVerifyHarness
{
    /// <summary>Runs <c>dotnet nuget verify --all</c> against a package.</summary>
    /// <param name="packagePath">The signed package.</param>
    /// <returns>The exit code and output.</returns>
    public static NuGetVerifyResult Verify(string packagePath)
    {
        ProcessStartInfo startInfo = new("dotnet")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        startInfo.ArgumentList.Add("nuget");
        startInfo.ArgumentList.Add("verify");
        startInfo.ArgumentList.Add("--all");
        startInfo.ArgumentList.Add(packagePath);

        using Process process = Process.Start(startInfo)!;
        string output = process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd();
        process.WaitForExit();
        return new NuGetVerifyResult(process.ExitCode, output);
    }
}
