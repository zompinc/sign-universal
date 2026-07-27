using System.Diagnostics;

namespace SignUniversal.Core.Tests;

/// <summary>
/// Verifies a signed file with Windows <c>signtool</c>. This is the correctness gate
/// for real Authenticode output once the PE and MSI paths land: every signature the
/// engine produces must be accepted by <c>signtool verify /pa</c>, with a
/// jsign-signed file as the byte-level reference.
/// </summary>
internal static class SigntoolHarness
{
    /// <summary>Gets a value indicating whether signtool-based verification can run here.</summary>
    public static bool IsAvailable => OperatingSystem.IsWindows();

    /// <summary>Runs <c>signtool verify /pa /v</c> against a file.</summary>
    /// <param name="filePath">The signed file to verify.</param>
    /// <returns>Whether verification succeeded, and the tool output.</returns>
    public static (bool Ok, string Output) Verify(string filePath)
    {
        if (!IsAvailable)
        {
            return (false, "signtool verification is only available on Windows.");
        }

        // TODO(pe-milestone): resolve signtool.exe from the installed Windows SDK
        // rather than relying on PATH.
        ProcessStartInfo startInfo = new("signtool", $"verify /pa /v \"{filePath}\"")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };

        using Process process = Process.Start(startInfo)!;
        string output = process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd();
        process.WaitForExit();
        return (process.ExitCode == 0, output);
    }
}
