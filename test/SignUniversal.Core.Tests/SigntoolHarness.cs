using System.Diagnostics;
using System.Runtime.InteropServices;

namespace SignUniversal.Core.Tests;

/// <summary>
/// Verifies a signed file with Windows <c>signtool</c>. This is the correctness gate
/// for real Authenticode output: every signature the engine produces must be accepted
/// by <c>signtool verify /pa</c>, with a jsign-signed file as the byte-level reference.
/// </summary>
internal static class SigntoolHarness
{
    private static readonly Lazy<string?> ToolPath = new(Resolve);

    /// <summary>Gets a value indicating whether signtool-based verification can run here.</summary>
    public static bool IsAvailable => ToolPath.Value is not null;

    /// <summary>Gets the reason verification cannot run, when <see cref="IsAvailable"/> is false.</summary>
    public static string UnavailableReason => OperatingSystem.IsWindows()
        ? "signtool.exe was not found in the installed Windows SDKs or on PATH."
        : "signtool verification is only available on Windows.";

    /// <summary>Runs <c>signtool verify /pa /v</c> against a file.</summary>
    /// <param name="filePath">The signed file to verify.</param>
    /// <returns>The tool's exit code and output.</returns>
    /// <exception cref="InvalidOperationException">signtool is not available on this machine.</exception>
    public static SigntoolResult Verify(string filePath)
    {
        string tool = ToolPath.Value
            ?? throw new InvalidOperationException(UnavailableReason);

        ProcessStartInfo startInfo = new(tool)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        startInfo.ArgumentList.Add("verify");
        startInfo.ArgumentList.Add("/pa");
        startInfo.ArgumentList.Add("/v");
        startInfo.ArgumentList.Add(filePath);

        using Process process = Process.Start(startInfo)!;
        string output = process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd();
        process.WaitForExit();
        return new SigntoolResult(process.ExitCode, output);
    }

    /// <summary>
    /// Locates signtool.exe in the installed Windows SDKs, preferring the newest, and
    /// falling back to PATH.
    /// </summary>
    private static string? Resolve()
    {
        if (!OperatingSystem.IsWindows())
        {
            return null;
        }

        string architecture = RuntimeInformation.ProcessArchitecture switch
        {
            Architecture.Arm64 => "arm64",
            Architecture.X86 => "x86",
            _ => "x64",
        };

        string[] roots =
        [
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
        ];

        string? best = null;
        Version? bestVersion = null;

        foreach (string root in roots.Where(root => !string.IsNullOrEmpty(root)))
        {
            string binRoot = Path.Combine(root, "Windows Kits", "10", "bin");
            if (!Directory.Exists(binRoot))
            {
                continue;
            }

            foreach (string versionDirectory in Directory.EnumerateDirectories(binRoot))
            {
                string candidate = Path.Combine(versionDirectory, architecture, "signtool.exe");
                if (!File.Exists(candidate))
                {
                    continue;
                }

                // Directory names are SDK versions such as 10.0.22621.0; unparseable ones
                // (older layouts put signtool directly under bin\x64) sort lowest.
                _ = Version.TryParse(Path.GetFileName(versionDirectory), out Version? version);
                if (best is null || (version is not null && (bestVersion is null || version > bestVersion)))
                {
                    best = candidate;
                    bestVersion = version;
                }
            }

            string flat = Path.Combine(binRoot, architecture, "signtool.exe");
            if (best is null && File.Exists(flat))
            {
                best = flat;
            }
        }

        return best ?? FindOnPath();
    }

    private static string? FindOnPath()
    {
        string? path = Environment.GetEnvironmentVariable("PATH");
        if (path is null)
        {
            return null;
        }

        return path.Split(Path.PathSeparator)
            .Where(directory => !string.IsNullOrWhiteSpace(directory))
            .Select(directory => Path.Combine(directory, "signtool.exe"))
            .FirstOrDefault(File.Exists);
    }
}
