using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using SignUniversal.Core.Authenticode;

namespace SignUniversal.Cli;

internal static class Program
{
    internal static int Main(string[] args)
    {
        string command = args.Length > 0 ? args[0] : "--help";

        return command switch
        {
            "--version" => PrintVersion(),
            "self-test" => RunSelfTest(),
            "sign" => NotYetImplemented(),
            _ => PrintHelp(),
        };
    }

    private static int PrintHelp()
    {
        Console.WriteLine(
            """
            sign-universal — cross-platform Authenticode signing (PE + MSI),
            keys in Azure Key Vault / Trusted Signing.

            Usage:
              sign-universal self-test    Verify the remote-key -> SignedCms pipeline on this OS.
              sign-universal sign ...     Sign a file (not implemented yet).
              sign-universal --version    Show version.
              sign-universal --help       Show this help.
            """);
        return 0;
    }

    private static int PrintVersion()
    {
        string version = typeof(Program).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
            ?? "0.0.0";
        Console.WriteLine(version);
        return 0;
    }

    private static int NotYetImplemented()
    {
        Console.WriteLine(
            "The 'sign' command is not implemented yet. See the README roadmap (PE, then MSI).");
        return 2;
    }

    private static int RunSelfTest()
    {
        Console.WriteLine($"Runtime: {RuntimeInformation.FrameworkDescription}");
        Console.WriteLine($"OS:      {RuntimeInformation.OSDescription.Trim()}");

        using EphemeralRemoteSigner signer = new();

        // Stand in for an Authenticode digest we would normally compute from a PE/MSI file.
        byte[] fakeFileDigest = SHA256.HashData("pretend this is a PE file"u8);

        byte[] signedData = AuthenticodeSignedDataBuilder.Build(signer, fakeFileDigest, HashAlgorithmName.SHA256);
        bool ok = AuthenticodeSignedDataBuilder.VerifySignatureOnly(signedData);

        Console.WriteLine($"SignedData size: {signedData.Length} bytes");
        Console.WriteLine(ok
            ? "PASS: remote-key signing produced a valid PKCS#7 SignedData; the private key never left the signer."
            : "FAIL: signature did not verify.");

        return ok ? 0 : 1;
    }
}
