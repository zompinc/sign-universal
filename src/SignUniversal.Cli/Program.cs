using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using SignUniversal.Core.Authenticode;
using SignUniversal.Core.Signing;

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
            "sign" => RunSign(args),
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
              sign-universal sign <file>  Sign a Windows PE image (.exe/.dll) in place.
              sign-universal --version    Show version.
              sign-universal --help       Show this help.

            sign options:
              --pfx <path>       PKCS#12 file holding the signing certificate and key.
              --password <pw>    Password for the PKCS#12 file.
              --self-signed      Sign with a throwaway self-signed certificate (smoke tests only).
              --hash <algorithm> Digest algorithm: sha256 (default), sha384, or sha512.

            Azure Key Vault and Trusted Signing backends land in the Azure milestone;
            MSI support lands in the MSI milestone.
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

    private static int RunSign(string[] args)
    {
        string? file = null;
        string? pfxPath = null;
        string? password = null;
        string hashName = "sha256";
        bool selfSigned = false;

        for (int i = 1; i < args.Length; i++)
        {
            string argument = args[i];
            switch (argument)
            {
                case "--pfx":
                    if (!TryTakeValue(args, ref i, out pfxPath)) return UsageError($"'{argument}' needs a value.");
                    break;
                case "--password":
                    if (!TryTakeValue(args, ref i, out password)) return UsageError($"'{argument}' needs a value.");
                    break;
                case "--hash":
                    if (!TryTakeValue(args, ref i, out string? hash)) return UsageError($"'{argument}' needs a value.");
                    hashName = hash;
                    break;
                case "--self-signed":
                    selfSigned = true;
                    break;
                default:
                    if (argument.StartsWith('-')) return UsageError($"Unknown option '{argument}'.");
                    if (file is not null) return UsageError("Specify exactly one file to sign.");
                    file = argument;
                    break;
            }
        }

        if (file is null) return UsageError("Specify the file to sign.");
        if (!File.Exists(file)) return UsageError($"File not found: {file}");
        if (selfSigned == (pfxPath is not null)) return UsageError("Specify exactly one of --pfx or --self-signed.");

        if (string.Equals(Path.GetExtension(file), ".msi", StringComparison.OrdinalIgnoreCase))
        {
            return UsageError("MSI signing is not implemented yet; only PE images (.exe/.dll) are supported.");
        }

        HashAlgorithmName hashAlgorithm;
        switch (hashName.ToLowerInvariant())
        {
            case "sha256": hashAlgorithm = HashAlgorithmName.SHA256; break;
            case "sha384": hashAlgorithm = HashAlgorithmName.SHA384; break;
            case "sha512": hashAlgorithm = HashAlgorithmName.SHA512; break;
            default: return UsageError($"Unsupported hash algorithm '{hashName}'; use sha256, sha384, or sha512.");
        }

        if (selfSigned)
        {
            Console.Error.WriteLine(
                "WARNING: --self-signed uses a throwaway certificate that no machine trusts. " +
                "It exercises the pipeline; it does not produce a distributable signature.");
        }

        try
        {
            // Loading the key can fail too (wrong password, no RSA key), so it happens
            // inside the same guard as the signing itself.
            using EphemeralRemoteSigner? ephemeral = selfSigned ? new EphemeralRemoteSigner() : null;
            using PfxRemoteSigner? pfxSigner = pfxPath is null ? null : new PfxRemoteSigner(pfxPath, password);
            IRemoteSigner signer = (IRemoteSigner?)ephemeral ?? pfxSigner!;

            byte[] digest = PeSigner.SignFile(file, signer, hashAlgorithm);
            Console.WriteLine($"Signed {file}");
            Console.WriteLine($"  digest ({hashAlgorithm.Name}): {Convert.ToHexString(digest)}");
            Console.WriteLine($"  certificate:      {signer.Certificate.Subject}");
            return 0;
        }
        catch (Exception ex) when (ex is InvalidDataException or NotSupportedException or InvalidOperationException
            or IOException or UnauthorizedAccessException or CryptographicException)
        {
            Console.Error.WriteLine($"error: {ex.Message}");
            return 1;
        }
    }

    private static bool TryTakeValue(string[] args, ref int index, out string value)
    {
        if (index + 1 >= args.Length)
        {
            value = string.Empty;
            return false;
        }

        value = args[++index];
        return true;
    }

    private static int UsageError(string message)
    {
        Console.Error.WriteLine($"error: {message}");
        Console.Error.WriteLine("Run 'sign-universal --help' for usage.");
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
