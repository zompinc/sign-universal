using System.Reflection;
using System.Runtime.InteropServices;
using Azure;
using Azure.Identity;
using NuGet.Packaging.Signing;
using SignUniversal.Authenticode;
using SignUniversal.Msi;
using SignUniversal.Packaging;
using SignUniversal.Signing.Azure;

namespace SignUniversal.Cli;

internal static class Program
{
    internal static async Task<int> Main(string[] args)
    {
        string command = args.Length > 0 ? args[0] : "--help";

        return command switch
        {
            "--version" => PrintVersion(),
            "self-test" => RunSelfTest(),
            "sign" => await RunSign(args).ConfigureAwait(false),
            "verify" => await VerifyCommand.Run(args).ConfigureAwait(false),
            _ => PrintHelp(),
        };
    }

    private static int PrintHelp()
    {
        Console.WriteLine(
            """
            sign-universal - cross-platform code signing: NuGet packages and Windows PE
            binaries, with the key held in Azure Trusted Signing.

            Usage:
              sign-universal self-test    Verify the remote-key -> SignedCms pipeline on this OS.
              sign-universal sign <files>  Sign PE images (.exe/.dll), MSI packages
                                           (.msi), and NuGet packages (.nupkg). Globs
                                           work: one signing session covers every file.
              sign-universal verify <files> Report what a signed file carries.
              sign-universal --version    Show version.
              sign-universal --help       Show this help.

            sign key sources (pick one):
              --pfx <path>                          A local PKCS#12 file. Its password
                                                    comes from SIGNUNIVERSAL_PFX_PASSWORD,
                                                    or --password-stdin, or --password
                                                    (which is visible in `ps` and shell
                                                    history - prefer the others).
              --key-vault-url <uri>                 Azure Key Vault. Also needs
                --key-vault-certificate <name>      --key-vault-certificate.
              --trusted-signing-endpoint <url>      Azure Trusted Signing. Also needs
                --trusted-signing-account <name>    --trusted-signing-account and
                --trusted-signing-certificate-profile <name>.
                Credentials come from AZURE_TENANT_ID / AZURE_CLIENT_ID /
                AZURE_CLIENT_SECRET, as DefaultAzureCredential reads them.
              --self-signed                         Throwaway certificate, smoke tests only.

            sign options:
              --hash <algorithm>  Digest algorithm: sha256 (default), sha384, or sha512.
              --export-certificate <path>
                                  Write the signing certificate out in DER form, for
                                  registering with a gallery that requires it.
              --timestamper <url> RFC 3161 authority. Defaults to
                                  http://timestamp.digicert.com. Microsoft's
                                  timestamp.acs.microsoft.com does not chain on a stock
                                  Linux agent - see the README.
              --no-timestamp      Skip timestamping. Trusted Signing certificates expire in
                                  days, and so will the signature.
              --trust-signing-root  Add the backend's root certificate to the current
                                  user's trust store. Needed on Linux agents, where
                                  signing otherwise fails with "Certificate chain
                                  validation failed" - see the README.

            Every format is timestamped by default.

            `verify` reports the signer, whether the signature covers the file, and the
            timestamp. It does not decide trust - use `signtool verify /pa` or
            `dotnet nuget verify` for that.
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

    /// <summary>Environment variable consulted when no password is passed on the command line.</summary>
    private const string PfxPasswordVariable = "SIGNUNIVERSAL_PFX_PASSWORD";

    private static async Task<int> RunSign(string[] args)
    {
        List<string> files = [];
        string? pfxPath = null;
        string? password = null;
        bool passwordFromStdin = false;
        string? endpoint = null;
        string? account = null;
        string? certificateProfile = null;
        string? keyVaultUrl = null;
        string? keyVaultCertificate = null;
        string? exportCertificatePath = null;
        string? timestamper = null;
        string hashName = "sha256";
        bool selfSigned = false;
        bool noTimestamp = false;
        bool trustSigningRoot = false;

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
                case "--password-stdin":
                    passwordFromStdin = true;
                    break;
                case "--trusted-signing-endpoint":
                    if (!TryTakeValue(args, ref i, out endpoint)) return UsageError($"'{argument}' needs a value.");
                    break;
                case "--trusted-signing-account":
                    if (!TryTakeValue(args, ref i, out account)) return UsageError($"'{argument}' needs a value.");
                    break;
                case "--trusted-signing-certificate-profile":
                    if (!TryTakeValue(args, ref i, out certificateProfile)) return UsageError($"'{argument}' needs a value.");
                    break;
                case "--key-vault-url":
                    if (!TryTakeValue(args, ref i, out keyVaultUrl)) return UsageError($"'{argument}' needs a value.");
                    break;
                case "--key-vault-certificate":
                    if (!TryTakeValue(args, ref i, out keyVaultCertificate)) return UsageError($"'{argument}' needs a value.");
                    break;
                case "--export-certificate":
                    if (!TryTakeValue(args, ref i, out exportCertificatePath)) return UsageError($"'{argument}' needs a value.");
                    break;
                case "--timestamper":
                    if (!TryTakeValue(args, ref i, out timestamper)) return UsageError($"'{argument}' needs a value.");
                    break;
                case "--hash":
                    if (!TryTakeValue(args, ref i, out string? hash)) return UsageError($"'{argument}' needs a value.");
                    hashName = hash;
                    break;
                case "--no-timestamp":
                    noTimestamp = true;
                    break;
                case "--trust-signing-root":
                    trustSigningRoot = true;
                    break;
                case "--self-signed":
                    selfSigned = true;
                    break;
                default:
                    if (argument.StartsWith('-')) return UsageError($"Unknown option '{argument}'.");
                    files.Add(argument);
                    break;
            }
        }

        if (files.Count == 0) return UsageError("Specify at least one file to sign.");

        foreach (string candidate in files.Where(candidate => !File.Exists(candidate)))
        {
            return UsageError($"File not found: {candidate}");
        }

        bool trustedSigning = endpoint is not null || account is not null || certificateProfile is not null;
        if (trustedSigning && (endpoint is null || account is null || certificateProfile is null))
        {
            return UsageError(
                "Trusted Signing needs all of --trusted-signing-endpoint, --trusted-signing-account, " +
                "and --trusted-signing-certificate-profile.");
        }

        if (passwordFromStdin)
        {
            if (password is not null)
            {
                return UsageError("Specify either --password or --password-stdin, not both.");
            }

            password = Console.In.ReadLine();
        }

        // A password on the command line is visible to anyone who can run `ps`, and lands
        // in shell history. The environment variable is the quiet default for CI.
        password ??= Environment.GetEnvironmentVariable(PfxPasswordVariable);

        bool keyVault = keyVaultUrl is not null || keyVaultCertificate is not null;
        if (keyVault && (keyVaultUrl is null || keyVaultCertificate is null))
        {
            return UsageError("Key Vault needs both --key-vault-url and --key-vault-certificate.");
        }

        int keySources = (selfSigned ? 1 : 0) + (pfxPath is not null ? 1 : 0)
            + (trustedSigning ? 1 : 0) + (keyVault ? 1 : 0);
        if (keySources != 1)
        {
            return UsageError(
                "Specify exactly one key source: --pfx, --key-vault-*, --trusted-signing-*, or --self-signed.");
        }

        HashAlgorithmName hashAlgorithm;
        switch (hashName.ToLowerInvariant())
        {
            case "sha256": hashAlgorithm = HashAlgorithmName.SHA256; break;
            case "sha384": hashAlgorithm = HashAlgorithmName.SHA384; break;
            case "sha512": hashAlgorithm = HashAlgorithmName.SHA512; break;
            default: return UsageError($"Unsupported hash algorithm '{hashName}'; use sha256, sha384, or sha512.");
        }

        bool anyPeImage = files.Any(candidate => !IsPackage(candidate) && !IsMsi(candidate));

        if (selfSigned)
        {
            Console.Error.WriteLine(
                "WARNING: --self-signed uses a throwaway certificate that no machine trusts. " +
                "It exercises the pipeline; it does not produce a distributable signature.");
        }

        try
        {
            IRemoteSigner signer;
            IDisposable owned;

            if (selfSigned)
            {
                EphemeralRemoteSigner ephemeral = new();
                signer = ephemeral;
                owned = ephemeral;
            }
            else if (pfxPath is not null)
            {
                PfxRemoteSigner pfxSigner = new(pfxPath, password);
                signer = pfxSigner;
                owned = pfxSigner;
            }
            else if (keyVault)
            {
                KeyVaultRemoteSigner vault = new(new Uri(keyVaultUrl!), keyVaultCertificate!);
                signer = vault;
                owned = vault;
            }
            else
            {
                TrustedSigningRemoteSigner trusted = new(new Uri(endpoint!), account!, certificateProfile!);
                signer = trusted;
                owned = trusted;
            }

            // One signing session covers every file. That matters for Trusted Signing,
            // where opening a session mints a certificate and costs a round trip.
            using (owned)
            {
                Console.WriteLine($"Certificate: {signer.Certificate.Subject}");

                if (exportCertificatePath is not null)
                {
                    ExportCertificate(signer, exportCertificatePath);
                }

                if (trustSigningRoot)
                {
                    SigningRootTrust.Install(signer);
                }

                if (anyPeImage && noTimestamp)
                {
                    WarnAboutUntimestampedPeSignatures(signer);
                }

                foreach (string target in files)
                {
                    if (IsPackage(target))
                    {
                        await SignPackage(target, signer, hashAlgorithm, timestamper, noTimestamp).ConfigureAwait(false);
                    }
                    else if (IsMsi(target))
                    {
                        Uri? timestampUrl = ResolveTimestampUrl(timestamper, noTimestamp);
                        byte[] digest = MsiSigner.SignFile(target, signer, hashAlgorithm, timestampUrl);
                        Console.WriteLine($"Signed {target}");
                        Console.WriteLine($"  digest ({hashAlgorithm.Name}): {Convert.ToHexString(digest)}");
                        Console.WriteLine($"  timestamp: {timestampUrl?.ToString() ?? "none"}");
                    }
                    else
                    {
                        Uri? timestampUrl = ResolveTimestampUrl(timestamper, noTimestamp);
                        byte[] digest = PeSigner.SignFile(target, signer, hashAlgorithm, timestampUrl);
                        Console.WriteLine($"Signed {target}");
                        Console.WriteLine($"  digest ({hashAlgorithm.Name}): {Convert.ToHexString(digest)}");
                        Console.WriteLine($"  timestamp: {timestampUrl?.ToString() ?? "none"}");
                    }
                }
            }

            return 0;
        }
        catch (Exception ex) when (ex is InvalidDataException or NotSupportedException or InvalidOperationException
            or IOException or UnauthorizedAccessException or CryptographicException or UriFormatException
            or SignatureException or TimestampException
            // Azure surfaces missing permissions, expired keys, and bad credentials this
            // way. They are ordinary misconfiguration, not defects worth a stack trace.
            or RequestFailedException or AuthenticationFailedException)
        {
            Console.Error.WriteLine($"error: {ex.Message}");
            return 1;
        }
    }

    private static async Task SignPackage(
        string file,
        IRemoteSigner signer,
        HashAlgorithmName hashAlgorithm,
        string? timestamper,
        bool noTimestamp)
    {
        Uri? timestampUrl = ResolveTimestampUrl(timestamper, noTimestamp);

        await NuGetPackageSigner.SignFileAsync(file, signer, hashAlgorithm, timestampUrl).ConfigureAwait(false);

        Console.WriteLine($"Signed {file}");
        Console.WriteLine($"  signature: author, {hashAlgorithm.Name}");
        Console.WriteLine($"  timestamp: {timestampUrl?.ToString() ?? "none"}");
    }

    /// <summary>
    /// Resolves the timestamp authority. Timestamping is the default because a signature
    /// that is not timestamped dies with its certificate - in days, for Trusted Signing.
    /// </summary>
    private static Uri? ResolveTimestampUrl(string? timestamper, bool noTimestamp) =>
        noTimestamp ? null : new Uri(timestamper ?? AuthenticodeTimestamp.DefaultTimestampUrl);

    private static void WarnAboutUntimestampedPeSignatures(IRemoteSigner signer)
    {
        TimeSpan remaining = signer.Certificate.NotAfter.ToUniversalTime() - DateTime.UtcNow;

        Console.Error.WriteLine(
            "WARNING: --no-timestamp means this signature stops validating when the signing " +
            $"certificate expires - {signer.Certificate.NotAfter:u}, about {remaining.TotalHours:F0} hours away.");
    }

    /// <summary>
    /// Writes the signing certificate out in DER form, which is the shape nuget.org wants
    /// when registering one.
    /// </summary>
    /// <remarks>
    /// A backend that mints short-lived certificates hands out a different one every couple
    /// of days, and a gallery that enforces registration needs whichever is current. Taking
    /// it from the process that just signed removes the step of digging it back out of the
    /// signed artifact afterwards, and removes the chance of exporting the wrong one.
    /// </remarks>
    private static void ExportCertificate(IRemoteSigner signer, string path)
    {
        File.WriteAllBytes(path, signer.Certificate.RawData);

        Console.WriteLine($"  certificate written to {path}");
        Console.WriteLine($"  valid until:      {signer.Certificate.NotAfter:u}");
    }

    private static bool IsMsi(string path) =>
        string.Equals(Path.GetExtension(path), ".msi", StringComparison.OrdinalIgnoreCase);

    private static bool IsPackage(string path)
    {
        // Symbol packages are ordinary packages as far as signing is concerned, and
        // publishing a signed .nupkg beside an unsigned .snupkg is a odd thing to ship.
        string extension = Path.GetExtension(path);
        return string.Equals(extension, ".nupkg", StringComparison.OrdinalIgnoreCase)
            || string.Equals(extension, ".snupkg", StringComparison.OrdinalIgnoreCase);
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
