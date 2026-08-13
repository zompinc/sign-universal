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
              --trusted-signing-metadata <path>     Those three from the JSON file that
                                                    vpk and dotnet sign already take:
                                                    Endpoint, CodeSigningAccountName,
                                                    CertificateProfileName. Also spelled
                                                    --azure-trusted-sign-file, as vpk does.
              --self-signed                         Throwaway certificate, smoke tests only.

            sign options:
              --base-directory <path>
                                  Resolve file patterns from this directory instead of
                                  the current one.
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
              --skip-signed       Leave any PE or MSI that already carries a signature
                                  alone, and sign the rest. Authenticode keeps one primary
                                  signature, so signing a vendor-signed assembly replaces
                                  theirs rather than joining it. This checks that a
                                  signature is present, not that it is valid or trusted.
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
        bool skipSigned = false;
        string? baseDirectory = null;
        string? metadataPath = null;

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
                // The second spelling is the one vpk uses for the same file, so a command
                // line can be moved across without editing it.
                case "--trusted-signing-metadata":
                case "--azure-trusted-sign-file":
                    if (!TryTakeValue(args, ref i, out metadataPath)) return UsageError($"'{argument}' needs a value.");
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
                case "--base-directory":
                    if (!TryTakeValue(args, ref i, out baseDirectory)) return UsageError($"'{argument}' needs a value.");
                    break;
                case "--trust-signing-root":
                    trustSigningRoot = true;
                    break;
                case "--skip-signed":
                    skipSigned = true;
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

        if (!FileArguments.TryResolve(files, baseDirectory, out List<string> resolved, out string? resolveError))
        {
            return UsageError(resolveError!);
        }

        files = resolved;

        if (metadataPath is not null)
        {
            if (endpoint is not null || account is not null || certificateProfile is not null)
            {
                return UsageError(
                    "Specify the Trusted Signing details either in the metadata file or as " +
                    "--trusted-signing-* options, not both.");
            }

            if (!TrustedSigningMetadata.TryLoad(metadataPath, out TrustedSigningMetadata? metadata, out string? metadataError))
            {
                return UsageError(metadataError!);
            }

            (endpoint, account, certificateProfile) = (metadata!.Endpoint, metadata.Account, metadata.CertificateProfile);
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

        if (selfSigned)
        {
            Console.Error.WriteLine(
                "WARNING: --self-signed uses a throwaway certificate that no machine trusts. " +
                "It exercises the pipeline; it does not produce a distributable signature.");
        }

        try
        {
            if (skipSigned)
            {
                (List<string> toSign, List<string> alreadySigned) = SigningTargets.PartitionBySignature(files);

                foreach (string skipped in alreadySigned)
                {
                    Console.WriteLine($"Skipped {skipped} (already signed)");
                }

                if (toSign.Count == 0)
                {
                    // Returning before the signer exists is the point, not a shortcut: opening
                    // a Trusted Signing session mints a certificate and costs a round trip, and
                    // a caller signing one file per invocation would otherwise pay for one on
                    // every vendor-signed assembly it hands over.
                    Console.WriteLine("Nothing to sign; every file already carries a signature.");
                    return 0;
                }

                files = toSign;
            }

            bool anyPeImage = files.Any(candidate =>
                !SigningTargets.IsPackage(candidate) && !SigningTargets.IsMsi(candidate));

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
                    if (SigningTargets.IsPackage(target))
                    {
                        await SignPackage(target, signer, hashAlgorithm, timestamper, noTimestamp).ConfigureAwait(false);
                    }
                    else if (SigningTargets.IsMsi(target))
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
        catch (Exception ex) when (IsMisconfiguration(Unwrap(ex)))
        {
            Console.Error.WriteLine($"error: {Describe(Unwrap(ex))}");
            return 1;
        }
    }

    /// <summary>
    /// Whether a failure is something the caller set up wrong, rather than a defect here.
    /// </summary>
    private static bool IsMisconfiguration(Exception ex) =>
        ex is InvalidDataException or NotSupportedException or InvalidOperationException
            or IOException or UnauthorizedAccessException or CryptographicException or UriFormatException
            or SignatureException or TimestampException
            // Azure surfaces missing permissions, expired keys, and bad credentials this
            // way. They are ordinary misconfiguration, not defects worth a stack trace.
            or RequestFailedException or AuthenticationFailedException;

    /// <summary>
    /// Digs out the failure worth reporting.
    /// </summary>
    /// <remarks>
    /// The Azure credential chain does its work asynchronously and is waited on, so a
    /// rejected credential arrives wrapped in an <see cref="AggregateException"/> - which
    /// matches nothing in the filter above, and so used to abort the process with a stack
    /// trace where a wrong AZURE_CLIENT_ID deserves one line.
    /// </remarks>
    private static Exception Unwrap(Exception ex) =>
        ex is AggregateException aggregate && aggregate.Flatten().InnerException is { } inner ? inner : ex;

    /// <summary>
    /// Describes a failure, following the inner exceptions.
    /// </summary>
    /// <remarks>
    /// Azure.Identity reports "ClientSecretCredential authentication failed" and leaves the
    /// part that says why - the AADSTS code - one layer down, so stopping at the outermost
    /// message tells the caller only that something went wrong.
    /// </remarks>
    private static string Describe(Exception ex)
    {
        List<string> messages = [];

        for (Exception? current = ex; current is not null; current = current.InnerException)
        {
            // MSAL writes several lines, the first being the diagnosis and the rest a
            // restatement of the exception type. One line each keeps the chain readable.
            string message = current.Message.Split('\n')[0].Trim().TrimEnd(':').Trim();
            if (message.Length > 0 && !messages.Contains(message, StringComparer.Ordinal))
            {
                messages.Add(message);
            }
        }

        return messages.Count > 0 ? string.Join(": ", messages) : ex.GetType().Name;
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
            $"certificate expires - {signer.Certificate.NotAfter.ToUniversalTime():u}, "
            + $"about {remaining.TotalHours:F0} hours away.");
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
        // NotAfter is local time and the "u" format appends Z without converting, so
        // without ToUniversalTime this reports the expiry off by the UTC offset.
        Console.WriteLine($"  valid until:      {signer.Certificate.NotAfter.ToUniversalTime():u}");
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
