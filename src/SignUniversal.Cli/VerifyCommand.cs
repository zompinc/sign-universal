using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using SignUniversal.Core.Authenticode;
using SignUniversal.Core.Msi;

namespace SignUniversal.Cli;

/// <summary>
/// Reports what a signed file carries: who signed it, whether the signature covers the
/// bytes on disk, and whether it is timestamped.
/// </summary>
/// <remarks>
/// <para>
/// This deliberately stops short of deciding whether a signature should be
/// <em>trusted</em>. Trust is a question about certificate chains and local policy, and
/// the platform tools already answer it well — <c>signtool verify /pa</c> on Windows,
/// <c>dotnet nuget verify</c> for packages. Answering it a second time, differently,
/// would be worse than not answering it.
/// </para>
/// <para>
/// What it does answer is the question those tools cannot answer off Windows: does this
/// signature actually cover this file, and is it intact.
/// </para>
/// </remarks>
internal static class VerifyCommand
{
    public static int Run(string[] args)
    {
        List<string> files = [];

        for (int i = 1; i < args.Length; i++)
        {
            if (args[i].StartsWith('-'))
            {
                Console.Error.WriteLine($"error: unknown option '{args[i]}'.");
                return 2;
            }

            files.Add(args[i]);
        }

        if (files.Count == 0)
        {
            Console.Error.WriteLine("error: specify at least one file to verify.");
            return 2;
        }

        bool allSigned = true;

        foreach (string file in files)
        {
            if (!File.Exists(file))
            {
                Console.Error.WriteLine($"error: file not found: {file}");
                return 2;
            }

            allSigned &= Report(file);
        }

        return allSigned ? 0 : 1;
    }

    private static bool Report(string file)
    {
        Console.WriteLine(file);

        try
        {
            bool isMsi = string.Equals(Path.GetExtension(file), ".msi", StringComparison.OrdinalIgnoreCase);

            using FileStream stream = File.OpenRead(file);
            byte[]? signature = isMsi
                ? MsiFile.ReadEmbeddedSignature(stream)
                : PeFile.ReadEmbeddedSignature(stream);

            if (signature is null)
            {
                Console.WriteLine("  not signed");
                return false;
            }

            SignedCms cms = new();
            cms.Decode(signature);

            Console.WriteLine($"  signer:    {cms.SignerInfos[0].Certificate?.Subject ?? "(certificate not embedded)"}");
            Console.WriteLine($"  chain:     {cms.Certificates.Count} certificate(s) embedded");
            Console.WriteLine($"  signature: {(AuthenticodeSignedDataBuilder.VerifySignatureOnly(signature) ? "valid" : "INVALID")}");

            // The digest is what ties the signature to these particular bytes.
            byte[] digest = isMsi
                ? MsiFile.ComputeAuthenticodeDigest(stream, HashAlgorithmName.SHA256)
                : PeFile.ComputeAuthenticodeDigest(stream, HashAlgorithmName.SHA256);

            bool covers = Convert.ToHexString(signature).Contains(
                Convert.ToHexString(digest), StringComparison.OrdinalIgnoreCase);

            Console.WriteLine($"  covers this file: {(covers ? "yes" : "NO — the file changed after signing, or uses another digest algorithm")}");

            Rfc3161TimestampToken? timestamp = AuthenticodeTimestamp.TryGetTimestamp(cms);
            Console.WriteLine(timestamp is null
                ? "  timestamp: none — the signature expires with the certificate"
                : $"  timestamp: {timestamp.TokenInfo.Timestamp:u}");

            return covers;
        }
        catch (Exception ex) when (ex is InvalidDataException or CryptographicException or NotSupportedException)
        {
            Console.Error.WriteLine($"  error: {ex.Message}");
            return false;
        }
    }
}
