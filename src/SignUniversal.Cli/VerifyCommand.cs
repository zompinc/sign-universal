using NuGet.Packaging.Signing;
using SignUniversal.Core;

namespace SignUniversal.Cli;

/// <summary>
/// Prints what a signed file carries. The inspection itself lives in the engine, where
/// tests can reach it.
/// </summary>
internal static class VerifyCommand
{
    public static async Task<int> Run(string[] args)
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

        bool allGood = true;

        foreach (string file in files)
        {
            if (!File.Exists(file))
            {
                Console.Error.WriteLine($"error: file not found: {file}");
                return 2;
            }

            allGood &= await Report(file).ConfigureAwait(false);
        }

        return allGood ? 0 : 1;
    }

    private static async Task<bool> Report(string file)
    {
        Console.WriteLine(file);

        try
        {
            SignatureReport report = await SignatureInspector.InspectAsync(file).ConfigureAwait(false);

            if (!report.IsSigned)
            {
                Console.WriteLine($"  {report.Format}, not signed");
                return false;
            }

            Console.WriteLine($"  format:    {report.Format}");
            Console.WriteLine($"  signer:    {report.Signer ?? "(certificate not embedded)"}");
            Console.WriteLine($"  chain:     {report.EmbeddedCertificates} certificate(s) embedded");
            Console.WriteLine($"  signature: {(report.SignatureValid ? "valid" : "INVALID")}");
            Console.WriteLine($"  covers this file: {(report.CoversFile ? "yes" : "NO - the file changed after signing")}");
            Console.WriteLine(report.Timestamp is null
                ? "  timestamp: none - the signature expires with the certificate"
                : $"  timestamp: {report.Timestamp:u}");

            return report.SignatureValid && report.CoversFile;
        }
        catch (Exception ex) when (ex is InvalidDataException or CryptographicException
            or NotSupportedException or SignatureException)
        {
            // A malformed signature file is a different thing from one that simply does not
            // cover the file, so it is reported rather than folded into the normal output.
            Console.Error.WriteLine($"  error: {ex.Message}");
            return false;
        }
    }
}
