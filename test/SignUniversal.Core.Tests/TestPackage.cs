using NuGet.Packaging;
using NuGet.Versioning;

namespace SignUniversal.Core.Tests;

/// <summary>
/// Builds a real .nupkg on disk with NuGet's own <see cref="PackageBuilder"/>, so the
/// signing tests operate on a package NuGet's tooling considers well formed.
/// </summary>
internal static class TestPackage
{
    /// <summary>The path inside the package that <see cref="Tamper"/> rewrites.</summary>
    public const string ContentPath = "lib/net8.0/SignUniversal.TestPackage.dll";

    /// <summary>Creates an unsigned test package.</summary>
    /// <param name="directory">The directory to create it in.</param>
    /// <returns>The path of the package.</returns>
    public static string Create(string directory)
    {
        // Deliberately several kilobytes of poorly-compressible bytes, so a test can flip
        // one at a known offset and be sure it landed in content rather than in the
        // signature that follows it.
        string payloadPath = Path.Combine(directory, "payload.bin");
        byte[] payload = new byte[16 * 1024];
        for (int i = 0; i < payload.Length; i++)
        {
            payload[i] = (byte)((i * 2654435761L) >> 13);
        }

        File.WriteAllBytes(payloadPath, payload);

        PackageBuilder builder = new()
        {
            Id = "SignUniversal.TestPackage",
            Version = NuGetVersion.Parse("1.0.0"),
            Description = "Fixture for signing tests.",
        };
        builder.Authors.Add("Zomp");
        builder.Files.Add(new PhysicalPackageFile { SourcePath = payloadPath, TargetPath = ContentPath });

        string packagePath = Path.Combine(directory, "SignUniversal.TestPackage.1.0.0.nupkg");
        using (FileStream stream = File.Create(packagePath))
        {
            builder.Save(stream);
        }

        File.Delete(payloadPath);
        return packagePath;
    }

    /// <summary>Rewrites a file inside a package, leaving the signature in place.</summary>
    /// <param name="packagePath">The package to modify.</param>
    public static void Tamper(string packagePath)
    {
        using FileStream stream = new(packagePath, FileMode.Open, FileAccess.ReadWrite);
        using System.IO.Compression.ZipArchive archive = new(stream, System.IO.Compression.ZipArchiveMode.Update);

        System.IO.Compression.ZipArchiveEntry entry = archive.GetEntry(ContentPath)
            ?? throw new InvalidOperationException($"'{ContentPath}' is missing from the package.");

        using Stream entryStream = entry.Open();
        entryStream.SetLength(0);
        entryStream.Write("tampered"u8);
    }
}
