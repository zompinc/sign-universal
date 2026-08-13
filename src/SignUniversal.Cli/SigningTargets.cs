namespace SignUniversal.Cli;

/// <summary>
/// Classifies the files a signing run was given, and decides which of them still need signing.
/// </summary>
internal static class SigningTargets
{
    /// <summary>Whether the file is an MSI package.</summary>
    public static bool IsMsi(string path) =>
        string.Equals(Path.GetExtension(path), ".msi", StringComparison.OrdinalIgnoreCase);

    /// <summary>Whether the file is a NuGet package.</summary>
    public static bool IsPackage(string path)
    {
        // Symbol packages are ordinary packages as far as signing is concerned, and
        // publishing a signed .nupkg beside an unsigned .snupkg is a odd thing to ship.
        string extension = Path.GetExtension(path);
        return string.Equals(extension, ".nupkg", StringComparison.OrdinalIgnoreCase)
            || string.Equals(extension, ".snupkg", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Splits the files into those still to sign and those already carrying an Authenticode
    /// signature.
    /// </summary>
    /// <param name="files">The resolved files, in signing order.</param>
    /// <returns>The two lists, each keeping the order it was given in.</returns>
    /// <remarks>
    /// <para>
    /// This exists for build tools that hand every binary in a publish output to a signing
    /// command one at a time - Velopack's <c>--signTemplate</c> is the case that prompted it.
    /// Such a payload contains assemblies Microsoft and other vendors already signed, and
    /// Authenticode keeps a single primary signature, so signing them does not add ours
    /// alongside the vendor's: it replaces it, and the provenance is gone.
    /// </para>
    /// <para>
    /// NuGet packages are never skipped. Their signature is a different mechanism with its
    /// own rules about repository countersignatures, and nothing hands out pre-signed
    /// packages to be re-signed by accident.
    /// </para>
    /// </remarks>
    public static (List<string> ToSign, List<string> AlreadySigned) PartitionBySignature(IReadOnlyList<string> files)
    {
        ArgumentNullException.ThrowIfNull(files);

        List<string> toSign = [];
        List<string> alreadySigned = [];

        foreach (string file in files)
        {
            if (!IsPackage(file) && AuthenticodeInspector.HasSignature(file, IsMsi(file)))
            {
                alreadySigned.Add(file);
            }
            else
            {
                toSign.Add(file);
            }
        }

        return (toSign, alreadySigned);
    }
}
