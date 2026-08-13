using System.Text.Json;

namespace SignUniversal.Cli;

/// <summary>The Trusted Signing account details, read from a JSON file.</summary>
/// <param name="Endpoint">The regional Trusted Signing endpoint.</param>
/// <param name="Account">The code signing account name.</param>
/// <param name="CertificateProfile">The certificate profile to sign under.</param>
/// <remarks>
/// <para>
/// The schema is the one <c>vpk</c> and <c>dotnet sign</c> already take, so a caller can
/// pass the file it has rather than restating its contents:
/// </para>
/// <code>
/// {
///   "Endpoint": "https://eus.codesigning.azure.net",
///   "CodeSigningAccountName": "my-account",
///   "CertificateProfileName": "my-profile"
/// }
/// </code>
/// <para>
/// This matters beyond ergonomics for build tools that take a signing command as a single
/// string and split it on whitespace - three long flags and their values are a lot to push
/// through that, and the file is what the tool itself already consumes.
/// </para>
/// </remarks>
internal sealed record TrustedSigningMetadata(string Endpoint, string Account, string CertificateProfile)
{
    // Case-insensitive because the file is hand-edited as often as it is generated, and a
    // lowercase "endpoint" failing with "missing endpoint" is a bad half hour.
    private static readonly JsonSerializerOptions ReadOptions = new() { PropertyNameCaseInsensitive = true };

    /// <summary>Reads the metadata file at <paramref name="path"/>.</summary>
    /// <param name="path">The JSON file to read.</param>
    /// <param name="metadata">The details it carried, when it was usable.</param>
    /// <param name="error">Why reading failed, when it did.</param>
    /// <returns><see langword="true"/> if the file supplied all three details.</returns>
    public static bool TryLoad(string path, out TrustedSigningMetadata? metadata, out string? error)
    {
        metadata = null;
        error = null;

        if (!File.Exists(path))
        {
            error = $"File not found: {path}";
            return false;
        }

        Document? document;
        try
        {
            document = JsonSerializer.Deserialize<Document>(File.ReadAllText(path), ReadOptions);
        }
        catch (JsonException ex)
        {
            error = $"{path} is not valid JSON: {ex.Message}";
            return false;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            error = $"Could not read {path}: {ex.Message}";
            return false;
        }

        // Fields the file does not carry are named as the file spells them, since that is
        // what the reader has to go and add.
        List<string> missing = [];
        if (string.IsNullOrWhiteSpace(document?.Endpoint)) missing.Add("Endpoint");
        if (string.IsNullOrWhiteSpace(document?.CodeSigningAccountName)) missing.Add("CodeSigningAccountName");
        if (string.IsNullOrWhiteSpace(document?.CertificateProfileName)) missing.Add("CertificateProfileName");

        if (missing.Count > 0)
        {
            error = $"{path} is missing {string.Join(", ", missing)}.";
            return false;
        }

        metadata = new TrustedSigningMetadata(
            document!.Endpoint!,
            document.CodeSigningAccountName!,
            document.CertificateProfileName!);
        return true;
    }

    /// <summary>The file as written on disk; other tools add fields, so unknown ones are ignored.</summary>
    private sealed record Document(string? Endpoint, string? CodeSigningAccountName, string? CertificateProfileName);
}
