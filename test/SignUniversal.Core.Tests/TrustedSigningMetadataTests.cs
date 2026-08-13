using SignUniversal.Cli;

namespace SignUniversal.Core.Tests;

/// <summary>
/// Covers reading the Trusted Signing details from the JSON file other tools already take.
/// </summary>
public sealed class TrustedSigningMetadataTests
{
    [Test]
    public void TryLoad_ReadsTheFileVpkPasses()
    {
        using TemporaryDirectory directory = new();
        string json =
            """
            {
              "Endpoint": "https://eus.codesigning.azure.net",
              "CodeSigningAccountName": "my-account",
              "CertificateProfileName": "my-profile"
            }
            """;
        string path = Write(directory, json);

        bool loaded = TrustedSigningMetadata.TryLoad(path, out TrustedSigningMetadata? metadata, out string? error);

        loaded.Should().BeTrue();
        error.Should().BeNull();
        metadata!.Endpoint.Should().Be("https://eus.codesigning.azure.net");
        metadata.Account.Should().Be("my-account");
        metadata.CertificateProfile.Should().Be("my-profile");
    }

    [Test]
    public void TryLoad_DoesNotCareAboutCase()
    {
        // Hand-edited as often as generated, and "endpoint" failing as "missing Endpoint"
        // is a bad half hour.
        using TemporaryDirectory directory = new();
        string json =
            """
            {
              "endpoint": "https://eus.codesigning.azure.net",
              "codeSigningAccountName": "my-account",
              "certificateprofilename": "my-profile"
            }
            """;
        string path = Write(directory, json);

        bool loaded = TrustedSigningMetadata.TryLoad(path, out TrustedSigningMetadata? metadata, out _);

        loaded.Should().BeTrue();
        metadata!.Account.Should().Be("my-account");
    }

    [Test]
    public void TryLoad_IgnoresFieldsOtherToolsAdd()
    {
        using TemporaryDirectory directory = new();
        string json =
            """
            {
              "Endpoint": "https://eus.codesigning.azure.net",
              "CodeSigningAccountName": "my-account",
              "CertificateProfileName": "my-profile",
              "CorrelationId": "6f0a",
              "ExcludeCredentials": ["VisualStudioCredential"]
            }
            """;
        string path = Write(directory, json);

        bool loaded = TrustedSigningMetadata.TryLoad(path, out _, out string? error);

        loaded.Should().BeTrue();
        error.Should().BeNull();
    }

    [Test]
    public void TryLoad_NamesEveryFieldTheFileIsMissing()
    {
        using TemporaryDirectory directory = new();
        string path = Write(directory, """{ "Endpoint": "https://eus.codesigning.azure.net" }""");

        bool loaded = TrustedSigningMetadata.TryLoad(path, out _, out string? error);

        loaded.Should().BeFalse();
        error.Should().Contain("CodeSigningAccountName").And.Contain("CertificateProfileName");
    }

    [Test]
    public void TryLoad_TreatsAnEmptyValueAsMissing()
    {
        using TemporaryDirectory directory = new();
        string json =
            """
            {
              "Endpoint": "https://eus.codesigning.azure.net",
              "CodeSigningAccountName": "  ",
              "CertificateProfileName": "my-profile"
            }
            """;
        string path = Write(directory, json);

        bool loaded = TrustedSigningMetadata.TryLoad(path, out _, out string? error);

        loaded.Should().BeFalse();
        error.Should().Contain("CodeSigningAccountName");
    }

    [Test]
    public void TryLoad_ReportsBrokenJsonRatherThanThrowing()
    {
        using TemporaryDirectory directory = new();
        string path = Write(directory, "{ \"Endpoint\": ");

        bool loaded = TrustedSigningMetadata.TryLoad(path, out _, out string? error);

        loaded.Should().BeFalse();
        error.Should().Contain("not valid JSON");
    }

    [Test]
    public void TryLoad_ReportsAMissingFile()
    {
        using TemporaryDirectory directory = new();

        bool loaded = TrustedSigningMetadata.TryLoad(
            Path.Combine(directory.Path, "absent.json"), out _, out string? error);

        loaded.Should().BeFalse();
        error.Should().Contain("absent.json");
    }

    private static string Write(TemporaryDirectory directory, string json)
    {
        string path = Path.Combine(directory.Path, "signing-metadata.json");
        File.WriteAllText(path, json);
        return path;
    }
}
