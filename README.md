# sign-universal

Cross-platform code signing for .NET - sign NuGet packages, Windows binaries (PE) and
installers (MSI) from **Linux, macOS or Windows**, with the private key held in **Azure
Trusted Signing** or **Azure Key Vault**, where it stays.

```bash
# The point of the tool: a release signed on ubuntu-latest, key never leaving the HSM.
sign-universal sign packages/*.nupkg --trust-signing-root \
  --trusted-signing-endpoint https://eus.codesigning.azure.net \
  --trusted-signing-account my-account \
  --trusted-signing-certificate-profile my-profile
```

## Why this exists

Signing a .NET release from Linux CI forces a Windows job into the pipeline, for two
separate reasons:

- **[`dotnet/sign`](https://github.com/dotnet/sign)** supports Trusted Signing but is
  Windows-only. For PE it delegates Authenticode to `wintrust`/`mssign32`, and its Trusted
  Signing backend ships a native signtool Dlib with MFC/MSVC dependencies.
- **`dotnet nuget sign`** runs on Linux, but only with a certificate whose private key is
  local. A key in Trusted Signing or Key Vault has no exportable key, so it is unreachable.

Those gaps intersect at exactly what a release pipeline needs: **a remote key plus a Linux
agent.** [`jsign`](https://github.com/ebourg/jsign) solves the Authenticode half
cross-platform and is excellent, but requires a JVM and does not do NuGet packages.

## Install

```bash
dotnet tool install --global SignUniversal.Cli
sign-universal --version
```

Needs .NET 8 or newer; the tool targets `net8.0` and rolls forward. `dotnet dnx
SignUniversal.Cli@<version>` runs it without installing, which suits CI.

## Use

```bash
sign-universal sign packages/*.nupkg      # NuGet package (and .snupkg)
sign-universal sign app.exe               # PE binary
sign-universal sign installer.msi         # MSI package
sign-universal verify app.exe pkg.nupkg   # what a signature says about itself
```

Files are signed in place, one signing session covers every file given, and everything is
RFC 3161 timestamped by default. `verify` reports the signer, the embedded chain, whether
the signature is intact and whether it still covers the bytes on disk; it exits non-zero if
not. It deliberately leaves *trust* to `signtool verify /pa` and `dotnet nuget verify`,
which already decide it properly.

When a build tool hands over a whole publish output - Velopack's `--signTemplate` does, one
file per invocation - `--skip-signed` leaves alone anything that already carries a
signature:

```bash
sign-universal sign app.dll --trusted-signing-metadata signing.json --skip-signed
```

Authenticode keeps a single primary signature, so signing an assembly Microsoft already
signed does not add ours beside theirs, it replaces it. The check is presence, not trust:
that is the only answer available off Windows, and it is the one that matters when the
question is whether signing would clobber somebody else's work. Nothing is skipped without
`--skip-signed`, since deliberate re-signing is legitimate.

For packages, the hashing and the zip surgery that inserts `.signature.p7s` are NuGet's own
libraries - the format's reference implementation. All this adds is the one thing they
cannot do: a CMS signature from a key it never holds.

## Use as a library

The engine ships separately from the tool, so another program can sign without shelling
out to a process:

| Package | Adds | Cost |
|---|---|---|
| `SignUniversal` | PE and MSI Authenticode | `System.Security.Cryptography.Pkcs`, `OpenMcdf` |
| `SignUniversal.Azure` | Trusted Signing and Key Vault key sources | the Azure SDK |
| `SignUniversal.NuGet` | `.nupkg` author signing | NuGet's client libraries |

```csharp
using IRemoteSigner signer = new TrustedSigningRemoteSigner(endpoint, account, profile);
PeSigner.SignFile("app.exe", signer, HashAlgorithmName.SHA256, timestampUrl);
MsiSigner.SignFile("installer.msi", signer, HashAlgorithmName.SHA256, timestampUrl);
```

Signing happens on a copy that replaces the original only on success, so a lost network or
a rejected credential cannot leave behind a file whose old signature is gone and whose new
one was never written.

`IRemoteSigner` is one `SignHash` method, so the key can stay wherever it already lives -
the Azure implementations are just two of them. Referencing `SignUniversal` on its own
costs no Azure and no NuGet dependency.

## Key sources

| Source | Options |
|---|---|
| Azure Trusted Signing | `--trusted-signing-endpoint`, `--trusted-signing-account`, `--trusted-signing-certificate-profile`, or all three from `--trusted-signing-metadata <file>` |
| Azure Key Vault | `--key-vault-url`, `--key-vault-certificate` |
| Local PKCS#12 | `--pfx`, with `SIGNUNIVERSAL_PFX_PASSWORD` or `--password-stdin` |
| Throwaway | `--self-signed`, for smoke tests only |

Both cloud sources authenticate through `DefaultAzureCredential`, so the usual `AZURE_*`
variables work unchanged. Key Vault needs `certificates/get` **and** `keys/sign` - separate
permissions, and holding the first without the second is the usual surprise.

`--trusted-signing-metadata` reads the JSON file `vpk` and `dotnet sign` already take
(`Endpoint`, `CodeSigningAccountName`, `CertificateProfileName`), which matters when a tool
takes the signing command as one string and splits it on whitespace. `--azure-trusted-sign-file`
is the same flag under the name `vpk` gives it.

`--export-certificate` writes out the certificate that signed, which is what a gallery
wants when it requires registration.

## Moving a signing job off Windows

Two requirements are invisible until you try it, and each costs an afternoon:

- **`--trust-signing-root` is required on Linux.** Trusted Signing issues from a root Linux
  trust stores do not carry, and NuGet refuses to sign against a chain it cannot build, so
  without it you get only `Certificate chain validation failed`.
- **Microsoft's `timestamp.acs.microsoft.com` does not chain on a stock Linux agent.** The
  default is DigiCert for that reason.

[`docs/adopting-sign-universal.md`](docs/adopting-sign-universal.md) has the full change,
which is two lines of workflow plus those flags.

How much time it saves depends on what else the job does. Signing itself is much the same
speed on either platform; what goes away is Windows runner startup, which costs about 48s
against 10s on `ubuntu-latest`. A job that only signs gains most of that:
`Zomp.SyncMethodGenerator` went from 51-90s to 10-12s. A job that also pushes packages
gains proportionally less - `Zomp.EFCore.BinaryFunctions` went from 41s to 36s while
gaining a verification step. Windows minutes are also billed at twice the rate, so a
private repository saves on both counts.

## Correctness

Authenticode is a format you cannot get *almost* right, and the verifier that decides is
not available where most of this code was written. Four checks stand in for it, all in CI:

1. **A second implementation, and a corpus.** `AuthenticodeDigestReference` is the digest
   transcribed straight from the specification, sharing no code with the engine. Pointed at
   a directory of signed binaries via `SIGNUNIVERSAL_PE_CORPUS`, the suite recomputes each
   digest and finds it inside that file's own signature - the oracle that settled every
   question the spec leaves ambiguous. A NuGet package cache works.
1. **Structural tests** compare the encoded `SpcIndirectDataContent` byte for byte against
   a Microsoft-signed binary's, and require that signing leave the digest it covers
   unchanged.
1. **`signtool verify /pa`** on Windows, for PE and MSI. The Windows leg sets
   `SIGNUNIVERSAL_REQUIRE_SIGNTOOL=1`, so a missing signtool fails the build instead of
   skipping the gate and reporting green.
1. **`dotnet nuget verify`** for packages, on the same Linux machine that produced the
   signature. A tamper test keeps it honest.

Both cloud backends have been exercised against live Azure. The tool signs its own
releases, and [`Zomp.SyncMethodGenerator`](https://www.nuget.org/packages/Zomp.SyncMethodGenerator)
is published signed by it from an Ubuntu runner.

Out of scope for v1: MSIX/APPX, CAB, scripts, non-Azure KMS, and PE page hashes.

## Credit

Design and format handling were informed by **jsign** - see [`NOTICE`](NOTICE). No
jsign code is included; the acknowledgement is a courtesy, not a licence obligation.
Licensed MIT (see [`LICENSE`](LICENSE)).
