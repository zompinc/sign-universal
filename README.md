# sign-universal

Cross-platform code signing for .NET — sign Windows binaries (PE), installers (MSI), and **NuGet packages** from **Linux, macOS, or Windows**, with the private key held in **Azure Trusted Signing** or **Azure Key Vault** (the key never leaves the HSM).

> **Status: working for NuGet packages and PE binaries.** Both are signed and RFC 3161 timestamped from Ubuntu with a key in Azure Trusted Signing, and both are gated by the tool that decides: `dotnet nuget verify` for packages, `signtool verify /pa` on Windows CI for PE. Azure Key Vault is verified the same way, and MSI packages are signed too.

```bash
# What this exists to make possible: signing on ubuntu-latest, key in Trusted Signing.
sign-universal sign packages/*.nupkg --trust-signing-root \
  --trusted-signing-endpoint   https://eus.codesigning.azure.net \
  --trusted-signing-account    my-account \
  --trusted-signing-certificate-profile my-profile
```

## Why this exists

Signing a .NET release from Linux CI currently forces a Windows job into the pipeline, for two separate reasons:

- **[`dotnet/sign`](https://github.com/dotnet/sign)** supports Trusted Signing but is Windows-only. For PE it delegates Authenticode to `wintrust`/`mssign32`; and its Trusted Signing backend, `Microsoft.Trusted.Signing.Client`, ships a **native signtool Dlib** with MFC/MSVC dependencies. Neither runs on Linux.
- **`dotnet nuget sign`** *does* run on Linux — but only with a certificate whose private key is local. A key in Trusted Signing or Key Vault has no exportable key, so it is simply unreachable.

Those two gaps intersect at exactly the thing a release pipeline needs: **a remote key plus a Linux agent.** That is the hole this tool fills. [`jsign`](https://github.com/ebourg/jsign) solves the Authenticode half cross-platform and is excellent — but requires a JVM, and does not do NuGet packages.

The formats are OS-agnostic; only some of the APIs that produce them are not. .NET's crypto stack (`System.Security.Cryptography.Pkcs`, `System.Formats.Asn1`, `Rfc3161TimestampRequest`) runs everywhere, and NuGet's own client libraries are already cross-platform — so a managed implementation is feasible.

## The de-risked core

The whole design rests on one question: **can you produce a valid Authenticode PKCS#7 signature on Linux when the private key is remote (Key Vault) and never present in-process?** Answer, proven by `self-test`: **yes.**

```bash
dotnet run --project src/SignUniversal.Cli -- self-test
# PASS: remote-key signing produced a valid PKCS#7 SignedData; the private key never left the signer.
```

Two findings the spike locked in:

1. The private-key operation is delegated through a custom `RSA` (`RemoteSigningRsa`) whose `SignHash` calls the backend; everything else is stock `SignedCms`/`CmsSigner`.
1. **`X509Certificate2.CopyWithPrivateKey` cannot be used** — on Linux it eagerly exports private parameters, which a remote key can't provide. Use the `CmsSigner(SubjectIdentifierType, certificate, privateKey)` overload, which signs via the key's `SignHash`.

## Install

```bash
dotnet tool install --global SignUniversal.Cli
sign-universal --version
```

Needs .NET 8 or newer — the tool targets `net8.0` but rolls forward, so a machine carrying
only a later runtime is fine.

> Nothing is on nuget.org yet. Until the first release, build it locally with
> `dotnet pack src/SignUniversal.Cli -c Release -o artifacts` and
> `dotnet tool install --global --add-source artifacts --prerelease SignUniversal.Cli`.

## Key sources

| Source | Options | Notes |
|---|---|---|
| Azure Trusted Signing | `--trusted-signing-endpoint`, `--trusted-signing-account`, `--trusted-signing-certificate-profile` | Verified against a live account. Needs `--trust-signing-root` on Linux |
| Azure Key Vault | `--key-vault-url`, `--key-vault-certificate` | Verified against a live vault, with a non-exportable key |
| Local PKCS#12 | `--pfx`, `--password` | For local runs and testing |
| Throwaway | `--self-signed` | Smoke tests only; nothing trusts it |

Azure credentials come from `DefaultAzureCredential` in both cloud cases, so the usual
`AZURE_TENANT_ID` / `AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET` variables work unchanged.
Key Vault needs `certificates/get` to read the certificate and `keys/sign` to use it.
Those are separate permissions, and having the first without the second is the usual
surprise: management rights over a key do not include signing with it. The private key is
never fetched — verification used a certificate marked non-exportable, which would have
failed outright had anything tried.

## Signing NuGet packages

```bash
sign-universal sign packages/*.nupkg --pfx signing.pfx --password ****
```

The package hashing and the zip surgery that inserts `.signature.p7s` are done by **NuGet's own libraries** — they are the format's reference implementation and they already run everywhere. All this tool adds is the one thing they cannot do: produce the CMS signature from a key it never holds.

Replacing a `windows-latest` signing job with an Ubuntu one looks like this:

```yaml
  sign:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v5
        with: { name: packages, path: packages }

      - name: Sign
        env:
          AZURE_TENANT_ID: ${{ secrets.AZURE_TENANT_ID }}
          AZURE_CLIENT_ID: ${{ secrets.AZURE_SIGNER_CLIENT_ID }}
          AZURE_CLIENT_SECRET: ${{ secrets.AZURE_SIGNER_CLIENT_SECRET }}
        run: |
          sign-universal sign packages/*.nupkg --trust-signing-root \
            --trusted-signing-endpoint "${{ secrets.TRUSTED_SIGNING_ENDPOINT }}" \
            --trusted-signing-account "${{ secrets.TRUSTED_SIGNING_ACCOUNT }}" \
            --trusted-signing-certificate-profile "${{ secrets.TRUSTED_SIGNING_CERTIFICATE_PROFILE }}"
```

Credentials are read by `DefaultAzureCredential`, so the same `AZURE_*` variables a Windows job already sets keep working. Every file is signed in one session, which matters because opening one mints a certificate.

### Why `--trust-signing-root` is needed on Linux

Without it, signing fails on an otherwise perfectly configured agent with nothing but:

```
error: Certificate chain validation failed.
```

Before NuGet will sign, it builds and validates the signing certificate's chain against
the *machine's* trust store, and an untrusted root is fatal. Trusted Signing issues from
**Microsoft Identity Verification Root Certificate Authority 2020**, which Linux trust
stores do not carry — Ubuntu ships only the Microsoft 2017 roots. Windows agents never
hit this, which is why the requirement is invisible until you move the job.

`--trust-signing-root` installs that root into the **current user's** store, never the
machine's, and takes it from the chain the signing service itself returned over an
authenticated connection rather than downloading a CA certificate over plain HTTP.

Consumers need no such thing: `dotnet nuget verify` validates against NuGet's own root
bundle, which already contains that root.

### Timestamping

Both formats are timestamped by default, and with Trusted Signing that is not optional: its certificates live about three days, so an untimestamped signature expires almost immediately. `--no-timestamp` opts out and says so loudly.

Authenticode keeps its RFC 3161 token in an unsigned attribute under Microsoft's own `szOID_RFC3161_counterSign` (`1.3.6.1.4.1.311.3.3.1`) rather than the `id-aa-timeStampToken` ordinary CMS uses — a detail taken from Microsoft-signed binaries, every one of which carries exactly that attribute. What the authority attests to is the signature value, not the file.

The default authority is **DigiCert**, not Microsoft's `timestamp.acs.microsoft.com`, because the latter **fails on a stock Linux agent**: its responses carry only the leaf and intermediate, and the root they chain to (*Microsoft Identity Verification Root Certificate Authority 2020*) is not in Ubuntu's trust store, so the chain cannot be built and signing fails. DigiCert returns a full chain to a root Ubuntu already trusts. Override with `--timestamper` if you have installed that root.

## Signing an MSI

```bash
sign-universal sign installer.msi --pfx signing.pfx
```

An MSI is an OLE compound file, so there is no offset arithmetic: the digest covers the
streams themselves, ordered by the raw bytes of their UTF-16LE names — which is not the
same as ordinal string order, and matters because MSI mangles table names into code
points where the two disagree. The `\u0005MsiDigitalSignatureEx` pre-hash is covered by
the digest when present, so re-signing removes it rather than leaving it stale.

Signing also writes `\u0005MsiDigitalSignatureEx`, a pre-hash over the package's
*metadata* — stream names, sizes, class identifiers, state bits, timestamps. Where the
main digest covers what the streams contain, this covers how they are described, so a
package cannot be altered by renaming or rearranging its parts either. signtool writes one
unconditionally and Windows rejects the signature without it.

Both were established the same way as the PE digest: reproduce what an already-signed
package carries. Point `SIGNUNIVERSAL_MSI_ORACLE` at a signed `.msi` to re-run those
checks.

## Signing a PE image

```bash
sign-universal sign app.exe --pfx signing.pfx --password ****   # or --self-signed, for smoke tests
```

The file is signed in place: an existing signature is replaced, the image is padded to
the 8-byte boundary the certificate table needs, the PKCS#7 blob is appended as a
`WIN_CERTIFICATE`, the data directory is repointed, and the PE checksum is refreshed.

## Cutting a release

Run the **build** workflow from master with *Run workflow*. It packs, signs the packages
with Trusted Signing using the build being released, verifies them, pushes to nuget.org,
and creates the GitHub Release.

The tag is derived from the package that was built, not typed. Nerdbank.GitVersioning
takes the version from `version.json` and git height, so a hand-written tag can claim a
version the package does not have — deriving it the other way round makes that
impossible. The corollary is that the version lives in `version.json`: while it says
`1.0-alpha`, every release is a prerelease.

## Releases sign themselves

The `publish` job installs the very build being released and uses it to sign its own
`.nupkg` and `.snupkg` with Trusted Signing, verifies the result with `dotnet nuget
verify`, and only then pushes. A regression in signing therefore breaks the release
loudly instead of shipping quietly broken signatures to everyone who installs the tool.

> **Do not register a certificate on the nuget.org account.** Trusted Signing rotates its
> certificate every three days, and nuget.org registers signing certificates by SHA-256
> fingerprint — so a Trusted Signing certificate cannot be registered
> ([NuGetGallery#10027](https://github.com/NuGet/NuGetGallery/issues/10027)). Pushing
> signed packages works fine while the account has *no* registered certificates. The
> moment one is registered, every future push must match it, and these signatures never
> will — which would break publishing for every package on that account, not just this
> one.

## Checking a signature

```bash
sign-universal verify app.exe installer.msi
```

Reports the signer, how many certificates the signature embeds, whether the signature is
intact, whether it covers the bytes on disk, and the timestamp. Exit code is non-zero if
any file is unsigned or no longer matches its signature.

It deliberately does not decide **trust** — that is a question about certificate chains
and local policy, and `signtool verify /pa` and `dotnet nuget verify` already answer it
well. What this answers is the part they cannot answer off Windows: does this signature
actually cover this file.

## Roadmap

| Milestone | What | Notes |
|---|---|---|
| ✅ Spike | remote-key → `SignedCms` on Linux | done — `self-test` |
| ✅ ASN.1 | `SpcIndirectData` + `SpcLink` | byte-identical to signtool's encoding |
| ✅ PE | Authenticode hash + cert-table embed | PE32/PE32+; page hashes deferred |
| ✅ NuGet | author-signed `.nupkg` with a remote key | NuGet's libraries do the format; we do the key |
| ✅ Trusted Signing | `IRemoteSigner` over the managed client | verified against a live account |
| ✅ Azure Key Vault | `IRemoteSigner` via `CryptographyClient` | verified against a live vault |
| ✅ MSI | compound-file digest + pre-hash + signature stream | digest and pre-hash both match signtool's |
| ✅ Timestamp | RFC 3161 for both formats | on by default; `--no-timestamp` opts out |
| ✅ Verify | `signtool /verify` + `dotnet nuget verify` in CI | both run on every push; `verify` command for offline checks |

Out of scope for v1: MSIX/APPX, CAB, scripts, non-Azure KMS.

## Correctness

Authenticode is a format you cannot get *almost* right, and the Windows verifier is not
available where most of this code is written. Three checks stand in for it:

1. **A second implementation, and a corpus.** `AuthenticodeDigestReference` in the test
   project is the digest algorithm transcribed straight from the specification, sharing
   no code with the engine. Point the suite at a directory of already-signed binaries
   with `SIGNUNIVERSAL_PE_CORPUS` and it recomputes each digest and finds it inside that
   file's own signature — the oracle that settled every format question the spec left
   ambiguous (`dwLength` including its padding, what `messageDigest` covers). A NuGet
   package cache works: `SIGNUNIVERSAL_PE_CORPUS=~/.nuget/packages`.
1. **Structural tests.** The encoded `SpcIndirectDataContent` is compared byte for byte
   with a Microsoft-signed binary's, and signing must leave the digest it covers
   unchanged.
1. **`signtool verify /pa`** on Windows — the gate that actually decides for Authenticode.
   CI's Windows leg sets `SIGNUNIVERSAL_REQUIRE_SIGNTOOL=1`, so a missing signtool fails
   the build rather than skipping the gate and reporting green.
1. **`dotnet nuget verify`** for packages — NuGet's own client judging our output, and
   unlike the Authenticode gate it runs on the same Linux machine that produced the
   signature. A tamper test keeps it honest: modify a signed package and the suite fails
   if NuGet does not notice.

The Trusted Signing path has been exercised against a live account: packages signed on
Ubuntu with a key in the service, verified clean by `dotnet nuget verify` — full
certificate chain embedded, RFC 3161 timestamp attached, exit code 0.

## Layout

```
src/SignUniversal.Core    signing engine (BCL-only today)
src/SignUniversal.Cli     dotnet tool (`sign-universal`)
test/SignUniversal.Core.Tests
```

## Adopting it

Moving an existing `windows-latest` signing job to Linux is a small diff, with two
non-obvious requirements that will otherwise cost an afternoon. See
[`docs/adopting-sign-universal.md`](docs/adopting-sign-universal.md).

## Prior art & credit

Design and format handling are informed by **jsign** (Apache-2.0) — see [`NOTICE`](NOTICE). Licensed Apache-2.0 (see [`LICENSE`](LICENSE)).
