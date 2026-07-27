# sign-universal

Cross-platform code signing for .NET — sign Windows binaries (PE), installers (MSI), and **NuGet packages** from **Linux, macOS, or Windows**, with the private key held in **Azure Trusted Signing** or **Azure Key Vault** (the key never leaves the HSM).

> **Status: early, but useful.** NuGet package signing and Authenticode PE signing both work end to end from Linux, against Trusted Signing. MSI, Key Vault, and PE timestamping are still ahead, and the `signtool` gate only runs on Windows.

```bash
# What this exists to make possible: signing on ubuntu-latest, key in Trusted Signing.
sign-universal sign packages/*.nupkg \
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
          sign-universal sign packages/*.nupkg \
            --trusted-signing-endpoint "${{ secrets.TRUSTED_SIGNING_ENDPOINT }}" \
            --trusted-signing-account "${{ secrets.TRUSTED_SIGNING_ACCOUNT }}" \
            --trusted-signing-certificate-profile "${{ secrets.TRUSTED_SIGNING_CERTIFICATE_PROFILE }}"
```

Credentials are read by `DefaultAzureCredential`, so the same `AZURE_*` variables a Windows job already sets keep working. Every file is signed in one session, which matters because opening one mints a certificate.

### Timestamping

Signatures are timestamped by default, and with Trusted Signing that is not optional: its certificates live about three days, so an untimestamped signature expires almost immediately.

The default authority is **DigiCert**, not Microsoft's `timestamp.acs.microsoft.com`, because the latter **fails on a stock Linux agent**: its responses carry only the leaf and intermediate, and the root they chain to (*Microsoft Identity Verification Root Certificate Authority 2020*) is not in Ubuntu's trust store, so the chain cannot be built and signing fails. DigiCert returns a full chain to a root Ubuntu already trusts. Override with `--timestamper` if you have installed that root.

## Signing a PE image

```bash
sign-universal sign app.exe --pfx signing.pfx --password ****   # or --self-signed, for smoke tests
```

The file is signed in place: an existing signature is replaced, the image is padded to
the 8-byte boundary the certificate table needs, the PKCS#7 blob is appended as a
`WIN_CERTIFICATE`, the data directory is repointed, and the PE checksum is refreshed.

## Roadmap

| Milestone | What | Notes |
|---|---|---|
| ✅ Spike | remote-key → `SignedCms` on Linux | done — `self-test` |
| ✅ ASN.1 | `SpcIndirectData` + `SpcLink` | byte-identical to signtool's encoding |
| ✅ PE | Authenticode hash + cert-table embed | PE32/PE32+; page hashes deferred |
| ✅ NuGet | author-signed `.nupkg` with a remote key | NuGet's libraries do the format; we do the key |
| ✅ Trusted Signing | `IRemoteSigner` over the managed client | untested against a live account — see below |
| Azure Key Vault | `IRemoteSigner` via `CryptographyClient` | `DefaultAzureCredential` |
| MSI | compound-file digest + signature streams | container via OpenMcdf |
| Timestamp (PE) | RFC 3161 for Authenticode | `.nupkg` timestamping already works |
| Verify | `signtool /verify` harness in CI | harness landed with PE; needs a Windows job |

Out of scope for v1: MSIX/APPX, CAB, scripts, non-Azure KMS.

## Correctness

Authenticode is a format you cannot get *almost* right, and the Windows verifier is not
available where most of this code is written. Three checks stand in for it:

1. **Known-answer vectors.** `tools/authenticode-digest-reference.py` is an independent
   transcription of the digest algorithm. Run it with `--check` over any directory of
   Microsoft-signed binaries and it recomputes each digest and finds it inside that
   file's own signature — the same oracle that fixed every format question the spec
   left ambiguous (`dwLength` including its padding, what `messageDigest` covers).
1. **Structural tests.** The encoded `SpcIndirectDataContent` is compared byte for byte
   with a Microsoft-signed binary's, and signing must leave the digest it covers
   unchanged.
1. **`signtool verify /pa`** on Windows — the gate that actually decides for Authenticode.
1. **`dotnet nuget verify`** for packages — NuGet's own client judging our output, and
   unlike the Authenticode gate it runs on the same Linux machine that produced the
   signature. A tamper test keeps it honest: modify a signed package and the suite fails
   if NuGet does not notice.

**Not yet proven:** the Trusted Signing backend has never run against a live account —
there are no credentials in this repo. It compiles and follows the client's documented
shape, but the first real run should be treated as a test, not a formality.

## Layout

```
src/SignUniversal.Core    signing engine (BCL-only today)
src/SignUniversal.Cli     dotnet tool (`sign-universal`)
test/SignUniversal.Core.Tests
```

## Prior art & credit

Design and format handling are informed by **jsign** (Apache-2.0) — see [`NOTICE`](NOTICE). Licensed Apache-2.0 (see [`LICENSE`](LICENSE)).
