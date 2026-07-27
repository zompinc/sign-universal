# sign-universal

Cross-platform [Authenticode](https://learn.microsoft.com/windows-hardware/drivers/install/authenticode) code signing for .NET — sign Windows binaries (PE) and installers (MSI) from **Linux, macOS, or Windows**, with the private key held in **Azure Key Vault** or **Azure Trusted Signing** (the key never leaves the HSM).

> **Status: early.** PE signing works end to end — `sign-universal sign app.exe --pfx key.pfx` embeds a real Authenticode signature, from Linux. Azure Key Vault / Trusted Signing backends, MSI, and timestamping are still ahead, and the `signtool` gate only runs on Windows.

## Why this exists

The official [`dotnet/sign`](https://github.com/dotnet/sign) tool is Windows-only by design (it delegates Authenticode to `wintrust`/`mssign32`). Building on Linux CI and needing to sign Windows artifacts today means standing up a separate Windows job. [`jsign`](https://github.com/ebourg/jsign) solves the same problem cross-platform and is excellent — but requires a JVM. `sign-universal` targets the one gap that leaves: a **.NET-native, zero-JVM `dotnet tool`** with the same cloud-key story.

The Authenticode *format* is OS-agnostic; only the Windows APIs that produce it are not. .NET's own crypto stack (`System.Security.Cryptography.Pkcs`, `System.Formats.Asn1`, `Rfc3161TimestampRequest`) runs everywhere — so a managed implementation is feasible.

## The de-risked core

The whole design rests on one question: **can you produce a valid Authenticode PKCS#7 signature on Linux when the private key is remote (Key Vault) and never present in-process?** Answer, proven by `self-test`: **yes.**

```bash
dotnet run --project src/SignUniversal.Cli -- self-test
# PASS: remote-key signing produced a valid PKCS#7 SignedData; the private key never left the signer.
```

Two findings the spike locked in:

1. The private-key operation is delegated through a custom `RSA` (`RemoteSigningRsa`) whose `SignHash` calls the backend; everything else is stock `SignedCms`/`CmsSigner`.
1. **`X509Certificate2.CopyWithPrivateKey` cannot be used** — on Linux it eagerly exports private parameters, which a remote key can't provide. Use the `CmsSigner(SubjectIdentifierType, certificate, privateKey)` overload, which signs via the key's `SignHash`.

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
| Azure | `IRemoteSigner` for Key Vault + Trusted Signing | `CryptographyClient` + `DefaultAzureCredential` |
| MSI | compound-file digest + signature streams | container via OpenMcdf |
| Timestamp | RFC 3161 (+ legacy Authenticode) | RFC 3161 is mostly in-box |
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
1. **`signtool verify /pa`** on Windows — the gate that actually decides.

## Layout

```
src/SignUniversal.Core    signing engine (BCL-only today)
src/SignUniversal.Cli     dotnet tool (`sign-universal`)
test/SignUniversal.Core.Tests
```

## Prior art & credit

Design and format handling are informed by **jsign** (Apache-2.0) — see [`NOTICE`](NOTICE). Licensed Apache-2.0 (see [`LICENSE`](LICENSE)).
