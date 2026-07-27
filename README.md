# sign-universal

Cross-platform [Authenticode](https://learn.microsoft.com/windows-hardware/drivers/install/authenticode) code signing for .NET — sign Windows binaries (PE) and installers (MSI) from **Linux, macOS, or Windows**, with the private key held in **Azure Key Vault** or **Azure Trusted Signing** (the key never leaves the HSM).

> **Status: early bootstrap.** The signing engine is not implemented yet. What exists today is the project skeleton plus a **working proof** that the hardest architectural assumption holds on Linux (see below). `sign` is a no-op; `self-test` is real.

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

## Roadmap

| Milestone | What | Notes |
|---|---|---|
| ✅ Spike | remote-key → `SignedCms` on Linux | done — `self-test` |
| ASN.1 | `SpcIndirectData` full `SpcLink` | partial today (digest is real) |
| Azure | `IRemoteSigner` for Key Vault + Trusted Signing | `CryptographyClient` + `DefaultAzureCredential` |
| PE | Authenticode hash + cert-table embed | PE32/PE32+; page hashes deferred |
| MSI | compound-file digest + signature streams | container via OpenMcdf |
| Timestamp | RFC 3161 (+ legacy Authenticode) | RFC 3161 is mostly in-box |
| Verify | `signtool /verify` harness in CI | correctness gate — never cut |

Out of scope for v1: MSIX/APPX, CAB, scripts, non-Azure KMS.

## Layout

```
src/SignUniversal.Core    signing engine (BCL-only today)
src/SignUniversal.Cli     dotnet tool (`sign-universal`)
test/SignUniversal.Core.Tests
```

## Prior art & credit

Design and format handling are informed by **jsign** (Apache-2.0) — see [`NOTICE`](NOTICE). Licensed Apache-2.0 (see [`LICENSE`](LICENSE)).
