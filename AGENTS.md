# AGENTS.md — sign-universal

Repo-level conventions for AI agents and contributors. Inherits the Zomp global
conventions; the notes below are additions or **explicit, temporary overrides**.

## Stack

- .NET, `net8.0` floor (LTS, broad CI reach). C# `LangVersion=preview`, `Nullable=enable`.
- Central Package Management (`Directory.Packages.props`); no inline `Version=` on `PackageReference`.
- Nerdbank.GitVersioning (`version.json` at root, `1.0-alpha`).
- Tests: TUnit + NSubstitute + FluentAssertions (pinned to the 7.x Apache-2.0 line).
- Default branch: **master**.

## Deliberate bootstrap deviations (remove before v1)

These are intentional and tracked, not oversights:

1. **`AnalysisMode=Recommended`**, not `AllEnabledByDefault` (Zomp default). Ratchet up
   once the surface stabilizes, then fix/justify each new diagnostic in `.editorconfig`.
1. **StyleCop ceremony rules relaxed** in `.editorconfig` (file headers, element docs,
   `this.` prefix, underscore-field naming). Each suppression carries a reason inline.

Package versions are now pinned exactly — a signing tool whose dependency graph can shift
between two builds of the same commit is not reproducible.

## Shipping

- **`net8.0` is the floor, not the ceiling.** `RollForward=LatestMajor` is set repo-wide
  in `Directory.Build.props` and must stay. Without it, anything executable — the tool a
  user installs, and the test host on a CI runner — refuses to start on a machine with
  only a newer runtime. CI runners carry exactly one runtime, so this fails immediately.
- **`fetch-depth: 0` in every CI job.** Nerdbank.GitVersioning derives the version from
  git height; a shallow clone silently produces the wrong one.
- **The Windows leg sets `SIGNUNIVERSAL_REQUIRE_SIGNTOOL=1`.** The signtool gate is the
  only check that can decide whether our Authenticode output is genuinely valid, and it
  runs nowhere else. With the variable set, a missing signtool fails the build instead of
  skipping the gate and going green.
- **Releases are signed by the build being released.** The `publish` job installs the
  packed tool and signs its own packages with it, then gates the push on
  `dotnet nuget verify`. Keep that ordering: sign, verify, then push.
- **Never register a certificate on the nuget.org account.** Trusted Signing rotates
  certificates every three days and nuget.org registers them by fingerprint, so ours can
  never match. Registering one would block publishing for every Zomp package.
- **The workflow runs under `act`.** It caught both roll-forward bugs before they ever
  reached a runner; run `act push -j pack --matrix os:ubuntu-latest` before touching CI.

## Security posture (non-negotiable)

- This is a **signing tool**. The private key must never be exported or logged. The
  only key operation in-process is `SignHash` over a digest, delegated to the backend
  (`IRemoteSigner`). `RemoteSigningRsa.ExportParameters(true)` must keep throwing.
- Every format's output must be gated by real Windows verification (`signtool /verify /pa`)
  in CI before it's considered done. jsign is the byte-diff oracle. Do not cut this.

## Format invariants (do not "simplify" these away)

Each of these was established against real Microsoft-signed binaries, not inferred from
the spec. They look like quirks; they are load-bearing.

1. **The encapsulated content is an OCTET STRING that has been retagged as a SEQUENCE.**
   `SignedCms` always writes `[0] { OCTET STRING v }`; Authenticode needs
   `[0] { SEQUENCE v }`. `AuthenticodeCms` converts between the two, and
   `VerifySignatureOnly` converts back before handing the blob to .NET.
1. **`messageDigest` covers the *value octets* of `SpcIndirectDataContent`**, not its
   full TLV — the direct consequence of the point above. This is why the builder passes
   the value octets to `ContentInfo`: it makes `SignedCms` compute exactly the digest
   Windows expects.
1. **`WIN_CERTIFICATE.dwLength` includes the 8-byte alignment padding**, and equals the
   data directory's `Size`. The PE spec's wording suggests otherwise; signtool does not.
1. **The digest skips bytes no section claims.** Hashing contiguously from
   `SizeOfHeaders` gives the same answer for ordinary compiler output and the wrong one
   otherwise.

1. **The RFC 3161 token lives under `1.3.6.1.4.1.311.3.3.1`**, Microsoft's own OID, not
   the `id-aa-timeStampToken` that ordinary CMS and NuGet use. The authority attests to
   the *signature value* in the signer info — not the file, not the signed attributes —
   so timestamping cannot disturb what it countersigns.

## NuGet packages: reuse, don't reimplement

The `.nupkg` path deliberately looks nothing like the Authenticode one. NuGet's client
libraries are cross-platform and are the format's reference implementation, so they do
the package hashing and the zip surgery; we supply only the CMS signature. Resist the
urge to hand-roll any of it.

1. **`SigningUtility.CreateCmsSigner` then `cmsSigner.PrivateKey = remoteRsa`.** NuGet
   builds the signer — identifier type, signed attributes, chain, digest algorithm — and
   we swap in the remote key. Building the `CmsSigner` ourselves would silently drift
   from whatever NuGet decides is correct.
1. **`SignPackageRequest.Dispose()` disposes the certificate you hand it.** Pass a copy,
   or the backend's certificate dies after one package and signing a directory fails on
   the second file.
1. **The timestamp is taken over the *hash* of the signature value**, not the signature
   value itself. Passing the raw value gets a bare HTTP 400 from the authority.
1. **`timestamp.acs.microsoft.com` does not work on a stock Linux agent.** Its responses
   omit the root, and *Microsoft Identity Verification Root CA 2020* is not in Ubuntu's
   trust store, so the chain cannot be built. The default is DigiCert for that reason.
1. **Use `Azure.Developer.TrustedSigning.CryptoProvider`, never
   `Microsoft.Trusted.Signing.Client`** — the latter ships a native signtool Dlib
   (MFC/MSVC) and is the reason `dotnet sign ... trusted-signing` cannot run on Linux.
1. **NuGet validates the signing certificate's chain against the machine trust store
   before it will sign, and an untrusted root is fatal.** Trusted Signing's root is not
   in Linux trust stores, so signing dies with a bare "Certificate chain validation
   failed". `--trust-signing-root` installs it for the current user. An untrusted root is
   only tolerated when the signing certificate is self-issued, which is why the
   self-signed test path never hits this.
1. **Feed the backend's chain into `SignPackageRequest.AdditionalCertificates`.** Without
   it the signature carries the leaf alone, the package verifies on the signing machine,
   and fails everywhere else. Same reasoning applies to `cmsSigner.Certificates` on the
   Authenticode side.

## Build & prove

```bash
dotnet build
dotnet run --project src/SignUniversal.Cli -- self-test   # must print PASS
dotnet run --project test/SignUniversal.Core.Tests        # TUnit suite

# Offline oracle: recompute digests of already-signed binaries and find each inside
# its own signature. Any directory of Microsoft-signed PEs will do.
python3 tools/authenticode-digest-reference.py --check ~/.nuget/packages
```
