# AGENTS.md - sign-universal

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

Package versions are now pinned exactly - a signing tool whose dependency graph can shift
between two builds of the same commit is not reproducible.

## Shipping

- **`net8.0` is the floor, not the ceiling.** `RollForward=LatestMajor` is set repo-wide
  in `Directory.Build.props` and must stay. Without it, anything executable - the tool a
  user installs, and the test host on a CI runner - refuses to start on a machine with
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
- **Registering the signing certificate on nuget.org is a per-release step, not a
  hazard.** An account with registered certificates makes the gallery enforce that pushes
  come from you. Trusted Signing's certificate is short-lived, so whichever one is current
  has to be registered as it rotates, and there is no API for it. `--export-certificate`
  writes out exactly the certificate that signed, which is what gets uploaded.
- **The workflow runs under `act`.** It caught both roll-forward bugs before they ever
  reached a runner; run `act push -j pack --matrix os:ubuntu-latest` before touching CI.

## Releasing

Run the **build** workflow from master with *Run workflow*. It packs, signs the packages
with Trusted Signing using the build being released, verifies them with
`dotnet nuget verify`, pushes to nuget.org, then creates the tag and GitHub Release.

- **The release signs itself.** The `publish` job installs the very build being released
  and signs with it, so a regression in signing breaks the release loudly instead of
  shipping broken signatures to everyone who installs the tool.
- **The tag is derived from the package, not typed.** Nerdbank.GitVersioning takes the
  version from `version.json` and git height, so a hand-written tag can claim a version the
  package does not have. Deriving it the other way round makes that impossible - and means
  the version lives in `version.json`, nowhere else.

## Layout

```text
src/SignUniversal.Core    signing engine
src/SignUniversal.Cli     dotnet tool, published as `SignUniversal` (`sign-universal`)
test/SignUniversal.Core.Tests
```

## Security posture (non-negotiable)

- This is a **signing tool**. The private key must never be exported or logged. The
  only key operation in-process is `SignHash` over a digest, delegated to the backend
  (`IRemoteSigner`). `RemoteSigningRsa.ExportParameters(true)` must keep throwing.
- Every format's output must be gated by real Windows verification (`signtool /verify /pa`)
  in CI before it's considered done. jsign is the byte-diff oracle. Do not cut this.

## Format invariants (do not "simplify" these away)

Each of these was established against real Microsoft-signed binaries, not inferred from
the spec. They look like quirks; they are load-bearing.

1. **`X509Certificate2.CopyWithPrivateKey` cannot be used.** On Linux it eagerly exports
   private parameters, which a remote key cannot provide. The private-key operation is
   delegated through `RemoteSigningRsa`, whose `SignHash` calls the backend, handed to the
   `CmsSigner(SubjectIdentifierType, certificate, privateKey)` overload. This is the
   assumption the whole design rests on, and `self-test` exists to prove it still holds.
1. **The encapsulated content is an OCTET STRING that has been retagged as a SEQUENCE.**
   `SignedCms` always writes `[0] { OCTET STRING v }`; Authenticode needs
   `[0] { SEQUENCE v }`. `AuthenticodeCms` converts between the two, and
   `VerifySignatureOnly` converts back before handing the blob to .NET.
1. **`messageDigest` covers the *value octets* of `SpcIndirectDataContent`**, not its
   full TLV - the direct consequence of the point above. This is why the builder passes
   the value octets to `ContentInfo`: it makes `SignedCms` compute exactly the digest
   Windows expects.
1. **`WIN_CERTIFICATE.dwLength` includes the 8-byte alignment padding**, and equals the
   data directory's `Size`. The PE spec's wording suggests otherwise; signtool does not.
1. **The digest skips bytes no section claims.** Hashing contiguously from
   `SizeOfHeaders` gives the same answer for ordinary compiler output and the wrong one
   otherwise.

1. **The RFC 3161 token lives under `1.3.6.1.4.1.311.3.3.1`**, Microsoft's own OID, not
   the `id-aa-timeStampToken` that ordinary CMS and NuGet use. The authority attests to
   the *signature value* in the signer info - not the file, not the signed attributes -
   so timestamping cannot disturb what it countersigns.

1. **MSI streams are ordered by the raw bytes of their UTF-16LE names**, not by ordinal
   string comparison. Ordinal compares 16-bit code units; the digest compares
   little-endian bytes, so the low half of each unit weighs first. MSI's mangled names sit
   in the range where the two orders genuinely differ.
1. **The MSI subject is `SpcSipInfo`, not `SpcPeImageData`**, and its first integer is
   **2**. One is the obvious guess and it is wrong.

## NuGet packages: reuse, don't reimplement

The `.nupkg` path deliberately looks nothing like the Authenticode one. NuGet's client
libraries are cross-platform and are the format's reference implementation, so they do
the package hashing and the zip surgery; we supply only the CMS signature. Resist the
urge to hand-roll any of it.

1. **`SigningUtility.CreateCmsSigner` then `cmsSigner.PrivateKey = remoteRsa`.** NuGet
   builds the signer - identifier type, signed attributes, chain, digest algorithm - and
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
   `Microsoft.Trusted.Signing.Client`** - the latter ships a native signtool Dlib
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

# The suite skips three checks unless you opt in. Each needs something the machine
# may not have: a corpus of signed binaries, and a reachable timestamp authority.
SIGNUNIVERSAL_PE_CORPUS=~/.nuget/packages \
  SIGNUNIVERSAL_TIMESTAMP_TESTS=1 \
  dotnet run --project test/SignUniversal.Core.Tests
```
