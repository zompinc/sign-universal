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
1. **Floating package versions** (`CentralPackageFloatingVersionsEnabled=true`). Pin to
   exact versions before v1 for reproducible builds.
1. **StyleCop ceremony rules relaxed** in `.editorconfig` (file headers, element docs,
   `this.` prefix, underscore-field naming). Each suppression carries a reason inline.

## Security posture (non-negotiable)

- This is a **signing tool**. The private key must never be exported or logged. The
  only key operation in-process is `SignHash` over a digest, delegated to the backend
  (`IRemoteSigner`). `RemoteSigningRsa.ExportParameters(true)` must keep throwing.
- Every format's output must be gated by real Windows verification (`signtool /verify /pa`)
  in CI before it's considered done. jsign is the byte-diff oracle. Do not cut this.

## Build & prove

```bash
dotnet build
dotnet run --project src/SignUniversal.Cli -- self-test   # must print PASS
```
