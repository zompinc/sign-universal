# Signing NuGet packages without a Windows runner

For a pipeline that signs with Azure Trusted Signing on `windows-latest` and would rather
not.

## Why the Windows runner is there

Two limitations put it there, and both are avoidable:

- **`dotnet sign` supports Trusted Signing but only runs on Windows.** Its backend,
  `Microsoft.Trusted.Signing.Client`, ships a native signtool Dlib with MFC/MSVC
  dependencies.
- **`dotnet nuget sign` runs anywhere but needs a local private key**, which a key in
  Trusted Signing does not have.

`sign-universal` is NuGet's own signing pipeline with the private-key operation redirected
to Trusted Signing over HTTPS, so neither limitation applies.

## The change

Move the job to Linux:

```diff
-    runs-on: windows-latest
+    runs-on: ubuntu-latest
```

and swap the signing command:

```diff
-          dotnet dnx --prerelease --yes sign code trusted-signing \
-            --base-directory "$GITHUB_WORKSPACE/packages" "*.nupkg" \
+          dotnet dnx SignUniversal.Cli@1.0.34 --yes sign packages/*.nupkg \
+            --trust-signing-root \
             --trusted-signing-endpoint "${{ secrets.TRUSTED_SIGNING_ENDPOINT }}" \
             --trusted-signing-account "${{ secrets.TRUSTED_SIGNING_ACCOUNT }}" \
             --trusted-signing-certificate-profile "${{ secrets.TRUSTED_SIGNING_CERTIFICATE_PROFILE }}"
```

`dotnet dnx` runs a tool without installing it, the same way the previous command did, so
no separate install step is needed. Pin the version: the thing signing your releases should
not change unless you choose to change it. (`dotnet tool install --global SignUniversal.Cli`,
or a `dotnet-tools.json` manifest with `dotnet tool restore`, work equally well if the
pipeline already uses one of those.)

Credentials are unchanged. `DefaultAzureCredential` reads the same `AZURE_TENANT_ID`,
`AZURE_CLIENT_ID` and `AZURE_CLIENT_SECRET` the previous tool did.

Anything the job carried only to satisfy Windows - a Node install, a Git-bash path shim,
`shell:` overrides - can go with it.

It will probably get quicker, by an amount that depends on what else the job does. Signing
is much the same speed on either platform; what goes away is Windows runner startup, about
48s against 10s. A job that only signs gains nearly all of that - `Zomp.SyncMethodGenerator`
went from 51-90s to 10-12s. A job that also pushes packages gains less -
`Zomp.EFCore.BinaryFunctions` went from 41s to 36s, while gaining a verification step.
Windows minutes are billed at twice the rate regardless.

## Two things that will otherwise cost you an afternoon

**`--trust-signing-root` is not optional on Linux.** Without it, signing fails with nothing
but `Certificate chain validation failed`. NuGet validates the signing certificate's chain
against the machine's trust store before it will sign, and an untrusted root is fatal.
Trusted Signing issues from *Microsoft Identity Verification Root Certificate Authority
2020*, which Linux trust stores do not carry - Ubuntu ships only the Microsoft 2017 roots.
Windows agents never hit this, which is why the requirement is invisible until the job
moves. The flag installs that root for the current user only, taking it from the chain the
signing service itself returned over an authenticated connection.

Consumers need nothing: `dotnet nuget verify` validates against NuGet's own root bundle,
which already contains that root.

**Do not use `timestamp.acs.microsoft.com`.** Microsoft documents it for Trusted Signing
and it does not work on a stock Linux agent: its responses carry only the leaf and
intermediate, and the root they chain to is the same one Ubuntu does not have. The default
is DigiCert, whose responses include a full chain to a root Ubuntu already trusts. Override
with `--timestamper` only if you have installed the Microsoft root.

Timestamping is on by default and should stay on. Trusted Signing certificates live about
three days, so an untimestamped signature expires almost immediately.

## Check the result

Add a verification step after signing, if the pipeline does not already have one:

```yaml
- name: Verify signature
  run: dotnet nuget verify packages/*.nupkg --all
```

It should exit **0** - a full pass, chain and timestamp included. That fails the build if a
signature is ever produced that nobody downstream could validate, while the package can
still be thrown away. `dotnet nuget verify` is cross-platform, so this needs nothing
Windows-specific.

## Registering the certificate on nuget.org

Unrelated to this change, but part of the same release day. If the nuget.org account has
registered certificates, the gallery requires every push to be signed with one of them.
Trusted Signing's certificate is short-lived, so whichever one is current has to be
registered as it rotates, and there is no API for it
([NuGetGallery#10027](https://github.com/NuGet/NuGetGallery/issues/10027)).

Signing with `--export-certificate` writes out exactly the certificate that signed, so
there is no need to extract it from the package afterwards:

```bash
dotnet dnx SignUniversal.Cli@1.0.34 --yes sign packages/*.nupkg \
  --trust-signing-root --export-certificate signing.cer \
  --trusted-signing-endpoint "..." --trusted-signing-account "..." \
  --trusted-signing-certificate-profile "..."
```

Upload `signing.cer` under Account settings -> Certificates before pushing. A long-lived
certificate in Key Vault avoids the repetition, at the cost of managing renewals yourself:
`--key-vault-url` and `--key-vault-certificate` take that path instead.

## Rolling back

Revert the change. Artifact names and job structure are untouched, and the signatures are
ordinary NuGet author signatures: a package signed either way is indistinguishable to
whoever installs it.

## Status

Signs NuGet packages, Windows PE binaries and MSI packages, all timestamped, with keys in
Trusted Signing or Key Vault. Every format is gated in CI by the verifier that decides:
`signtool verify /pa` on Windows for PE and MSI, `dotnet nuget verify` for packages.

In production use: `sign-universal` signs its own releases, and
[`Zomp.SyncMethodGenerator`](https://www.nuget.org/packages/Zomp.SyncMethodGenerator) is
published this way from an Ubuntu runner.
