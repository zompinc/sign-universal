# Moving a signing job off Windows

Handoff notes for a repository that signs NuGet packages with Azure Trusted Signing on a
`windows-latest` runner, and wants to stop. Written against
[`sync-method-generator`](https://github.com/zompinc/sync-method-generator), whose
pipeline is the shape this was built for, but nothing here is specific to it.

## Why the Windows job exists today

Two separate limitations put it there, and both are now avoidable:

- **`dotnet sign` supports Trusted Signing but cannot run on Linux.** Its backend,
  `Microsoft.Trusted.Signing.Client`, ships a native signtool Dlib with MFC/MSVC
  dependencies.
- **`dotnet nuget sign` runs anywhere but needs a local private key**, which a key in
  Trusted Signing does not have.

`sign-universal` sits in the gap: NuGet's own signing pipeline with the private-key
operation redirected to Trusted Signing over HTTPS.

## The change

The `sign` job keeps its name, its inputs, and its outputs. Only the runner and the
signing command change, so `publish` - which consumes `packages-signed` - needs no edit.

```diff
   sign:
     needs: build
     if: ${{ github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository }}
-    runs-on: windows-latest
+    runs-on: ubuntu-latest
     defaults:
       run:
         shell: bash

     steps:
-      - name: Set path for nektos/act
-        if: ${{ runner.os == 'Windows' && env.ACT }}
-        run: echo "C:\Program Files\Git\bin" >> $GITHUB_PATH
-        shell: '"C:\Program Files\Git\bin\bash.exe" -c {0}'
-
-      - name: "Determine prerequisites"
-        id: prerequisite
-        run: |
-          echo "need_node=$(command -v node >/dev/null 2>&1 && echo 0 || echo 1)" >> $GITHUB_OUTPUT
-
-      - name: Install node
-        if: ${{ steps.prerequisite.outputs.need_node == '1' }}
-        run: |
-          ...
-
       - name: Setup .NET
         uses: actions/setup-dotnet@v5
         with:
           dotnet-version: |
             10.0.x

       - name: Download Package artifact
         uses: actions/download-artifact@v5
         with:
           name: packages
           path: packages

+      - name: Install the signing tool
+        run: dotnet tool install --global SignUniversal --prerelease
+
       - name: Sign
         env:
           AZURE_TENANT_ID: ${{ secrets.AZURE_TENANT_ID }}
           AZURE_CLIENT_SECRET: ${{ secrets.AZURE_SIGNER_CLIENT_SECRET }}
           AZURE_CLIENT_ID: ${{ secrets.AZURE_SIGNER_CLIENT_ID }}
         if: ${{ env.AZURE_CLIENT_SECRET != '' && github.ref == 'refs/heads/master' }}
         run: |
-          dotnet dnx --prerelease --yes sign code trusted-signing \
-          --base-directory "${{ github.workspace }}/packages" \
-          "*.nupkg" \
-          --trusted-signing-endpoint "${{ secrets.TRUSTED_SIGNING_ENDPOINT }}" \
-          --trusted-signing-account "${{ secrets.TRUSTED_SIGNING_ACCOUNT }}" \
-          --trusted-signing-certificate-profile "${{ secrets.TRUSTED_SIGNING_CERTIFICATE_PROFILE }}" \
-          -v normal
+          sign-universal sign packages/*.nupkg --trust-signing-root \
+            --trusted-signing-endpoint "${{ secrets.TRUSTED_SIGNING_ENDPOINT }}" \
+            --trusted-signing-account "${{ secrets.TRUSTED_SIGNING_ACCOUNT }}" \
+            --trusted-signing-certificate-profile "${{ secrets.TRUSTED_SIGNING_CERTIFICATE_PROFILE }}"
+
+      - name: Verify what was signed
+        if: ${{ env.AZURE_CLIENT_SECRET != '' && github.ref == 'refs/heads/master' }}
+        env:
+          AZURE_CLIENT_SECRET: ${{ secrets.AZURE_SIGNER_CLIENT_SECRET }}
+        run: |
+          for package in packages/*.nupkg; do
+            dotnet nuget verify "$package" --all
+          done

       - name: Upload artifacts (.nupkg)
         uses: actions/upload-artifact@v5
         with:
           name: packages-signed
           path: packages/
```

The same `AZURE_*` variables work unchanged: `DefaultAzureCredential` reads them exactly
as the previous tool did. Node is no longer needed by this job.

## Two things that will bite you otherwise

**`--trust-signing-root` is not optional on Linux.** Without it, signing fails with
nothing but `Certificate chain validation failed`. NuGet validates the signing
certificate's chain against the machine's trust store before it will sign, and an
untrusted root is fatal. Trusted Signing issues from *Microsoft Identity Verification Root
Certificate Authority 2020*, which Linux trust stores do not carry - Ubuntu ships only the
Microsoft 2017 roots. Windows agents never hit this, which is why the requirement is
invisible until the job moves. The flag installs that root into the **current user's**
store only, taking it from the chain the signing service itself returned over an
authenticated connection.

Consumers need nothing: `dotnet nuget verify` validates against NuGet's own root bundle,
which already contains that root.

**Do not use `timestamp.acs.microsoft.com`.** Microsoft documents it for Trusted Signing,
and it does not work on a stock Linux agent: its responses carry only the leaf and
intermediate, and the root they chain to is the same one Ubuntu does not have, so the
chain cannot be built and signing fails outright. The default is DigiCert, whose responses
include a full chain to a root Ubuntu already trusts. Override with `--timestamper` only if
you have installed that root.

Timestamping is on by default and should stay on: Trusted Signing certificates live about
three days, so an untimestamped signature expires almost immediately.

## Verifying the switch worked

`dotnet nuget verify` should exit **0** on the signed packages - a full pass, chain and
timestamp included. That is what the added step above checks, and it is worth keeping: it
fails the build if a signature is ever produced that nobody downstream could validate.

A signed package should show:

```
Signature type: Author
  Subject Name: CN=Zomp Inc., O=Zomp Inc., L=Toronto, S=Ontario, C=CA
```

## Rolling back

Revert the job. Nothing else in the pipeline changes, the artifact names are the same, and
the produced signatures are ordinary NuGet author signatures - packages signed by either
tool are indistinguishable to consumers.

## One standing hazard, unrelated to this change

**Never register a certificate on the nuget.org account.** Trusted Signing rotates
certificates every three days and nuget.org registers signing certificates by SHA-256
fingerprint, so a Trusted Signing certificate can never be registered
([NuGetGallery#10027](https://github.com/NuGet/NuGetGallery/issues/10027)). Pushing signed
packages works today only because the account has *no* registered certificates. The moment
one is registered, every future push must be signed with it - and these signatures never
will be, which would block publishing for every package on that account.

## Status of the tool

It signs NuGet packages, Windows PE binaries, and MSI packages, all timestamped, with keys
in Trusted Signing or Key Vault. Every format is gated in CI by the verifier that decides:
`signtool verify /pa` on Windows for PE and MSI, `dotnet nuget verify` for packages.

It is versioned `1.0.x-alpha` and has not been used by anyone outside its own repository.
The NuGet path is the best-exercised: it is what the tool was built for, it is verified
against a live Trusted Signing account, and `sign-universal` signs its own releases with
it. Treat the first run here as a test - check the artifact before it is published, not
after.
