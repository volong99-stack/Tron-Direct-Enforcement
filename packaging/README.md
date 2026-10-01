# TRON Direct Enforcement — packaging

## Decided route (2026-10-01, Long): local install on his own computers

- **Self-signed certificate**, installed into the trusted store of each machine
  (QSM and R97). No paid certificate, no SignPath reapply for now.
- Build once, install on **all** his computers.

### Steps (Windows)

1. Fresh build from the pinned, validated commit (`da94e83b950c` or newer pinned):
   run `build.ps1` (offline; refuses network/download). Do NOT package the
   2026-09-19 preview ZIP without provenance validation.
2. Layout: `packaging/layout/TronDirectEnforcer.exe` + `Assets\` logos +
   `AppxManifest.xml` at the layout root.
   - Identity Name: `TronDirectEnforcer` (local-only; reinstall to rename).
   - Publisher: must exactly match the self-signed certificate's Subject
     (e.g. `CN=TRON Local`).
3. `MakeAppx pack /d packaging/layout /p TronDirectEnforcement.msix`
4. On **each** target machine:
   - Install the self-signed `.cer` into `Local Machine > Trusted People`
     (or Trusted Root) via an elevated prompt.
   - `Add-AppxPackage .\TronDirectEnforcement.msix`
5. Verify: app installed, launches, enforcement engine initializes
   per `VALIDATION-PLAN.md`.

To create the self-signed cert (once, on the build machine):

```powershell
$cert = New-SelfSignedCertificate -Type Custom -Subject "CN=TRON Local" `
  -KeyUsage DigitalSignature -FriendlyName "TRON Local Signing" `
  -CertStoreLocation "Cert:\CurrentUser\My" `
  -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3", "2.5.29.19={text}")
```

Sign the package before installing:

```powershell
SignTool sign /fd SHA256 /a /f tron-local.pfx /p <password> TronDirectEnforcement.msix
```

## What's in this branch

- `packaging/AppxManifest.xml` — draft manifest for `TronDirectEnforcer.exe`
  (full-trust Win32, `runFullTrust` + `allowElevation`). Identity `Name` and
  `Publisher` are filled for the local-install route; re-verify if the signing
  route ever changes.
- `Assets\` logos are still missing — add before packing.

## Parked: SignPath Foundation (rejected 2026-09-16)

The free OSS application was rejected on public-visibility grounds (needs GitHub
stars/forks/contributors, external articles/discussions, institutional backing,
sustained activity). Reapplication is welcome once the project has broader
recognition. Paid alternatives if distribution with trust is ever needed:
SignPath subscription, Azure Artifact Signing (~$9.99/mo), or a purchased OV
cert (~$100–200/yr).

## Guardrails

- Source updates only. No signed release is produced or published from this branch.
- No purchases, no account changes, no trust/policy changes beyond installing
  Long's own self-signed cert on his own machines.
