# TRON Direct Enforcement — MSIX packaging (SignPath, self-distribution)

Draft packaging scaffold. **Not releasable yet** — see TODOs below.

## What's here

- `AppxManifest.xml` — draft manifest for `TronDirectEnforcer.exe` (full-trust Win32,
  `runFullTrust` + `allowElevation`). Identity `Name` and `Publisher` are explicit
  `TODO` placeholders; the Publisher MUST exactly match the SignPath signing
  certificate's Subject.

## TODOs (need Long)

1. Confirm the stable MSIX **Identity Name** (candidate seen: `TronDirectEnforcement`).
2. Register the repo at **signpath.io**; record the **project slug**.
3. Provide the signing certificate's complete **Subject** → set as `Publisher` and
   `PublisherDisplayName`.

## Build & pack steps (Windows, when TODOs are resolved)

1. Fresh build from the pinned, validated commit (`da94e83b950c` or newer pinned):
   run `build.ps1` (offline; refuses network/download). Do NOT package the
   2026-09-19 preview ZIP without provenance validation.
2. Layout: `packaging/layout/TronDirectEnforcer.exe` + `Assets\` logos +
   `AppxManifest.xml` at the layout root.
3. `MakeAppx pack /d packaging/layout /p TronDirectEnforcement.msix`
4. Submit the unsigned `.msix` to SignPath; install the signed result for validation
   per `VALIDATION-PLAN.md`.

## Guardrails

- Source updates only. No signed release is produced or published from this branch.
- No purchases, no account changes, no trust/policy changes.
- `Assets\` logos are still missing (referenced by the manifest) — add before packing.
