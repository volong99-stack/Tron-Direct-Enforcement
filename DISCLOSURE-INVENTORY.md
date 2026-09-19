# Source disclosure inventory

The exact public source allowlist is `RELEASE-FILES.json`. The standalone source is approved for publication under MIT. The current developer-preview scope also permits the exact archive and sidecar lists in that manifest. Everything else remains excluded.

| File | Disclosed content |
| --- | --- |
| `TronDirectEnforcer.cs` | Generic administrator attestation and firewall code, fixed product directory/rule names, supported threat categories, safety gates, state formats and limitations. No operating installation values are embedded. |
| `TronDirectEnforcerPureTests.cs` | Synthetic test logic, fictional device/account identifiers, illustrative public/private IPs and generic executable paths. No network requests or real threat evidence are present in these fixtures. |
| `AssemblyInfo.cs` | Generic product identity and retained candidate version metadata; publisher and copyright assembly strings are empty. |
| `build.ps1` | Fixed local compiler verification and build procedure. No account, remote service, credentials, machine-specific profile paths or policy bypass. |
| `config.disabled.example.json` | Configuration field names with placeholders, disabled authorization and empty target pins/allowlist. |
| `README.md` | Generic design, build procedure, trust limitations and actual validation/signing status. |
| `LICENSE` | Operative MIT license with generic project-contributor attribution. |
| `RELEASE-FILES.json` | Exact source/preview file lists and exclusion/signing flags. |
| `.gitignore` | Exclusions for generated files and signing keys. |
| `.github/workflows/developer-preview.yml` | Public CI/release procedure, pinned action identities and repository name. |
| `ci/PreviewTests.cs` | Standard-token verification and refusal probes; no installation or firewall mutation. |
| `ci/Test-Preview.ps1` | Disposable-runner standard-account setup, test execution and account removal; random credentials are never published. |
| `ci/Package-Preview.ps1` | Exact preview file selection, checksums and sanitized validation summary. |
| `PREVIEW.md`, `VALIDATION-PLAN.md` | Download verification, test scope, feedback guidance and outstanding runtime validation. |
| `DISCLOSURE-INVENTORY.md` | This description of disclosed and excluded material. |

Excluded: real device IDs, machine GUIDs, account SIDs, user names, home-network topology or addresses, credentials, pairing/session tokens, signing keys, health reports, sensor data, threat evidence, deployment history, private prompts or chat transcripts, actual policy/configuration, remote access instructions, operating logs, screenshots, private release archives and private repository configuration.

Raw `build/` output remains excluded. The reviewed developer-preview exception permits only the two executables built from public source, license, README, PREVIEW guide, disabled example configuration and sanitized VALIDATION summary. The archive is accompanied by SHA-256 checksums and a GitHub attestation bundle. Validation metadata discloses only commit/run identifiers, counts and explicit limitations; it contains no runner usernames, device identifiers, credentials or operational records. This exception does not permit recursively publishing build directories, compiler logs, build receipts, test-driver binaries or private records.

Fictional fixture addresses, standard Windows security identifiers and generic Windows product paths are intentional. They are explanatory/test inputs, not statements about an operating installation. No successful runtime deployment, provider sponsorship or open-source reputation is asserted.
