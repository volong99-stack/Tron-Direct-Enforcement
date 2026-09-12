# Source disclosure inventory

The exact public source whitelist is `RELEASE-FILES.json`. The standalone source is approved for publication under MIT. Files outside that list remain excluded and require their own review before release.

| File | Disclosed content |
| --- | --- |
| `TronDirectEnforcer.cs` | Generic administrator attestation and firewall code, fixed product directory/rule names, supported threat categories, safety gates, state formats and limitations. No operating installation values are embedded. |
| `TronDirectEnforcerPureTests.cs` | Synthetic test logic, fictional device/account identifiers, illustrative public/private IPs and generic executable paths. No network requests or real threat evidence are present in these fixtures. |
| `AssemblyInfo.cs` | Generic product identity and retained candidate version metadata; publisher and copyright assembly strings are empty. |
| `build.ps1` | Fixed local compiler verification and build procedure. No account, remote service, credentials, machine-specific profile paths or policy bypass. |
| `config.disabled.example.json` | Configuration field names with placeholders, disabled authorization and empty target pins/allowlist. |
| `README.md` | Generic design, build procedure, trust limitations and actual validation/signing status. |
| `LICENSE` | Operative MIT license with generic project-contributor attribution. |
| `RELEASE-FILES.json` | This exact source-file list and exclusion/signing flags. |
| `DISCLOSURE-INVENTORY.md` | This description of disclosed and excluded material. |

Excluded: real device IDs, machine GUIDs, account SIDs, user names, home-network topology or addresses, credentials, pairing/session tokens, signing keys, health reports, sensor data, threat evidence, deployment history, private prompts or chat transcripts, actual policy/configuration, remote access instructions, operating logs, screenshots, private release archives and private repository configuration.

Any `build/` output created later is excluded from this source whitelist, including binaries, raw compiler logs and build receipts. Such artifacts need their own reproducibility, privacy, signing and runtime review before release.

Fictional fixture addresses, standard Windows security identifiers and generic Windows product paths are intentional. They are explanatory/test inputs, not statements about an operating installation. No successful runtime deployment, provider sponsorship or open-source reputation is asserted.
