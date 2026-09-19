# TRON developer preview

This is an unsigned development build for source review and controlled testing.
It is not a production security product. No signing provider has approved it.

## What the preview validates

The recorded GitHub run compiles both executables with the installed,
signature-verified Microsoft .NET Framework compiler. It runs the synthetic
in-memory harness under a temporary standard-user account on a disposable
GitHub-hosted Windows runner. A separate driver checks that its real Windows
token is non-administrative and that eight operations refuse to run from the
uninstalled preview, including rejection of installation by an ordinary user.

The release's `VALIDATION.json` records the exact source commit, run URL, test
counts, and remaining validation gaps. Check the linked run for success.

These checks do not validate live network blocking, an installed controller's
privilege boundary, scheduled cleanup, crash/reboot/update recovery, or genuine
authenticated external reviews. Synthetic fixtures are not actual threat
evidence or model confirmations. No firewall rule is created by these tests.

## Verify a download

Obtain the ZIP, `SHA256SUMS.txt`, and `attestation.sigstore.json` from the same
[GitHub prerelease](https://github.com/volong99-stack/Tron-Direct-Enforcement/releases).
Use a current, independently obtained GitHub CLI. Replace `ZIP_NAME` and
`FULL_COMMIT_SHA` below with the release's archive name and full 40-character
source commit. Run verification before extraction:

```powershell
gh attestation verify .\ZIP_NAME --repo volong99-stack/Tron-Direct-Enforcement --bundle .\attestation.sigstore.json --signer-workflow volong99-stack/Tron-Direct-Enforcement/.github/workflows/developer-preview.yml --source-digest FULL_COMMIT_SHA --source-ref refs/heads/main --deny-self-hosted-runners
Get-FileHash -LiteralPath .\ZIP_NAME -Algorithm SHA256
```

The attestation verification must succeed for the expected repository, workflow,
and source commit. Compare the printed SHA-256 with `SHA256SUMS.txt` as an
additional integrity check. A checksum downloaded beside a file is not, by
itself, proof of its publisher. Attestations identify the build's origin; they
are not an Authenticode certificate or a guarantee of code safety.

## Development testing

After verification, extract into an empty development directory. The archive
contains only the two unsigned executables, license, README, this guide, a
disabled example configuration, and the validation summary.

In a permitted Windows test environment, a standard user can run:

```powershell
.\TronDirectEnforcerPureTests.exe
```

Expect exit code zero and a JSON line with `status` equal to `PURE_TESTS_PASSED`.
Do not run the harness as administrator. Do not use the enforcer executable to
protect a working computer: the preview supplies no installer or real runtime
configuration. The placeholder configuration has authorization disabled and
empty executable pins. Do not interpret the refusal probes as installed-system
security validation.

Windows may warn about or block unsigned executables, including locally built
ones. Keep SmartScreen, Smart App Control, antivirus, and application-control
policies enabled. If a policy blocks the preview, stop and use a development
environment that permits it. No bypass or certificate installation is required
by this preview.

## Reporting useful feedback

For a build or pure-test problem, open a GitHub issue with the release commit,
Windows version, test count/error code, and minimal reproduction steps. Redact
personal paths and account names. Do not attach real device IDs, configuration,
network addresses, credentials, journals, audit logs, or threat evidence.

## Release procedure and cost

The `Developer preview` workflow checks pull requests and `codex/free-preview-*`
branches. Each successful build on `main` publishes a uniquely tagged GitHub
prerelease after testing, packaging, attestation, and attestation verification.
Existing release tags/assets are never overwritten. Review changes before
merging to `main`; a main-branch push is the release trigger.

Only standard `windows-2022` GitHub-hosted runners are used. There are no paid
services, larger runners, package-registry uploads, signing certificates, or
retained Actions artifact uploads. Build directories stay on disposable
runners; approved ZIPs and attestation bundles are GitHub Release assets.
Public-repository standard runner use and public artifact attestations are
available with GitHub Free, subject to GitHub's service limits and terms.

Reapplying to SignPath requires actual validation, independent feedback, and
community adoption. Do not report a CI run as evidence of users or endorsement.
See [VALIDATION-PLAN.md](VALIDATION-PLAN.md) for remaining runtime work.
