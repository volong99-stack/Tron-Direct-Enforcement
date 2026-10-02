# TRON Direct Enforcement

**Experimental MIT-licensed developer preview. Public preview artifacts remain unsigned; verified local signed deployments are documented below. Not runtime-validated for production.** Public source availability does not establish signing-provider acceptance, verified adoption or reputation, or readiness to protect a computer.

The native adapter accepts an explicit, elevated administrator-controller attestation before adding one narrow outbound Windows firewall rule. The authority is named `ADMIN_CONTROLLER_ATTESTATION`; it is not a cryptographic proof that an AI review occurred. The caller must independently witness a real Codex review and make a separate current ChatGPT controller decision about the exact technical evidence and proposed action. That authenticated end-to-end review integration is not supplied or validated by this standalone source release. The native layer checks the administrator token, pinned controller identity, bound metadata, scope, freshness, replay state and executable identity. It cannot authenticate external transcripts or establish the truth of evidence from its hashes. This project is not affiliated with or endorsed by Microsoft or OpenAI.

Only supported confirmed technical-threat categories are accepted. Content claims, opinions and unknown devices do not qualify. A rule is limited to one existing administrator-pinned executable SHA-256 and one canonical public IPv4 destination on one device. Private/reserved addresses, broad destination ranges, Windows executables and management tools are excluded. Empty executable pins deny every new rule.

There is no incoming directory, untrusted receipt ingestion, signing key or background apply service. The optional SYSTEM scheduled task runs only native cleanup. Explicit apply/arm calls require the configured authenticated elevated non-SYSTEM controller in a user session. Durable reservations and an initialized history checkpoint are designed to detect missing or truncated authorization history; removal requires a fully matched owned rule. Cleanup also checks whether an active rule's destination has become protected by the current configuration. Clock faults prevent new creation while cleanup attempts safe exact removal. Expiry depends on execution of the cleanup task; it is not an operating-system-enforced TTL.

Windows firewall rules are path-based. The adapter verifies the current file under a read handle during application, then checks identity again during cleanup. This does not prove the identity of an already running process or permanently bind a firewall rule to file bytes. Native rule readback also does not prove actual network blocking; controlled traffic tests are required.

## Inert staging candidate

Candidate `0.1.0.2` adds a separate bounded staging journal. `init-staging`, `stage`, `show-stage` and `cancel-stage` return before native firewall initialization and never change executable pins or active authorizations. A hash-only target remains inert without a local executable. See [STAGING.md](STAGING.md) for exact schemas, failure handling and deployment gates.

New blocks require `activate` with a fresh, separately recorded Long approval, a matching unexpired staged record and all existing executable, review, controller, replay and health checks. The old `apply` command rejects new creation; version 1 authorizations remain readable for cleanup and rollback. The operational Codex/ChatGPT review requirements remain unchanged. Staged evidence and privileged approval fields are assertions, not authenticated proof of a chat or a threat. This candidate is unbuilt and undeployed pending both code reviews and full tests; the signed `0.1.0.1` deployment documented below is a different artifact.

## Files and build

`RELEASE-FILES.json` is the exact source-file whitelist. `DISCLOSURE-INVENTORY.md` describes what those files disclose. The separate `previewArchiveFiles` list permits only the documented developer-preview archive contents. Raw build receipts/logs, credentials, runtime configuration, deployment data and operating records remain excluded. The owner-approved local signed-deployment summary below is the only deployment disclosure added here. See [PREVIEW.md](PREVIEW.md) for verification and [VALIDATION-PLAN.md](VALIDATION-PLAN.md) for remaining runtime work.

`build.ps1` uses only the installed Microsoft .NET Framework C# compiler and local framework references. It locates the fixed framework installation under the Windows directory, rejects reparse paths, and requires a valid Microsoft compiler signature and matching compiler identity. It refuses an existing build-output directory. It does not download tools, change execution policy, request elevation, sign files, execute either result, install components, or publish anything.

When local policy permits ordinary PowerShell script execution, invoke it from its directory with `./build.ps1`. If policy refuses the script or generated programs, stop and use a separately approved build/validation environment. Do not weaken or bypass application-control or script policies to run this candidate.

Production output uses `/target:winexe` so launching it does not create a console window. The pure harness uses `/target:exe`. Both include the same `AssemblyInfo.cs` and candidate file/assembly version `0.1.0.2`, with informational version `0.1.0-dev-preview.2`. Version text does not establish passing tests; inspect the release's exact commit and validation summary. The script records compiler/source/output hashes locally under `build/`. Those generated records are not approved for publication.

The pure-test harness uses fictional identifiers and synthetic in-memory evidence. A successful build is not a passing test result, and a passing pure harness would not establish native privilege isolation, scheduling, traffic blocking, expiry, crash recovery or production readiness. Run the pure harness without elevation in a permitted test environment; do not describe its fabricated review fixtures as actual model confirmations.

## Configuration and operation limits

`config.disabled.example.json` contains placeholders only. It is deliberately not installable until independently verified values are supplied. It is disabled, has an empty path allowlist and no executable hash pins. A real machine's device mapping, machine GUID, controller SID, policy and protection list are private deployment inputs and must never be copied into the public source repository.

The native installation uses protected application directories and a cleanup-only SYSTEM task. Deployment requires separately reviewed protected staging, administrator access, and testing on the intended Windows environment. This source candidate includes no installer automation, no connector recovery/elevation instructions, and no production activation step.

Before any use, verify the actual controller privilege boundary, protection of code/configuration/state, ordinary-user and SYSTEM apply refusals, exact cleanup task behavior, controlled baseline/block/rollback traffic, replay handling, deadline cleanup, interrupted writes, altered programs, clock faults and policy changes. No such release validation is claimed here.

## Manual uninstallation if installed later

Use a verified elevated controller session and the exact protected installed executable. First run its `disarm` command and verify the successful disabled/removal result. Independently confirm there are no remaining exactly owned rules; an error or unverified removal is a reason to stop and resolve that specific item before deleting anything. Identify the single cleanup task from the verified installation's device identity and inspect its executable/action before removing only that task. Confirm no instance of that cleanup task is still active. Preserve the installation's audit, authorization journal, state and configuration in a private archive for recovery/replay review. Only then remove that one verified fixed installation folder. Do not remove rules by prefix, delete unrelated tasks or folders, terminate unrelated processes, or change Windows security policy to complete removal.

## License and signing status

This standalone source is licensed under the MIT license in `LICENSE`. Source distribution is limited to `allowedFiles` in `RELEASE-FILES.json`. The separate developer-preview allowance covers only `previewArchiveFiles` and the named release sidecars. Private operating records and all other generated artifacts remain excluded.

No external code-signing provider has accepted this project or signed this candidate. The local self-signed deployment described below does not establish provider acceptance. Free signing, if pursued, depends on the provider's independent eligibility, project reputation, build verification and release approval requirements. A new public repository and MIT license do not establish eligibility. No paid signing service is required or configured by this source.

### Code signing policy

There is currently no external signing provider or public signed release. A local self-signed certificate was used for the separately verified deployment below; no certificate or private key is distributed by this repository. Any future signing request must be tied to the exact reviewed source commit and a verifiable build, and a designated project maintainer must explicitly approve that release. Actual maintainer roles and provider attribution will be published only after they are verified. Signing will not be described as proof of runtime safety or effective threat protection.

### Verified local signed deployment — 2026-10-01

This owner-approved summary records local binary identity and file deployment only. It does not establish production readiness, effective network blocking, authenticated dual review, or a public signed release. It makes no new source-to-binary reproducibility claim.

| Field | Verified value |
| --- | --- |
| Binary | `TronDirectEnforcer.exe` |
| SHA-256 | `ABFAB323C66E8248929C51F15316BA792C8205978DD57C48368B878EAF50C979` |
| Size | 78,176 bytes |
| File version | `0.1.0.1` |
| FileDescription | `TRON Direct Enforcement` |
| Signer subject | `CN=TRON Local` |
| Signer thumbprint | `5EF39D6D9531E1406802CA13094121FFB6C6D3DB` |
| QSM (`DESKTOP-QSM1IPD`) | Signed approximately 17:10–17:14 CDT on 2026-10-01; host verification reported Authenticode `Valid`. |
| R97 (`DESKTOP-R97L6H0`) | Deployed and independently verified at 18:22:04 CDT on 2026-10-01; Authenticode `Valid`, message `Signature verified.`. |
| Preserved R97 original backup SHA-256 | `753A14F80D927FEFE54EB795AD834CCB6317B463A364B3A350DC29B278778D8F` |

The deployment receipt reported `VERIFIED_COMPLETE` (completion at 18:21:37 CDT); independent host-side verification followed at 18:22:04 CDT (6:22:04 PM). The original backup was preserved and its hash verified.

The successful transfer used ordinary file copying through the existing OneDrive sync, followed by a UAC-approved PowerShell `Copy-Item` on R97. That successful deployment attempt used no antivirus bypass, encoded commands, certificate import, permission changes, broker execution, or Jarvis changes. These statements describe the successful deployment attempt and do not erase earlier failed attempts.

Authenticode `Valid` is the observed status on these two hosts, not a promise of trust on other computers. This documentation update publishes no binary, certificate, private key, raw receipt, runtime configuration, or authorization record. The public preview manifest, disabled defaults, native enforcement code, and release workflow remain unchanged.

### Privacy

This standalone native program implements no telemetry or network-upload client. It stores administrator-provided authorization metadata and an audit locally in its protected installation directory. External review/controller services are not included; any later integration must disclose its own data handling. Never publish a real installation's configuration, authorization journal, audit, evidence or recovery records with this source.

## Validation status

The developer-preview workflow compiles the exact checked-out source, runs the in-memory harness as a standard Windows user, and runs thirteen native process refusal probes from an uninstalled directory. A passing run records the observed test counts in the preview's `VALIDATION.json`. Consult that file and its linked successful GitHub run for the specific release; workflow presence alone is not evidence that tests passed.

The probes check ordinary-user installation refusal and refusal to use the uninstalled executable for apply, arm, disarm, cleanup, cleanup-task installation, rollback, status, staging initialization/creation/read/cancellation and activation. They do not create firewall rules or install TRON. The pure harness separately reports staging cases and zero firewall operations through the production inert dispatcher. Live blocking, expiry, rollback, installed administrator isolation, scheduling, recovery and authenticated end-to-end review remain unverified. A passing pure harness or refusal test is not evidence of those behaviors.

Build origin is attested using GitHub artifact attestations. The public developer-preview Windows executables remain unsigned; attestations do not supply a Windows-trusted publisher identity or suppress Windows security controls. No paid signing service is configured.

## Optional local advisory source

[LOCAL-ADVISORY.md](LOCAL-ADVISORY.md) describes the bounded loopback model client. Its explanations have no action authority and do not replace actual Codex/ChatGPT reviews. This source-only addition is not included in the native preview archive and does not change its disabled defaults, signing status or production validation status.
