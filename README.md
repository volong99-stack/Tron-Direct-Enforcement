# TRON Direct Enforcement

**Experimental MIT-licensed source candidate. Unsigned, not installed or activated, and not runtime-validated for production.** Public source availability does not establish signing-provider acceptance, verified adoption or reputation, or readiness to protect a computer.

The native adapter accepts an explicit, elevated administrator-controller attestation before adding one narrow outbound Windows firewall rule. The authority is named `ADMIN_CONTROLLER_ATTESTATION`; it is not a cryptographic proof that an AI review occurred. The caller must independently witness a real Codex review and make a separate current ChatGPT controller decision about the exact technical evidence and proposed action. That authenticated end-to-end review integration is not supplied or validated by this standalone source release. The native layer checks the administrator token, pinned controller identity, bound metadata, scope, freshness, replay state and executable identity. It cannot authenticate external transcripts or establish the truth of evidence from its hashes. This project is not affiliated with or endorsed by Microsoft or OpenAI.

Only supported confirmed technical-threat categories are accepted. Content claims, opinions and unknown devices do not qualify. A rule is limited to one existing administrator-pinned executable SHA-256 and one canonical public IPv4 destination on one device. Private/reserved addresses, broad destination ranges, Windows executables and management tools are excluded. Empty executable pins deny every new rule.

There is no incoming directory, untrusted receipt ingestion, signing key or background apply service. The optional SYSTEM scheduled task runs only native cleanup. Explicit apply/arm calls require the configured authenticated elevated non-SYSTEM controller in a user session. Durable reservations and an initialized history checkpoint are designed to detect missing or truncated authorization history; removal requires a fully matched owned rule. Cleanup also checks whether an active rule's destination has become protected by the current configuration. Clock faults prevent new creation while cleanup attempts safe exact removal. Expiry depends on execution of the cleanup task; it is not an operating-system-enforced TTL.

Windows firewall rules are path-based. The adapter verifies the current file under a read handle during application, then checks identity again during cleanup. This does not prove the identity of an already running process or permanently bind a firewall rule to file bytes. Native rule readback also does not prove actual network blocking; controlled traffic tests are required.

## Files and build

`RELEASE-FILES.json` is the exact source-file whitelist. `DISCLOSURE-INVENTORY.md` describes what those files disclose. Generated binaries, build receipts/logs, credentials, runtime configuration, deployment data and operating records are outside that whitelist.

`build.ps1` uses only the installed Microsoft .NET Framework C# compiler and local framework references. It locates the fixed framework installation under the Windows directory, rejects reparse paths, and requires a valid Microsoft compiler signature and matching compiler identity. It refuses an existing build-output directory. It does not download tools, change execution policy, request elevation, sign files, execute either result, install components, or publish anything.

When local policy permits ordinary PowerShell script execution, invoke it from its directory with `./build.ps1`. If policy refuses the script or generated programs, stop and use a separately approved build/validation environment. Do not weaken or bypass application-control or script policies to run this candidate.

Production output uses `/target:winexe` so launching it does not create a console window. The pure harness uses `/target:exe`. Both include the same `AssemblyInfo.cs` and fixed file/assembly version `0.1.0.0`, with informational version `0.1.0-private-candidate`. This historical candidate version metadata is retained to match the inspected build procedure. The release includes subsequent native source corrections; the version text is not a claim that this exact source snapshot has passed runtime tests. The script records compiler/source/output hashes locally under `build/`. Those generated records are not approved for publication.

The pure-test harness uses fictional identifiers and synthetic in-memory evidence. A successful build is not a passing test result, and a passing pure harness would not establish native privilege isolation, scheduling, traffic blocking, expiry, crash recovery or production readiness. Run any eventual pure harness without elevation in a permitted test environment; do not describe its fabricated review fixtures as actual model confirmations.

## Configuration and operation limits

`config.disabled.example.json` contains placeholders only. It is deliberately not installable until independently verified values are supplied. It is disabled, has an empty path allowlist and no executable hash pins. A real machine's device mapping, machine GUID, controller SID, policy and protection list are private deployment inputs and must never be copied into the public source repository.

The native installation uses protected application directories and a cleanup-only SYSTEM task. Deployment requires separately reviewed protected staging, administrator access, and testing on the intended Windows environment. This source candidate includes no installer automation, no connector recovery/elevation instructions, and no production activation step.

Before any use, verify the actual controller privilege boundary, protection of code/configuration/state, ordinary-user and SYSTEM apply refusals, exact cleanup task behavior, controlled baseline/block/rollback traffic, replay handling, deadline cleanup, interrupted writes, altered programs, clock faults and policy changes. No such release validation is claimed here.

## Manual uninstallation if installed later

Use a verified elevated controller session and the exact protected installed executable. First run its `disarm` command and verify the successful disabled/removal result. Independently confirm there are no remaining exactly owned rules; an error or unverified removal is a reason to stop and resolve that specific item before deleting anything. Identify the single cleanup task from the verified installation's device identity and inspect its executable/action before removing only that task. Confirm no instance of that cleanup task is still active. Preserve the installation's audit, authorization journal, state and configuration in a private archive for recovery/replay review. Only then remove that one verified fixed installation folder. Do not remove rules by prefix, delete unrelated tasks or folders, terminate unrelated processes, or change Windows security policy to complete removal.

## License and signing status

This standalone source is licensed under the MIT license in `LICENSE`. Public distribution is limited to the files listed in `RELEASE-FILES.json`; private operating records and generated artifacts are excluded.

No code-signing provider has accepted this project or signed this candidate. Free signing, if pursued, depends on the provider's independent eligibility, project reputation, build verification and release approval requirements. A new public repository and MIT license do not establish eligibility. No paid signing service is required or configured by this source.

### Code signing policy

There is currently no signing provider, certificate or signed release. Any future signing request must be tied to the exact reviewed source commit and a verifiable build, and a designated project maintainer must explicitly approve that release. Actual maintainer roles and provider attribution will be published only after they are verified. Signing will not be described as proof of runtime safety or effective threat protection.

### Privacy

This standalone native program implements no telemetry or network-upload client. It stores administrator-provided authorization metadata and an audit locally in its protected installation directory. External review/controller services are not included; any later integration must disclose its own data handling. Never publish a real installation's configuration, authorization journal, audit, evidence or recovery records with this source.

## Validation status

The corrected native source compiled privately with the installed, signature-verified Microsoft .NET Framework compiler. Its corresponding private harness compiled but was not executed. The public harness applies only fixture-privacy substitutions to that private harness; this exact sanitized harness has not been separately compiled or executed. Seventeen regression cases were added for authorization-history continuity and removal when a destination becomes protected; they have not been run.

The unchanged build script previously passed Windows PowerShell syntax parsing with zero errors; the script itself was not executed. Its assembly metadata and build settings are preserved. No generated executable in this source candidate is signed, installed or activated. Live blocking, expiry, rollback, administrator isolation and authenticated end-to-end Codex/ChatGPT confirmation remain unverified for this candidate. A successful compile is not evidence of those behaviors.
