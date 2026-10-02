# Inert target staging (candidate 0.1.0.2)

Staging records a possible target; it does not grant permission to block it.
The staged program hash is not an executable pin. No sample is downloaded,
restored, copied, opened or executed by staging. Evidence URLs are stored as
references and are never fetched or treated as instructions.

The native `stage`, `show-stage`, `cancel-stage` and `init-staging` command
branch returns before firewall COM initialization or cleanup. It cannot call
`RunAttested`. Staging never changes configuration, active authorizations,
executable pins, existing rules, scheduled tasks, certificates or permissions.
New files inherit the already-protected installation directory's permissions.

## Commands and storage

All commands run only from the existing protected installed executable.
Staging commands require the existing authenticated, elevated, interactive,
pinned administrator controller, correct machine identity and healthy clock.
They use the existing operation lock to serialize journal changes.

| Command | Effect |
| --- | --- |
| `init-staging` | Explicitly initializes an empty journal/checkpoint only if neither exists. No automatic initialization or reset. |
| `stage JSON_FILE` | Validates one bounded canonical UTF-8 JSON object and appends an inert `STAGED` event. No local executable is required. |
| `show-stage STAGE_ID` | Reads the exact record and digest. Expiration is derived from time without changing files. |
| `cancel-stage STAGE_ID` | Appends `CANCELLED` for a pending record. Never removes a firewall rule. |
| `activate JSON_FILE` | A separate enforcement operation requiring a fresh owner approval and all existing native checks. Not authorized by staging. |
| `apply ...` | Refused with `USE_ACTIVATE_WITH_FRESH_LONG_APPROVAL`. Legacy attestations are historical cleanup records only. |

The journal is `staged-targets.jsonl`, alongside (not inside) the existing
authorization ledger. `staging-high-water.json` stores the exact event count and
head digest. Each canonical event includes its sequence, predecessor digest,
stage ID, immutable target digest, event time and transition data.

There are at most 1,024 events and 16,384 UTF-8 bytes per event. The checkpoint
is persisted before appending/flushing the event. Missing, altered, truncated,
torn, reordered or unexpected-prefix history fails closed. Partial initialization
is an error; the program never repairs or recreates it implicitly. Checkpoint
and journal are not a cryptographic signature: protection depends on the
existing trusted-administrator filesystem boundary. Deliberate administrator
replacement of both files is outside that boundary.

`STAGED -> CANCELLED` and `STAGED -> CONSUMED` are terminal transitions.
Expiration is exclusive at the exact deadline. A consumed record retains the
activation nonce/hash but is not evidence that a rule was successfully created.
The existing authorization ledger and live rule readback remain authoritative
for enforcement state. Cancellation is not rollback.

`status` exposes staging health/counts separately from existing broker health.
`NOT_INITIALIZED` and `RECOVERY_REQUIRED` do not prevent cleanup of existing
authorizations; they prevent staged activation. A read-only status racing a
commit can briefly observe recovery-required state; inspect again after the
writer finishes, never rewrite state to silence it.

## Staged target schema

The input must use exactly these keys. JSON keys are ordinally sorted at every
object level, with no insignificant whitespace or BOM, matching the broker's
existing canonical JSON representation. Integers only; duplicate keys reject.

| Field | Required value or constraint |
| --- | --- |
| `schemaVersion` | `1` |
| `kind`, `authority` | `TRON_STAGED_TARGET`, `NONE` |
| `stageId` | Fresh 64-character lowercase hexadecimal identifier; never reused. |
| `deviceId`, `machineGuid`, `host` | Exact local configuration identities and hostname. |
| `policyHash` | Exact current configuration policy hash. |
| `programSha256` | Exact 64-character lowercase SHA-256; no path or pin is installed. |
| `remoteAddress` | One canonical public IPv4, preserving current protection exclusions. |
| `direction`, `protocol`, `scope` | `OUTBOUND`, `ANY`, `SINGLE_DEVICE`; no new port/range support. |
| `category` | Existing `MALWARE_C2`, `PHISHING` or `EXFILTRATION` category. |
| `reason` | Nonempty, control-free text, at most 1,024 characters. |
| `evidenceReferences` | 1-8 HTTPS URL strings, each at most 2,048 characters; no userinfo. References are claims, not independently verified evidence. |
| `createdAt`, `expiresAt` | Canonical UTC millisecond timestamps; lifetime at most 24 hours. Creation must be within the preceding five minutes. |
| `stagingApproval` | Exactly `approver`, `decision`, `approvedAt`, `approvalReference`. Approver `Long`; decision `APPROVE_STAGE_ONLY`; approval no later than creation and less than 24 hours earlier; reference at most 256 characters. |

No executable path, review confirmation or activation authority is accepted in
this object. Readback reports `programBinding: UNBOUND_HASH_ONLY` and
`authority: NONE`. The returned target digest binds every field above, including
host, evidence references, approval and expiry. Any edit requires a new stage.

## Separate activation authority

No task watches this journal. There is no automatic activation, refresh, retry
or escalation. A later activation requires explicit new owner approval, after
staging, for the exact host, executable/hash, destination and expiration.

Activation uses version 2 of the existing block attestation. It retains every
version 1 field and check, plus `stageId`, `stageHash` and `longApproval`.
`candidateDigest` must equal the staged target digest. `longApproval` has exactly
`approver`, `decision`, `approvalId`, `approvedAt`, `contextHash`: `Long`,
`APPROVE_ACTIVATE`, a fresh lowercase SHA-256-form identifier, a timestamp
after staging and within five minutes before both issuance and current validation, and the
complete activation context digest. The context additionally binds schema
version, stage ID/digest, issuance and all approval fields except its own digest.

The existing separately witnessed Codex and current ChatGPT controller
`CONFIRM_BLOCK` reviews must both bind that complete new context. The code-review
arrangement for a candidate build is not an operational threat confirmation.
No synthetic fixture, local advisory answer, staged approval, or prior review
can stand in for those actual activation reviews.

As before, privileged attestation fields are assertions witnessed by the trusted
controller, not authenticated chat transcripts. This patch does not add a chat
service or prove that Long or either reviewer actually made an assertion. The
controller must truthfully witness and record the real approval and reviews.

Activation checks the stage is pending, unchanged, local, current-policy and
unexpired; the exact hash/address/category must match and activation cannot
outlive staging. It then requires a present local canonical `.exe`, its existing
configuration pin/allowlist, all protected-program exclusions, distinct original
evidence, fresh native attestation, enabled authorization, healthy cleanup,
clock, firewall policy, and existing replay/limit checks. Never download or
restore malware to satisfy the file requirement.

After read-only native preflight, the journal durably consumes the stage before
`RunAttested` can mutate a firewall rule. Stage ID and owner approval ID also
participate in authorization replay detection. If later creation fails, the
stage stays consumed. Inspect the actual journals and rules; do not retry or
revive a consumed stage. A new attempt needs a new stage and fresh approvals.

Historical version 1 and 2 attestations remain readable for exact cleanup and
rollback without consulting staging. Historical records are not upgraded or
rewritten. Direct new version 1 creation is refused.

## Validation and deployment gates

The pure harness runs the production inert dispatcher with in-memory storage
and a poison firewall object. New cases cover inert creation/read/cancellation,
expiry, host/policy/hash bindings, forbidden authority fields, malformed and
tampered journals, interrupted commits, fresh approval, terminal states and
consumption/replay. The preview driver adds five uninstalled refusal probes
(13 total). These are tests to execute after both code reviews; their presence
does not claim they passed or validate installed firewall behavior.

Before building, record both approved code reviews against the exact full diff
and address findings. Then run the complete existing/new tests, including local
advisory tests, native pure tests, standard-user refusal probes and archive
validation. No workflow push may cause an early build or release.

After passing tests, sign with the existing approved certificate in place; do
not export its private key. Verify publisher/thumbprint, hash, size, version and
observed Authenticode status. Deploy one host at a time, first QSM and then R97,
with an exact verified backup and tested file-replacement rollback path. Preserve
configuration, authorization history, audit and cleanup task unchanged.

For this staging-only rollout, confirm the authorization ledger is unchanged
and no native active rules exist before reverting to 0.1.0.1. Preserve any new
staging files during rollback. The old binary ignores them but cannot parse
version 2 authorization records: once activation has ever occurred, do not
revert to the old binary without a separately reviewed compatible recovery.

After deploying each host, snapshot actual firewall rules (canonical sorted
properties and digest, not count alone), active authorization ledger and pins;
initialize staging explicitly if absent; record the approved hash/IP as inert;
read it back; compare the complete before/after snapshots. Require zero added,
removed or changed rules, unchanged pins and active ledger, and no activation.
Any failure or unexplained change stops the rollout. Do not proceed to the
second host until the first host passes verification.
