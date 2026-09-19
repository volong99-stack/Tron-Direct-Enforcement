# Runtime validation before a production release

The developer preview covers compilation, in-memory logic, and uninstalled
standard-user refusal probes. This plan is not a claim that the tests below ran.

Use a dedicated, disposable Windows test machine with a snapshot and independent
recovery access. Keep private device/account/configuration values outside the
public repository. Synthetic test assertions must be explicitly identified as
test fixtures, never as actual AI review or threat evidence.

| Area | Required evidence before enabling real enforcement |
| --- | --- |
| Installation and identity | Verified protected staging; restrictive ACLs; disabled initial install; no mutation by a standard user, different administrator, SYSTEM apply request, or wrong machine identity. |
| Controller integration | Real, authenticated and current separate review decisions bound to the exact proposed operation; false, expired and replayed decisions rejected. |
| Network behavior | Controlled baseline, exact outbound block, unrelated traffic unaffected, and successful rollback with externally observed traffic. Use only a controlled public endpoint and a dedicated test executable. |
| Cleanup | Exact owned-rule removal on expiry, disarm, destination becoming protected, executable replacement and clock faults; unrelated firewall rules preserved. |
| Recovery | Interrupt writes and crash at each journal/state transition; verify replay protection and fail-closed creation without stranding owned rules. |
| Scheduling | Cleanup-only SYSTEM task, exact action and ACL checks, fresh heartbeat, behavior across locked desktop, sleep and reboot. |
| Lifecycle | Explicit, tested update and uninstall procedures that remove owned rules before removing the executable/task; preserve private recovery records. |

Keep the default authorization disabled until these gates are satisfied. Publish
only a sanitized summary: exact commit, environment category, case names,
pass/fail outcomes, and known gaps. Do not publish real configuration or logs.

For a future SignPath reapplication, collect the successful workflow/release
links, reproducible verification steps, independent reviews, genuine user
feedback, issue history, and sustained maintenance. There is no guaranteed
adoption threshold or approval date.
