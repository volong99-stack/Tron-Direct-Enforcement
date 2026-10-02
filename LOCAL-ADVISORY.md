# Optional local advisory client

This source-only Node client reads a bounded private evidence packet and asks an existing loopback Ollama runtime for a technical explanation. It does not install a model, start a service, expose a network endpoint or change the native enforcer. It is not bundled into the unsigned native preview archive.

Run `node local-review/local-review.mjs private-evidence.json` with Node 22 or later. The input file must remain private and be at most 100 KB. It contains `sources`, with at most twelve objects: a unique `id`, ISO timestamp `at`, bounded `text`, optional `kind` (`TECHNICAL` or `OBSERVATION`), and optional `synthetic: true` for test fixtures. Never publish real packets, outputs, prompts, device identities or credentials. Credential-pattern redaction is limited and does not make a private packet safe to publish.

The client uses only `127.0.0.1:11435`, checks the companion app on port 3210 for busy state, refuses redirects and bounds inference to 150 seconds. It selects an already-installed `qwen3.5:9b` with 32 GPU layers, otherwise `qwen3.5:4b` on CPU. Missing, busy, malformed or truncated responses return UNAVAILABLE with no action. An idle check is not a runtime lock; another application can become busy afterward. There is no cross-host failover or automatic retry.

Output is LOCAL_ADVISORY_ONLY with authority NONE, actionExecuted false and automaticBlocking false. REVIEW only means human technical review: it requires a fresh, exact quotation from non-synthetic technical evidence. Unknown-device observations alone cannot authorize anything. Synthetic-only packets cannot become real security findings. Quotes older than fifteen minutes cannot support current findings. Model explanations still require human assessment; exact quotations do not independently prove an inference is correct.

Actual Codex and ChatGPT reviews remain required by the existing native policy. Local advice is not either review, code signing, a signed authorization, or proof of deployment. No firewall, production policy, broker, signing or deployment permissions are added. No continuous watcher, cloud escalation, model training or automatic blocking is installed by this module.

Validate with `node --test local-review/local-review.test.mjs`. Tests use synthetic inputs and mocked loopback responses; CI makes no model request and receives no private evidence. The native build, refusal tests and disabled preview defaults remain separate requirements.
