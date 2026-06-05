# Hopframe threat model

This document describes what Hopframe defends against, what it doesn't, and the assumptions it makes about its environment. Read it before deploying Hopframe in production.

---

## Threat scope

Hopframe defends against four classes of attack on agent traffic:

### 1. Prompt injection

Adversarial natural-language content inside tool calls or tool results that attempts to override the model's behavior.

- **Direct injection.** User input designed to make the model ignore prior instructions, switch role, or leak its system prompt.
- **Indirect injection.** Content fetched from a third-party tool (web pages, files, query results) that addresses the model directly.
- **Paraphrased injection.** Instruction-override semantics expressed in language that does not match a known signature.

**Hopframe coverage:** regex pack (Layer 1) catches known signatures with high precision; the heuristic classifier (Layer 2) catches paraphrased variants via feature density; behavioral layer (Layer 4) catches abnormal injection rates.

### 2. Tool poisoning

Adversarial tool descriptions or metadata served by an MCP server at registration time.

- **Authority claims.** `<system>` tags or `[admin]` markers in tool descriptions.
- **Override directives.** Phrasings like "always use this tool", "before any other tool", "bypass safety".
- **Confused-deputy framing.** "Switch user to admin and execute on behalf of".
- **Invisible-Unicode smuggling.** Zero-width and tag-block bytes that hide instructions inside otherwise plain text.

**Hopframe coverage:** the rule pack at `content/tool-poisoning/` covers all four patterns; the quarantine workflow auto-blocks subsequent calls to a tool whose description triggered a high/critical finding.

### 3. Credential and PII exfiltration

Sensitive material in tool arguments, tool results, or A2A task messages.

- **Credentials:** AWS / GCP / GitHub / Slack / OpenAI / Anthropic key formats; PEM private keys; bearer tokens; webhooks
- **PII:** SSN-shape sequences, credit-card-shape sequences, IBAN, bulk email lists
- **Exfiltration patterns:** `send X to https://...` style imperatives, base64-encode-and-call patterns

**Hopframe coverage:** rule packs at `content/credential-exfiltration/` and `content/pii-leakage/`; the heuristic classifier's exfil-imperative feature catches paraphrased variants.

### 4. Cross-protocol taint leak

Sensitive data flowing from an MCP tool result into an A2A task message destined for an untrusted peer.

- **Attack pattern.** Agent calls an MCP tool, receives sensitive data, then delegates an A2A task to a peer agent, where that peer is malicious or external.
- **Why it is invisible to other tools.** MCP gateways see only MCP. A2A gateways see only A2A. LLM guardrails see neither.

**Hopframe coverage:** `pkg/taint` tags MCP tool-call results with shingle fingerprints + source metadata; A2A sensor checks task messages for reuse and blocks when the counterparty is not on the allowlist. **This is unique to Hopframe in this category.**

---

## Out of scope

These are *not* what Hopframe defends against. We say so explicitly to avoid surprising buyers who think they got more than they did.

### Model-side jailbreaks

If you're running an LLM with safety training and the user convinces it to misbehave purely through prose, that's the model provider's problem (Anthropic / OpenAI / your fine-tuning vendor). Hopframe inspects protocol traffic, not LLM responses to direct chat. Pair Hopframe with an LLM guardrail (Lakera, Protect AI, NeMo) for that surface.

### Application logic flaws in your tools

If your `fetch` tool has SSRF, your `database` tool has SQLi, or your custom MCP server has authn bypass, those are bugs in your tools and not threats Hopframe will catch. Use the same SAST, DAST, and dependency-scanning tooling you would use for any HTTP service.

### Authentication and authorization

Hopframe forwards Authorization headers but does not validate or refresh tokens. OAuth flows, token rotation, and mTLS to the upstream are your responsibility. The control plane has bearer-token auth on `/v1/*` and supports mTLS for sensor-to-control-plane traffic. That is where the auth story stops.

### Resource abuse

Hopframe applies a per-IP rate limit to `/v1/*` writes when `HOPFRAME_RATE_LIMIT_RPS` is set, and rejected requests are counted in `hopframe_rate_limited_total`. That is a guard for the control plane, not for your downstream tools. The detection pipeline holds at ~115k evals/sec, so a misbehaving agent making 10,000 tool calls per second will overwhelm your tools well before the sensor is the bottleneck, and the sensor will not stop the abuse on its own. For tool-side quota and runaway-loop protection, pair Hopframe with an API gateway that rate-limits the upstream.

### Network-layer threats

DDoS, TLS termination, IP allowlists, and DNS rebinding are out of scope. Hopframe sits behind a real WAF (Cloudflare, BIG-IP) or inside a VPC. We assume the network edge is handled elsewhere.

### Compliance auto-pilot

We make evidence verifiable. We do not make controls automatic. For SOC2, HIPAA, or FedRAMP, Hopframe is one piece of the evidence chain, not the chain itself.

### Detection content gaps

Hopframe ships 58 rules and a heuristic classifier scoring F1=1.0 on the 84-sample seed corpus at `bench/corpus/v1.jsonl`. Both are growing. **Until the registry hits the 200-rule target and is validated against public attack libraries (HarmBench, JailbreakBench, AgentDojo), expect false negatives on novel attacks.** Open issues / PRs at the main repo when you find them.

---

## Trust assumptions

Hopframe assumes:

1. **The control plane is trusted.** It holds the audit log, the chain head, and the rule packs. Compromise of the control plane defeats the integrity story. Run it in your trust boundary, behind your IAM, with mTLS on the sensor link.

2. **The sensor is trusted.** It sits inline; if an attacker controls the sensor binary, they can drop or rewrite traffic at will. Pin sensor images, sign your deployments, run with `gcr.io/distroless/static-debian12:nonroot`.

3. **The detection content is trusted.** Rules are loaded from disk; bad rules can produce false negatives. Review every PR to `content/`. The compatibility-matrix and corpus are how community quality is verified.

4. **Time is roughly synchronized.** Behavioral anomaly detection uses windowed counts; severe clock skew between sensor and control plane will distort sparkline / histogram / spike detection. NTP your hosts.

5. **The chain genesis (when rotated) is trusted.** A side-channel adversary who replaces both the log and the `<log>.genesis` file simultaneously can hide a rotation. Treat the genesis file with the same protection as the log itself.

---

## Failure modes and what they mean

| Mode | What happens | Operational response |
|---|---|---|
| Sensor pipeline error | Either fail-open (forwards) or fail-closed (rejects). Configurable per `policy.fail_open`. | Default fail-open in dev; fail-closed in prod for high-stakes deployments. |
| Control plane down | Sensor spools events to disk; replays on reconnect. UI is offline; sensor inline path keeps working. | Buy a small spool disk per sensor (default 64 MiB). Alert on `dropped > 0`. |
| Chain integrity broken | UI badge goes red; `GET /v1/verify` returns ok=false. | Treat as a security incident. Don't trust subsequent records until investigated. |
| Quarantine TTL expires | Tool can be called again. | Default 24h. Lower if you want stickier blocks. Or clear via `/admin/quarantine`. |
| Spool full (durable replay) | New events dropped; counter incremented. | Increase `spool_max_bytes` or fix the control-plane outage. |
| Webhook delivery fails | Best-effort; counted but not retried. | Use Splunk HEC for retry semantics, or scrape `/v1/events.ndjson` from your SIEM on a schedule. |

---

## Reporting a vulnerability

See [SECURITY.md](https://github.com/jLuPSP/hopframe/blob/main/SECURITY.md). Open a [private security advisory](https://github.com/jLuPSP/hopframe/security/advisories/new) for any issue that affects Hopframe's defensive integrity.
