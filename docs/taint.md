# Value lineage (cross-protocol taint)

Hopframe can tell that the bytes an agent read over one protocol are the same bytes the
agent is sending over another. It can block based on that **provenance**. A model-layer
guard sees one prompt at a time and cannot represent "this value came from somewhere it
should not leave." A single-protocol gateway sees only its own wire. Confused-deputy and
capability-laundering attacks use the link between the read and the send. This feature
inspects that link.

We are not aware of a shipping product that provides value-level lineage across MCP and
A2A. See [landscape-research.md](landscape-research.md) for the survey and the closest
adjacent work. The claim covers byte lineage between two protocols. It excludes semantic
data-flow analysis.

---

## The attack it closes

Each hop is individually benign. A tool that watches a single hop cannot catch the
attack:

1. The agent calls an MCP tool and legitimately receives sensitive data (a token, a
   customer record, an internal hostname).
2. The agent is then induced (via indirect prompt injection in that same tool result, or
   in a later one) to delegate an A2A task to a peer agent and to include that data.
3. The peer is malicious, external, or simply not supposed to see the data.

The MCP gateway saw a normal tool result. The A2A gateway saw a normal task envelope. The
LLM guardrail saw neither wire. A tool must remember the read while inspecting the send
to connect them.

---

## What "the same data" means

Hopframe matches bytes after expanding them into the forms an attacker would use to
defeat an exact-string comparison. For every tagged value and candidate value, Hopframe
computes a set of **shingles**: SHA-256 over a sliding 24-byte window
(`pkg/taint/taint.go::shingleSet`). Two values match when their shingle sets overlap. This
is the standard near-duplicate test. Before shingling, Hopframe expands each value into
its **canonical views** (`canonicalViews`):

- Unicode-normalized (NFKC) with zero-width and smuggling runes stripped, so homoglyph
  and zero-width obfuscation does not evade.
- Any base64 payload embedded in the value is decoded and normalized too, so the agent
  base64-wrapping the secret before forwarding it does not evade.

This mirrors the rule engine's own normalize-and-base64-recurse pass, so both halves of
the engine agree on what "the same data" is.

This is **byte lineage**. It recognizes reuse of the same underlying bytes. It does not
provide semantic lineage or recognize a paraphrase, a summary, or an encrypted or hashed
copy. See [Evasion surface](#evasion-surface) below for the consequences.

---

## How a leak is caught

Lineage is scoped per `agent_run_id` and has two ends:

- **Tag (MCP wire).** When a `tools/call` response arrives from upstream, every leaf
  string in the result is tagged against the run's taint set, with source metadata
  (protocol, method, tool, field). `pipeline.go::TagMCPResult`.
- **Check (A2A wire).** When an A2A task envelope appears on the same `agent_run_id`, its
  message strings are matched against the run's taints. On a hit where the counterparty is
  **not** on the allowlist, Hopframe appends a `taint.cross_protocol_leak` finding (High
  severity, confidence 0.95) and marks the envelope for blocking. `pipeline.go::CheckA2ALeak`.

With an empty allowlist, the policy **blocks any tainted MCP result reused in an A2A task
on the same run.** The allowlist permits specific trusted peers. Wiring it from config is
a roadmap item (today it is empty in every shipped sensor, so the policy is block-any).

---

## Deployment topologies

The link between the read and the send only exists if both wires share taint state. Two
topologies provide that shared state, and the choice has security consequences.

### In-process (combined `sensor`): recommended default

The combined `sensor` binary runs both the MCP and A2A proxies over one pipeline, so they
share a single in-memory tracker. Lineage is **exact and synchronous**. The next A2A
egress on that run can match a tool result as soon as it is tagged, with no network in
the path and no race. Use this topology when both wires can sit behind one sensor.

### Split sensors or replicas (control-plane-shared): opt-in

When MCP and A2A traffic terminates at separate sensor processes (or you run several
replicas of a sensor), one process's in-process tracker cannot see what another process
tagged. Set `HOPFRAME_CONTROL_PLANE_URL` so the sensors share taint through the control
plane:

- **Local-first.** A match checks the in-process tracker first (the fast path is
  unchanged); only on a local miss does it ask the control plane.
- **Fingerprints only.** The wire carries shingle fingerprints, never the raw tagged
  value, so the sensitive bytes never leave the sensor that read them.
- **Async push.** Tagging pushes to the control plane in the background (best-effort, 5s
  timeout); the read path is never blocked on the network.

| | In-process (combined sensor) | Control-plane-shared (split / replicas) |
|---|---|---|
| Consistency | Exact, synchronous | Eventually consistent (sub-ms push race) |
| Network in match path | None | One sync call on local miss (2s timeout) |
| On store/CP outage | N/A | Falls back to local-only (fails open, see below) |
| Raw value exposure | Stays in process | Never leaves the sensor (fingerprints only) |
| Enable with | Run `cmd/sensor` | Set `HOPFRAME_CONTROL_PLANE_URL` on each sensor |

---

## Threat model

**Assumed attacker capabilities.** The attacker can influence tool results (the classic
indirect-injection foothold), induce the agent to forward data to an A2A peer, and control
or impersonate that peer. The attacker **cannot** read sensor or control-plane memory,
forge the `agent_run_id` correlation, or tamper with the sensor binary. The general
[trust assumptions](threat-model.md#trust-assumptions) cover those cases.

**In scope.** Reuse of the same bytes (after normalization and base64 decoding) read from
an MCP tool result and sent in an A2A task on the same agent run, to a counterparty not on
the allowlist.

**Out of scope.** This includes everything in [Evasion surface](#evasion-surface) and the
global out-of-scope items in the [threat model](threat-model.md#out-of-scope). Taint adds
a layer for the cross-protocol case that egress DLP proxies and content rules structurally
cannot see. Continue to use those tools.

---

## Evasion surface

- **Heavy transformation.** If the agent encrypts, hashes, or paraphrases the
  value so that no canonical view shares a 24-byte window with the original, taint will
  not match. This is byte lineage; it does not follow data through a transformation that
  changes the bytes. Defense-in-depth: content rules and the heuristic classifier still
  fire on credential-shaped or PII-shaped output regardless of lineage.
- **Sub-window chunking.** Splitting the secret into pieces shorter than the 24-byte
  shingle window, each in a separate message, can stay under the matcher. Long secrets
  reassembled across many tiny A2A messages are the realistic version of this.
- **Run-id propagation.** Lineage is scoped to `agent_run_id`. If the run id is not
  carried onto both wires (via the SDK or proxy correlation), the read and the send land
  in different buckets and never link. Correct run-id plumbing is a deployment
  responsibility; an SDK middleware to make it automatic is roadmap work.
- **TTL and capacity eviction.** Taints are dropped after the run is idle past the TTL
  (compiled default **2h**). The run table is bounded (defaults **128** taints per run,
  **4096** runs, oldest-newest evicted first). The matcher does not catch a read followed
  by exfiltration after the window or after eviction under heavy load.
- **Low-entropy or very short values.** Values at or below the shingle width produce a
  single coarse fingerprint; extremely common or short strings are not reliable lineage
  signal and are not the intended target. Taint is for distinctive secrets, not for
  "the word `admin` appeared on both wires."

---

## Operational caveats (control-plane-shared mode)

These caveats apply only to the opt-in cross-replica topology. They do not apply to the
combined sensor.

- **Eventual consistency.** Registration is asynchronous, so there is a sub-millisecond
  window after a read when an egress check on another process could miss a taint that has
  not propagated. The agent's read-then-forward turn (an LLM round trip) is orders of
  magnitude slower than propagation. A normal agent loop cannot reach the window, but the
  window exists.
- **Fail-open to local on control-plane outage.** If the control plane is unreachable, a
  remote match times out (2s) and returns no-hit. The lineage check does not block the
  egress. This behavior prevents a control-plane interruption from breaking legitimate
  agent traffic. Split deployments degrade to per-process taint during an outage. Use the
  combined sensor for a hard cross-protocol guarantee that does not depend on the control
  plane.
- **In-memory control-plane store.** The shared tracker lives in the control plane's
  process memory today and is lost on restart. Durable, Postgres-backed persistence rides
  on the HA control-plane work; see [roadmap.md](roadmap.md).

---

## Configuration

- **`HOPFRAME_CONTROL_PLANE_URL`** on a sensor enables control-plane-shared taint. Unset,
  the sensor uses in-process taint only (and the combined sensor still shares across both
  of its wires).
- **Compiled defaults**: 2h TTL, 128 taints per run, 4096 runs. These are not yet exposed
  as config; open an issue if you need them tunable.
- **Counterparty allowlist**: the pipeline supports an allowlist of A2A peers permitted to
  receive tainted data; exposing it from config is roadmap work. Until then the policy is
  block-any tainted egress on the run.

---

## What it is not

- **Lineage scope.** It inspects the A2A wire for reuse of data tagged on the MCP wire.
  It does not inspect all outbound traffic for sensitive shapes. Pair it with content rules
  (which do shape-detection) and a real egress proxy.
- **Near-duplicate detection.** Fingerprints support near-duplicate detection. They do not
  provide integrity or secrecy. The audit log provides cryptographic accountability.
- **Byte-level matching.** It follows bytes. A model that launders data through
  summarization will not be caught by this layer. That is the model provider's and the
  content layer's surface.

See also: [architecture.md](architecture.md) for where `pkg/taint` sits in the pipeline,
[capabilities.md](capabilities.md) for the one-line capability summary, and
[threat-model.md](threat-model.md) for the full defensive scope.
