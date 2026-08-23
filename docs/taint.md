# Value lineage (cross-protocol taint)

Hopframe can tell that bytes an agent read over one protocol are the bytes it sends over
another, and can block on that **provenance**. Confused-deputy and capability-laundering
attacks use the link between the read and the send. This feature inspects that link.

No shipping product we know of provides value-level lineage across MCP and A2A; see
[landscape-research.md](landscape-research.md) for the survey and closest adjacent work.
The claim covers byte lineage between two protocols and excludes semantic data-flow
analysis.

---

## The attack it closes

Each hop is individually benign.

1. The agent calls an MCP tool and legitimately receives sensitive data (a token, a
   customer record, an internal hostname).
2. Indirect prompt injection in that tool result, or a later one, induces the agent to
   delegate an A2A task to a peer and include the data.
3. The peer is malicious, external, or not supposed to see the data.

The MCP gateway saw a normal tool result, the A2A gateway a normal task envelope, and the
LLM guardrail neither wire. Catching the attack means remembering the read while
inspecting the send.

---

## What "the same data" means

For every tagged and candidate value, Hopframe computes **shingles**: SHA-256 over a
sliding 24-byte window (`pkg/taint/taint.go::shingleSet`). Two values match when their
shingle sets overlap, the standard near-duplicate test. Before shingling, Hopframe
expands each value into its **canonical views** (`canonicalViews`):

- Unicode-normalized (NFKC) with zero-width and smuggling runes stripped, so homoglyph
  and zero-width obfuscation does not evade.
- Any base64 payload embedded in the value is decoded and normalized too, so
  base64-wrapping the secret before forwarding does not evade.

This mirrors the rule engine's normalize-and-base64-recurse pass, so both halves of the
engine agree.

This is **byte lineage**: reuse of the same underlying bytes. See
[Evasion surface](#evasion-surface) below for the consequences.

---

## How a leak is caught

Lineage is scoped per `agent_run_id` and has two ends:

- **Tag (MCP wire).** When a `tools/call` response arrives, every leaf string in the
  result is tagged against the run's taint set, with source metadata (protocol, method,
  tool, field). `pipeline.go::TagMCPResult`.
- **Check (A2A wire).** When an A2A task envelope appears on the same `agent_run_id`, its
  message strings are matched against the run's taints. On a hit from a counterparty
  **not** on the allowlist, Hopframe appends a `taint.cross_protocol_leak` finding (High
  severity, confidence 0.95) and marks the envelope for blocking. `pipeline.go::CheckA2ALeak`.

With an empty allowlist, the policy **blocks any tainted MCP result reused in an A2A task
on the same run.** Today the allowlist is empty in every shipped sensor; wiring it from
config is a roadmap item.

---

## Deployment topologies

Linking the read and the send requires both wires to share taint state. Two topologies
provide it, and the choice has security consequences.

### In-process (combined `sensor`): recommended default

The combined `sensor` binary runs the MCP and A2A proxies over one pipeline and one
in-memory tracker. Lineage is **exact and synchronous**: an A2A egress on the run can
match a tool result the moment it is tagged. Use it when both wires can sit behind one
sensor.

### Split sensors or replicas (control-plane-shared): opt-in

When MCP and A2A traffic terminates at separate sensor processes (or several replicas of
one sensor), one process's tracker cannot see what another tagged. Set
`HOPFRAME_CONTROL_PLANE_URL` so the sensors share taint through the control plane:

- **Local-first.** A match checks the in-process tracker first and asks the control plane
  only on a local miss.
- **Fingerprints plus a short sample.** The wire carries shingle fingerprints and an
  up-to-80-character sample used in findings. It does not send the complete tagged value
  unless that value itself is 80 characters or shorter.
- **Async push.** Tagging pushes to the control plane in the background (best-effort, 5s
  timeout); the read path never blocks on the network.

| | In-process (combined sensor) | Control-plane-shared (split / replicas) |
|---|---|---|
| Consistency | Exact, synchronous | Eventually consistent (async registration) |
| Network in match path | None | One sync call on local miss (2s timeout) |
| On store/CP outage | N/A | Falls back to local-only (fails open, see below) |
| Raw value exposure | Stays in process | Fingerprints plus an up-to-80-character sample leave the sensor |
| Enable with | Run `cmd/sensor` | Set `HOPFRAME_CONTROL_PLANE_URL` on each sensor |

---

## Threat model

**Assumed attacker capabilities.** The attacker can influence tool results, induce the
agent to forward data to an A2A peer, and control or impersonate that peer. The attacker **cannot** read sensor or control-plane memory,
forge the `agent_run_id` correlation, or tamper with the sensor binary. The general
[trust assumptions](threat-model.md#trust-assumptions) cover those cases.

**In scope.** Reuse of the same bytes (after normalization and base64 decoding) read from
an MCP tool result and sent in an A2A task on the same agent run, to a counterparty not on
the allowlist.

**Out of scope.** This includes everything in [Evasion surface](#evasion-surface) and the
global out-of-scope items in the [threat model](threat-model.md#out-of-scope).

---

## Evasion surface

- **Heavy transformation.** If the agent encrypts, hashes, or paraphrases the
  value so that no canonical view shares a 24-byte window with the original, taint will
  not match. Content rules and the heuristic classifier still fire on credential-shaped
  or PII-shaped output regardless of lineage.
- **Sub-window chunking.** Splitting the secret into pieces shorter than the 24-byte
  shingle window, each in a separate message, can stay under the matcher. The realistic
  version reassembles a long secret across many tiny A2A messages.
- **Run-id propagation.** If the run id is not carried onto both wires (via proxy
  correlation, `run_scope`, or explicit headers), the read and the send never link.
  Correct run-id plumbing is a deployment responsibility.
- **TTL and capacity eviction.** The tracker has a compiled **2h** TTL, but shipped
  runtimes do not yet schedule the sweep that enforces it. Capacity bounds do apply
  (defaults **128** taints per run and **4096** runs, oldest-newest evicted first), so
  heavy load can still evict lineage before a later send.
- **Low-entropy or very short values.** Values at or below the shingle width produce a
  single coarse fingerprint. Common or short strings are unreliable lineage signal; taint
  targets distinctive secrets.

---

## Operational caveats (control-plane-shared mode)

These caveats apply only to the opt-in cross-replica topology, never to the combined
sensor.

- **Eventual consistency.** Registration is asynchronous and unacknowledged. An egress
  check on another process can miss a taint until the push completes, and there is no
  ordering or latency guarantee.
- **Fail-open to local on control-plane outage.** If the control plane is unreachable, a
  remote match times out (2s), returns no-hit, and the egress is not blocked. This keeps a
  control-plane interruption from breaking legitimate agent traffic; split deployments
  degrade to per-process taint. The combined sensor gives a hard cross-protocol guarantee
  independent of the control plane.
- **In-memory control-plane store.** The shared tracker lives in control-plane process
  memory today and is lost on restart. Durable Postgres-backed persistence rides on the
  HA control-plane work; see [roadmap.md](roadmap.md).

---

## Configuration

- **`HOPFRAME_CONTROL_PLANE_URL`** on a sensor enables control-plane-shared taint. Unset,
  the sensor uses in-process taint only (and the combined sensor still shares across both
  wires).
- **Compiled defaults**: 2h TTL, 128 taints per run, 4096 runs. The TTL is not currently
  enforced because shipped runtimes do not schedule `Sweep`; the capacity limits are
  enforced. These values are not yet exposed as config.
- **Counterparty allowlist**: the pipeline supports an allowlist of A2A peers permitted to
  receive tainted data; exposing it from config is roadmap work.

---

## What it is not

- **Lineage scope.** It checks the A2A wire for reuse of MCP-tagged data, never all
  outbound traffic for sensitive shapes. Pair it with content rules (which do
  shape-detection) and an egress proxy.
- **Near-duplicate detection.** Fingerprints support near-duplicate detection, never
  integrity or secrecy. The audit log provides cryptographic accountability.
- **Byte-level matching.** A model that launders data through summarization will not be
  caught by this layer. That surface belongs to the model provider and the content layer.

See also: [architecture.md](architecture.md) for where `pkg/taint` sits in the pipeline,
[capabilities.md](capabilities.md) for the one-line capability summary, and
[threat-model.md](threat-model.md) for the full defensive scope.
