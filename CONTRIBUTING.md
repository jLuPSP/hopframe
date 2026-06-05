# Contributing to Hopframe

Hopframe is source-available under BSL 1.1, with each release converting to Apache 2.0 three years after it ships. BSL is not OSI-approved open source; it allows reading, running, forking, and modifying the code and using it for any purpose except offering a competing managed service. The detection content registry under `content/` is the long-term moat, and community contributions are how it stays ahead of closed competitors.

## Three flavours of contribution

### 1. Detection rules (the hottest path)

Rules live in `content/<category>/<pack>.yaml`. Each rule is a YAML document with a regex-driven matcher. The format is intentionally trivial so contributors who don't write Go can still ship signal.

Add a new rule by editing an existing pack or creating a new pack file. The minimum viable rule:

```yaml
category: prompt-injection
rules:
  - id: pi.contrib.your_rule_id           # unique, dotted, snake_case
    description: One-line plain-English summary.
    severity: high                        # info | low | medium | high | critical
    mode: warn                            # monitor | warn | block
    fields:                               # which inspectable field paths apply
      - "params.**"
      - "result.**"
    patterns:                             # regex; matched ANY = finding
      - 'attempt|to|match'
```

Optional fields:

- `targets`: list of MCP/A2A method names this rule scopes to (default: any)
- `directions`: `inbound` and/or `outbound` (default: both)
- `case_sensitive`: defaults to `false`. Patterns are wrapped with `(?i)` unless you opt in

**Important:** Hopframe uses Go's RE2 engine. **No backreferences (`\1`) or lookarounds (`(?!...)`)**. If your pattern uses them, rewrite it without. RE2's deterministic guarantees are why the pipeline runs at sub-50ms p99.

After adding a rule, **add a test sample to `bench/corpus/v1.jsonl`** so the public benchmark covers it. Run `make bench-corpus` to see your contribution's effect on overall precision/recall/F1.

### 2. Code

Standard Go layout. `make test` for the test suite (race-enabled), `make build` for the binaries, `make demo` for a hands-on stack. The packages worth knowing:

| Path | What |
|------|------|
| `pkg/event` | Event schema (versioned) |
| `pkg/mcp`, `pkg/a2a` | Protocol parsers + field extractors |
| `pkg/detect` | Detector interface, heuristic classifier (Layer 2) |
| `pkg/ruleset` | YAML rule engine (Layer 1) |
| `pkg/taint` | Cross-protocol taint tracking |
| `internal/pipeline` | Pipeline orchestration |
| `internal/proxy`, `internal/a2aproxy` | Inline HTTP proxies |
| `internal/emitter` | Event emission, durable spool |
| `control-plane/store` | Append-only hash-chained log + analytics |
| `control-plane/api` | HTTP API + embedded UI |
| `control-plane/behavior` | Layer 4 anomaly detection |
| `control-plane/exporter` | SIEM/SOAR webhook |

PRs that add a feature should include a test in the same package.

### 3. Eval corpus rows

`bench/corpus/v1.jsonl` is the public benchmark. Open a PR adding rows that cover attack patterns the current rule pack misses. Each row is one JSON object:

```json
{"id":"pi-099","category":"prompt-injection","label":"malicious","text":"<the attack string>"}
```

Optional context fields when the sample is method-scoped:

```json
{"id":"tp-099","category":"tool-poisoning","label":"malicious",
 "method":"tools/list","direction":"outbound",
 "field":"result.tools.0.description","text":"..."}
```

Adding rows that cause **false negatives is more valuable than rows the system already catches**. They are how the rule pack improves.

## Style

- Keep rule descriptions one line.
- No emoji in code, comments, or rule descriptions.
- Comments explain *why*, not *what*.
- New packages get a package-level doc comment summarising purpose.

## Review

A maintainer will review and merge. We aim to respond within a week. For urgent security signal (an attack happening in the wild), open an issue with `[urgent]` in the title.

## License of contributions

Two licenses, depending on which directory you touch:

- **Detection rules in `content/`** and **corpus rows in `bench/corpus/`** are accepted under [Apache License 2.0](content/LICENSE). Rule packs and corpus data are explicitly OSI-approved open source so they can spread freely across the security ecosystem.
- **Everything else** (Go code, SDKs, docs, Helm chart, scripts) is accepted under [BSL 1.1](LICENSE), which converts to Apache 2.0 three years after each release.

In practice: most contributions go under Apache 2.0 because rules and corpus rows are the most useful contribution. Code contributions go under BSL for now and convert with the rest of the repo on the Change Date.

By opening a PR, you agree your contribution is licensed under whichever of these two applies to the directory you changed. PRs must be DCO-signed (`git commit -s`) so the chain of authorship is preserved through the eventual Apache conversion.
