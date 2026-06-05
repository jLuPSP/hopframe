---
name: Detection rule request
about: Propose a new rule for the detection content registry.
title: "[rule] "
labels: detection-content
---

## Attack pattern

<!-- One-paragraph description. What is the attack? Where on the wire does it appear? -->

## Why the current rule pack misses it

<!-- Have you tried? What did `make bench-corpus` say? -->

## Proposed rule

```yaml
- id: <category>.contrib.<short_name>
  description: One-line summary.
  severity: <info | low | medium | high | critical>
  mode: <monitor | warn | block>
  fields:
    - "params.**"
    - "result.**"
  patterns:
    - 'regex pattern (RE2-compatible, no backrefs, no lookarounds)'
```

## Sample

<!-- Add a sample to bench/corpus/v1.jsonl that exercises the rule.
     Paste the JSON object below. Real attack samples are best;
     synthetic samples are also welcome but should be plausible. -->

```json
{"id":"<category>-<n>","category":"<category>","label":"malicious","text":"..."}
```

## References

<!-- Links to writeups, advisories, prior art if applicable. -->
