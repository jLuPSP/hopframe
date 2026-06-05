<!-- Thanks for the contribution. A few minutes here saves time on review. -->

## Summary

<!-- One-paragraph description. What changes, why. Link any issue. -->

## What kind of change?

- [ ] Bug fix
- [ ] New detection rule (`content/`)
- [ ] New benchmark sample (`bench/corpus/`)
- [ ] Feature
- [ ] Documentation
- [ ] CI / build / dependencies

## Test plan

<!-- What tests cover this change? Paste relevant `go test`, `pytest`, or `npm test` output. -->

## Checklist

- [ ] `make test` passes (Go race tests). For SDK changes, the relevant SDK tests pass too.
- [ ] No em-dash characters (Unicode U+2014) in any `*.md` or `*.go` file. Use a hyphen, comma, or rephrase.
- [ ] [`CHANGELOG.md`](../CHANGELOG.md) updated under `[Unreleased]` for any user-visible change.
- [ ] All commits are DCO-signed: `git commit -s`. (See [CONTRIBUTING.md](../CONTRIBUTING.md).)
- [ ] For new detection rules: the rule has a corresponding sample in `bench/corpus/v1.jsonl`.
- [ ] For substantive code changes: a test was added or modified in the same package.

<!-- By submitting this PR you agree your contribution is licensed under
     BSL 1.1 / future Apache 2.0 conversion, same as the rest of the
     repo. See CONTRIBUTING.md. -->
