# Security Policy

Hopframe is a security tool, so we take vulnerabilities in Hopframe itself seriously. If you find one, please follow the disclosure process below. Do not open a public GitHub issue.

## Reporting a vulnerability

Open a **[private security advisory](https://github.com/jLuPSP/hopframe/security/advisories/new)** on the repository with:

- A clear description of the issue
- Reproduction steps (or proof-of-concept code)
- Affected version (`git rev-parse HEAD` or release tag)
- Whether you've shared this with anyone else

We aim to:

- Acknowledge your report within **48 hours**
- Triage and confirm severity within **5 business days**
- Ship a fix or workaround within **30 days** for high/critical, **90 days** for medium/low
- Credit you in the release notes (unless you ask us not to)

If you do not get a response within 48 hours, comment on the advisory again. The first notification likely got missed.

## Scope

In scope:

- Hopframe sensor binaries (`mcp-sensor`, `mcp-stdio-sensor`, `a2a-sensor`)
- Control plane (`control-plane` binary, HTTP API, embedded UI)
- Detection content engine (`pkg/ruleset`, `pkg/detect`)
- Cross-protocol primitives (`pkg/taint`, `pkg/mcp`, `pkg/a2a`)
- Python SDK (`sdk/python/hopframe`)
- Helm chart and Docker images we publish

Not in scope (please don't report these):

- Issues in MCP servers we proxy. Report those upstream.
- Issues in agent frameworks (LangChain, CrewAI, etc.) we integrate with. Report those upstream.
- Detection content false positives or false negatives. Open a regular GitHub issue.
- Theoretical attacks against the threat model that do not have a demonstrable exploit.
- Dependency CVEs that do not affect a Hopframe code path. Feel free to PR a bump.

## What we consider critical / high

- Bypass of a configured `block` rule (sensor forwards traffic that should be blocked)
- Tamper that the chain-verify check fails to detect
- Privilege escalation in the control plane (unauthenticated access to admin endpoints)
- Sensor crash or hang triggered by a remotely-controlled message
- Credential leakage from the sensor or control plane to an unintended destination

## Coordinated disclosure

If you're a researcher with a publication timeline, tell us up front and we'll work back from your date. We default to a 90-day disclosure window with the option to extend if a fix is in flight.

## Hall of fame

Researchers credited for a Hopframe security report:

*None yet. Be the first.*

---

For non-security bugs, feature requests, or detection-content gaps: open a [regular issue](https://github.com/jLuPSP/hopframe/issues).
