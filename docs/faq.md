# FAQ

Short answers to the common questions.

## What exactly does Hopframe see?

It sees the protocol messages agents exchange: MCP `tools/list`, `tools/call`, `tools/result`, and A2A task envelopes. It does not see prompts or model responses. Full detail in [How it works](how-it-works.md).

## Will it slow down my agent?

Measured: ~115k evaluations/sec on a laptop (p50 ~30µs, p99 ~160µs) for the regex + heuristic layers. The LLM judge runs only on the uncertain band and is optional.

## Does it require an LLM?

No. Layers 1 and 2 are deterministic. The Layer-3 LLM judge is optional and off by default.

## Inline or SDK, which should I pick?

If you control the endpoint, inline: full fidelity, hard-blocking, no code changes. If the runtime is managed but you own the agent code, SDK: observable, advisory. See [Deploy](deploy.md).

## Is it open source?

Source-available under BSL 1.1, converting to Apache 2.0 three years after each release. The detection content and benchmark corpus are Apache 2.0 today. See the [license section](index.md#license) of the docs.

## How do I prove a log wasn't tampered with?

`hopframe verify`, or hand an auditor the `hopframe export` bundle they verify offline against the manifest and Merkle root. The signatures are Ed25519; the UI verifies them in-browser.

## What traffic should I run it on first?

Evaluation traffic, a homelab, or a small team. It is alpha: the detection corpus is small, so validate against your real traffic and treat the shipped rules as a floor. See [Operations](operations.md#roadmap).

## Where do my events go?

To the control plane (file or Postgres audit chain), and optionally to a webhook or Splunk HEC exporter. Events do not leave your deployment unless you configure an exporter. See [Operations](operations.md#exporters).

## How do I add my own detection rules?

Drop a YAML pack under `content/<category>/`, or use the `/v1/rules` and content endpoints. Rules are Apache 2.0 and community contributions are welcome. See [CONTRIBUTING](https://github.com/jLuPSP/hopframe/blob/main/CONTRIBUTING.md).

## Is there a SaaS?

Not yet. Hopframe is self-hosted: you control the control plane, the data, and the keys.
