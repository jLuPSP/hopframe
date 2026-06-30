# hopframe-py

Python SDK for [Hopframe](https://github.com/jLuPSP/hopframe), emit agent traffic events from frameworks that don't speak MCP or A2A natively.

The Go sensors (`mcp-sensor`, `a2a-sensor`, `mcp-stdio-sensor`) handle the protocol-layer cases. This SDK is for the surface area that lives one level higher: LangChain agents, LangGraph state machines, OpenAI Assistants, agents deployed to Vertex AI Agent Engine, custom Python agent loops. It emits events with the same wire schema, so they appear on the same Hopframe timeline alongside MCP and A2A events.

## Install

The package is not yet published to PyPI. Until the first PyPI release, install from the repo:

```bash
pip install -e "git+https://github.com/jLuPSP/hopframe.git#egg=hopframe&subdirectory=sdk/python"
pip install -e "git+https://github.com/jLuPSP/hopframe.git#egg=hopframe[langchain]&subdirectory=sdk/python"
pip install -e "git+https://github.com/jLuPSP/hopframe.git#egg=hopframe[openai]&subdirectory=sdk/python"
```

Once published to PyPI:

```bash
pip install hopframe                  # base, stdlib only
pip install "hopframe[langchain]"     # adds the LangChain callback
pip install "hopframe[openai]"        # adds the OpenAI Assistants helper
```

## Quick start

### Direct emission

```python
from hopframe import Hopframe, new_run_id

hf = Hopframe("http://localhost:7090", api_token="your-token")
run_id = new_run_id()

hf.emit_tool_call(tool="fetch", args={"url": "https://..."}, run_id=run_id)
# ... your tool runs ...
hf.emit_tool_result(tool="fetch", result={"status": 200}, run_id=run_id)
```

### Async direct emission

For asyncio-native loops (LangGraph async, FastAPI handlers, AsyncIO-based agents), use `AsyncHopframe`. It buffers events and ships them in batches with retry; nothing blocks the event loop.

```python
import asyncio
from hopframe import AsyncHopframe, new_run_id

async def main():
    hf = AsyncHopframe("http://localhost:7090", api_token="your-token")
    run_id = new_run_id()
    await hf.emit_tool_call(tool="fetch", args={"url": "https://..."}, run_id=run_id)
    # ... your async tool runs ...
    await hf.emit_tool_result(tool="fetch", result={"status": 200}, run_id=run_id)
    await hf.close()  # drains the buffer

asyncio.run(main())
```

If you already have `httpx` or `aiohttp` in scope, pass a `transport` callable to get fully non-blocking IO. The default uses `urllib.request` in the event-loop executor so the SDK has zero hard dependencies.

### LangChain / LangGraph callback

```python
from langgraph.prebuilt import create_react_agent
from hopframe import Hopframe, new_run_id
from hopframe.integrations.langchain import HopframeCallback

hf = Hopframe("http://localhost:7090")
cb = HopframeCallback(hf, run_id=new_run_id(), framework="langgraph")

agent = create_react_agent(model, tools=[fetch_tool, search_tool])
result = agent.invoke({"messages": [...]}, config={"callbacks": [cb]})
```

Every tool call entry/exit/error is emitted to Hopframe. Same `run_id` ties all events together on the timeline. The same callback works for raw LangChain agents.

### OpenAI Assistants

```python
from openai import OpenAI
from hopframe import Hopframe, new_run_id
from hopframe.integrations.openai_assistants import wrap_tool_execution

hf = Hopframe("http://localhost:7090")
run_id = new_run_id()

# When the assistant requests tool outputs, wrap your handler:
result = wrap_tool_execution(hf, tool_call, run_id, my_tool_handler)
```

## How it fits with the Go sensors

Different agent runtimes need different integration points:

| Runtime | Integration |
|---|---|
| Claude Desktop, Cursor, Continue, claude-code | wrap MCP server with `mcp-stdio-sensor` |
| HTTP-MCP server behind a gateway | sit `mcp-sensor` in front |
| A2A peer | `a2a-sensor` reverse-proxy |
| **LangChain / LangGraph (no MCP)** | **this SDK's `HopframeCallback`** |
| **OpenAI Assistants** | **this SDK's `wrap_tool_execution`** |
| **Vertex AI Agent Engine** | **this SDK** (Agent Engine runs LangChain/LangGraph) |
| Custom Python agent | direct `hf.emit_tool_call(...)` calls |

Events from the SDK land on the same Hopframe timeline as events from the Go sensors. If you mix MCP and direct-Python tools in one agent run with a shared `agent_run_id`, you get a unified forensic view of the run.

## Run-id propagation

Cross-protocol taint lineage is scoped to an `agent_run_id`: a value read over MCP is only recognized when it leaves over A2A if **both wires carry the same run id**. Rather than thread `run_id=` through every call, set it once with `run_scope` and it becomes ambient for everything emitted inside the block:

```python
from hopframe import Hopframe, run_scope

hf = Hopframe("http://control-plane:7090")
with run_scope() as run_id:            # mints one, or pass run_scope("run-x")
    hf.emit_tool_call(tool="fetch", args={...})   # carries run_id automatically
    ...                                            # so does every emit in here
```

The id lives in a `contextvars.ContextVar`, so it is correct across threads and asyncio tasks and nests cleanly. To make your agent's **outbound** MCP/A2A HTTP carry the same id (so the Go sensors correlate the read and the send), install the httpx hook on the client your agent uses for tool calls:

```python
import httpx
from hopframe import run_scope
from hopframe.integrations.httpx import instrument

client = instrument(httpx.Client())   # also works on httpx.AsyncClient
with run_scope():
    client.post(mcp_url, json=...)     # sends X-Hopframe-Agent-Run-Id
```

If you are not on httpx, `run_id_headers()` returns the header dict to merge into any request: `client.post(url, headers=run_id_headers())`.

## Configuration

| Constructor arg | Env var | Default |
|---|---|---|
| `url` | | required |
| `api_token` | `HOPFRAME_API_TOKEN` | empty |
| `sensor_id` | | `hopframe-python` |
| `tenant_id` | | empty |
| `buffer_size` | | 1024 |
| `timeout` | | 5.0 (seconds) |
| `async_delivery` | | True |

`async_delivery=True` (default) ships events on a background thread so `emit()` never blocks the agent. Events past `buffer_size` are dropped (count tracked by `hf.stats()`).

Call `hf.close()` at the end of your program to drain pending events.

## Publishing (maintainers)

The name `hopframe` is unclaimed on PyPI as of this writing. Reserve it before
the first public release, or someone else can take it once the project gets
attention.

Build and validate locally (this produces a wheel + sdist and checks that the
metadata and this README render correctly on PyPI):

```bash
cd sdk/python
python -m pip install --upgrade build twine
python -m build                 # -> dist/hopframe-<version>.whl and .tar.gz
python -m twine check dist/*
```

For the first release, dry-run against TestPyPI before the real index:

```bash
python -m twine upload --repository testpypi dist/*
pip install --index-url https://test.pypi.org/simple/ hopframe   # smoke test
python -m twine upload dist/*                                     # the real upload
```

After that first upload reserves the name, releases are automated: pushing a
`vX.Y.Z` tag runs the `pypi-sdk` job in
[`.github/workflows/release.yaml`](../../.github/workflows/release.yaml),
which builds and publishes via PyPI **Trusted Publishing** (OIDC, no API token
stored in the repo). One-time setup on PyPI: add a trusted publisher for
project `hopframe` pointing at this repo, workflow `release.yaml`, environment
`pypi`.

Keep `version` in `pyproject.toml` in sync with the tag, the build reads the
version from there.

## Status

Alpha, like the Go side. Tested with LangChain ≥ 0.1 and LangGraph. Open issues / PRs at the main repo.

## License

Business Source License 1.1, same as the Go side. Converts to Apache 2.0 three years after each release.
