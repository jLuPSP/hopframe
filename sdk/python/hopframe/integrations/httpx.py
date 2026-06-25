"""Auto-stamp the ambient agent run id onto outbound httpx requests.

The Go sensors correlate an MCP read with a later A2A send by the
``X-Hopframe-Agent-Run-Id`` header. Install this hook on the httpx client your
agent uses for tool calls, wrap the run in :func:`hopframe.run_scope`, and both
wires carry the same id, so cross-protocol taint lineage works without
threading the id through every call site.

    import httpx
    from hopframe import run_scope
    from hopframe.integrations.httpx import instrument

    client = httpx.Client()
    instrument(client)
    with run_scope() as run_id:
        client.post(mcp_url, json=...)   # carries X-Hopframe-Agent-Run-Id

The hook is a plain function and httpx is imported lazily (only when you call
:func:`instrument`), so this module imports fine even where httpx is absent,
and the same sync hook works for both ``httpx.Client`` and ``AsyncClient``.
"""

from __future__ import annotations

from typing import Any

from ..context import RUN_ID_HEADER, current_run_id


def run_id_request_hook(request: Any) -> None:
    """httpx request event hook: stamp the ambient run id when one is set.

    Leaves an already-present header untouched, so an explicit per-request id
    wins over the ambient one.
    """
    rid = current_run_id()
    if rid and RUN_ID_HEADER not in request.headers:
        request.headers[RUN_ID_HEADER] = rid


def instrument(client: Any) -> Any:
    """Add the run-id hook to an httpx ``Client``/``AsyncClient`` (idempotent).

    Returns the same client for chaining. Existing event hooks are preserved.
    """
    hooks = dict(getattr(client, "event_hooks", {}) or {})
    request_hooks = list(hooks.get("request", []))
    if run_id_request_hook not in request_hooks:
        request_hooks.append(run_id_request_hook)
    hooks["request"] = request_hooks
    client.event_hooks = hooks
    return client
