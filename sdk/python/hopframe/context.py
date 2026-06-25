"""Ambient agent-run-id propagation.

Cross-protocol taint lineage is scoped to an ``agent_run_id``: a value read
over MCP is only recognized when it leaves over A2A if both wires carry the
same run id. This module makes that id ambient, so you set it once per agent
run and every emitted event (and, via the httpx integration, every outbound
request) carries it, instead of threading ``run_id=`` through every call.

    from hopframe import run_scope, current_run_id

    with run_scope() as run_id:          # mints one, or pass run_scope("run-x")
        hf.emit_tool_call(tool="fetch", args={...})   # carries run_id
        ...                                            # so does the A2A send

The id lives in a :class:`contextvars.ContextVar`, so it is correct across
threads and asyncio tasks and nests cleanly.
"""

from __future__ import annotations

import contextlib
from contextvars import ContextVar, Token
from typing import Dict, Iterator, Mapping, Optional

#: Header the Go sensors read to correlate MCP and A2A traffic on one run.
RUN_ID_HEADER = "X-Hopframe-Agent-Run-Id"

_current_run_id: ContextVar[str] = ContextVar("hopframe_run_id", default="")


def current_run_id() -> str:
    """Return the run id in effect for the current context, or ``""``."""
    return _current_run_id.get()


def set_run_id(run_id: str) -> Token:
    """Set the ambient run id, returning a token for :func:`reset_run_id`.

    Prefer :func:`run_scope`; this is the low-level primitive for callers
    that cannot use a ``with`` block (e.g. framework start/stop callbacks).
    """
    return _current_run_id.set(run_id)


def reset_run_id(token: Token) -> None:
    """Restore the ambient run id to what it was before :func:`set_run_id`."""
    _current_run_id.reset(token)


@contextlib.contextmanager
def run_scope(run_id: Optional[str] = None) -> Iterator[str]:
    """Bind an agent run id for the duration of the block.

    Mints a fresh id when none is given. Nesting is supported: the previous
    id is restored on exit. Every ``emit_*`` call, and (with the httpx
    integration installed) every outbound request made inside the block,
    carries this id.
    """
    if not run_id:
        from .client import new_run_id  # lazy import: avoid a module cycle

        run_id = new_run_id()
    token = _current_run_id.set(run_id)
    try:
        yield run_id
    finally:
        _current_run_id.reset(token)


def run_id_headers(
    headers: Optional[Mapping[str, str]] = None,
    run_id: Optional[str] = None,
) -> Dict[str, str]:
    """Return ``headers`` with the run-id header added.

    Uses the explicit ``run_id`` when given, otherwise the ambient one. If
    neither is set the headers are returned unchanged (no empty header is
    added). Handy for stamping the id onto an outbound request by hand:

        resp = client.post(url, json=body, headers=run_id_headers())
    """
    out: Dict[str, str] = dict(headers or {})
    rid = run_id or current_run_id()
    if rid:
        out[RUN_ID_HEADER] = rid
    return out
