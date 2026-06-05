"""Tests for the LangChain / LangGraph integration.

The integration imports `from langchain.callbacks.base import
BaseCallbackHandler` at module load. The test installs a minimal
stub into sys.modules before the integration is imported so the
test runs without LangChain in the environment, while still
exercising the real Hopframe-side logic.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
import types
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import List

import pytest

# Ensure the SDK source is on sys.path even when run from the repo root.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _install_langchain_stub() -> None:
    """Install a minimal langchain.callbacks.base.BaseCallbackHandler
    so HopframeCallback can subclass it without LangChain installed.
    Idempotent."""
    if "langchain.callbacks.base" in sys.modules:
        return
    pkg_lc = types.ModuleType("langchain")
    pkg_cb = types.ModuleType("langchain.callbacks")
    mod_base = types.ModuleType("langchain.callbacks.base")

    class BaseCallbackHandler:  # noqa: D401
        """Stub stand-in for langchain.callbacks.base.BaseCallbackHandler."""

        pass

    mod_base.BaseCallbackHandler = BaseCallbackHandler
    pkg_cb.base = mod_base
    pkg_lc.callbacks = pkg_cb
    sys.modules["langchain"] = pkg_lc
    sys.modules["langchain.callbacks"] = pkg_cb
    sys.modules["langchain.callbacks.base"] = mod_base


_install_langchain_stub()

from hopframe import Hopframe, new_run_id  # noqa: E402
from hopframe.integrations.langchain import HopframeCallback  # noqa: E402


class _Capture(BaseHTTPRequestHandler):
    received: List[bytes] = []

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        type(self).received.append(self.rfile.read(n))
        self.send_response(202)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a, **k):
        pass


@pytest.fixture
def server():
    _Capture.received = []
    srv = HTTPServer(("127.0.0.1", 0), _Capture)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_port}", _Capture
    srv.shutdown()
    t.join(timeout=1)


def _wait_for(cap, n: int, timeout: float = 2.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline and len(cap.received) < n:
        time.sleep(0.02)


def test_callback_emits_inbound_on_tool_start_and_outbound_on_tool_end(server):
    url, cap = server
    hf = Hopframe(url=url, async_delivery=True, buffer_size=8)
    run = new_run_id()
    cb = HopframeCallback(hf, run_id=run, framework="langgraph")

    cb.on_tool_start(
        serialized={"name": "fetch"},
        input_str=json.dumps({"url": "https://example.com"}),
        run_id="lc-1",
    )
    cb.on_tool_end(output={"status": 200, "body": "ok"}, run_id="lc-1", name="fetch")

    _wait_for(cap, 2)
    hf.close()

    assert len(cap.received) == 2
    parsed = [json.loads(b) for b in cap.received]
    inb = next(p for p in parsed if p["direction"] == "inbound")
    out = next(p for p in parsed if p["direction"] == "outbound")

    assert inb["agent_run_id"] == run
    assert inb["source"] == "langgraph"
    assert inb["message"]["params"]["name"] == "fetch"
    assert inb["message"]["params"]["arguments"]["url"] == "https://example.com"

    assert out["agent_run_id"] == run
    assert out["destination"] == "langgraph"
    assert out["message"]["result"]["status"] == 200
    # Latency was measured between start and end; at minimum non-negative.
    assert out["latency_micros"] >= 0


def test_callback_records_tool_error(server):
    url, cap = server
    hf = Hopframe(url=url, async_delivery=True, buffer_size=8)
    run = new_run_id()
    cb = HopframeCallback(hf, run_id=run)

    cb.on_tool_start(serialized={"name": "fetch"}, input_str="", run_id="lc-2")
    cb.on_tool_error(error=RuntimeError("upstream 500"), run_id="lc-2", name="fetch")

    _wait_for(cap, 2)
    hf.close()

    parsed = [json.loads(b) for b in cap.received]
    err = next(p for p in parsed if p["direction"] == "outbound")
    # The integration emits error context via emit_tool_result with an
    # error string; the field surfaces in the wire envelope's findings.
    assert err["agent_run_id"] == run
    has_error_marker = any(
        f.get("description", "").startswith("upstream 500")
        or "upstream 500" in json.dumps(err)
        for f in err.get("findings", []) or [{}]
    )
    assert has_error_marker, f"expected error description in event: {err}"


def test_callback_mints_run_id_when_omitted(server):
    url, _ = server
    hf = Hopframe(url=url, async_delivery=False)
    cb = HopframeCallback(hf)
    assert cb.run_id.startswith("run-")
    hf.close()


def test_callback_handles_non_json_input_string(server):
    url, cap = server
    hf = Hopframe(url=url, async_delivery=True, buffer_size=8)
    cb = HopframeCallback(hf, run_id=new_run_id())

    # LangChain sometimes hands in raw strings (when a tool takes a
    # single positional input); the adapter should still emit and
    # tag the raw payload rather than crashing.
    cb.on_tool_start(
        serialized={"name": "summarize"},
        input_str="this is not JSON",
        run_id="lc-3",
    )
    _wait_for(cap, 1)
    hf.close()

    parsed = [json.loads(b) for b in cap.received]
    inb = next(p for p in parsed if p["direction"] == "inbound")
    args = inb["message"]["params"]["arguments"]
    assert args.get("_raw_input") == "this is not JSON"
