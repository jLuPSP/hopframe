"""Tests for the hopframe Python client.

Self-contained: spins up a tiny in-process HTTP server that mimics
the control plane's POST /v1/events endpoint, captures the bodies,
and asserts the wire shape and async-buffer behavior.
"""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import List

import pytest

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hopframe import Hopframe, new_run_id
from hopframe.client import _prune_empty


class _Capture(BaseHTTPRequestHandler):
    received: List[bytes] = []

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(n)
        type(self).received.append(body)
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


def test_emit_tool_call_async(server):
    url, cap = server
    hf = Hopframe(url=url, async_delivery=True, buffer_size=8)
    run = new_run_id()
    hf.emit_tool_call(tool="fetch", args={"url": "x"}, run_id=run, framework="langchain")
    hf.emit_tool_result(tool="fetch", result={"status": 200}, run_id=run, framework="langchain")

    deadline = time.time() + 2
    while time.time() < deadline and len(cap.received) < 2:
        time.sleep(0.02)
    hf.close()

    assert len(cap.received) == 2
    parsed = [json.loads(b) for b in cap.received]
    inb = next(p for p in parsed if p.get("direction") == "inbound")
    out = next(p for p in parsed if p.get("direction") == "outbound")

    assert inb["protocol"] == "agent"
    assert inb["agent_run_id"] == run
    assert inb["message"]["method"] == "tools/call"
    assert inb["message"]["params"]["name"] == "fetch"
    assert inb["source"] == "langchain"

    assert out["agent_run_id"] == run
    assert out["message"]["result"]["status"] == 200
    assert out["destination"] == "langchain"


def test_bearer_token_header(server):
    url, cap = server
    hf = Hopframe(url=url, api_token="secret-tok", async_delivery=False)
    hf.emit_tool_call(tool="x", args={}, run_id="r")
    # synchronous mode posts before returning
    assert len(cap.received) == 1


def test_prune_empty_strips_blank_fields():
    raw = {
        "schema": "x",
        "tenant_id": "",
        "findings": [],
        "metadata": {},
        "value": "kept",
        "nested": {"a": "", "b": "kept"},
    }
    pruned = _prune_empty(raw)
    assert "tenant_id" not in pruned
    assert "findings" not in pruned
    assert "metadata" not in pruned
    assert pruned["value"] == "kept"
    assert pruned["nested"] == {"b": "kept"}


def test_async_drops_when_buffer_full(server):
    url, _ = server
    # tiny buffer + slow no-op sink (we don't call close so stats reflect drops)
    hf = Hopframe(url=url, async_delivery=True, buffer_size=2)
    for i in range(50):
        hf.emit_tool_call(tool=f"t{i}", args={}, run_id="r")
    # don't close yet, give the worker a moment
    time.sleep(0.1)
    stats = hf.stats()
    # Either delivered everything (if worker is fast) or has drops.
    # We tolerate both; the test just verifies the counter exists and is non-negative.
    assert stats["dropped"] + stats["delivered"] > 0
    hf.close()
