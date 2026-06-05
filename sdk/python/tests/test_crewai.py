"""Tests for the CrewAI integration. Doesn't require crewai installed
- uses a duck-typed fake tool."""

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
from hopframe.integrations.crewai import wrap_tool, wrap_agent


class _Capture(BaseHTTPRequestHandler):
    received: List[bytes] = []

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        type(self).received.append(self.rfile.read(n))
        self.send_response(202); self.send_header("Content-Length", "0"); self.end_headers()
    def log_message(self, *a, **k): pass


@pytest.fixture
def server():
    _Capture.received = []
    srv = HTTPServer(("127.0.0.1", 0), _Capture)
    t = threading.Thread(target=srv.serve_forever, daemon=True); t.start()
    yield f"http://127.0.0.1:{srv.server_port}", _Capture
    srv.shutdown(); t.join(timeout=1)


class FakeCrewAITool:
    """Duck-typed stand-in for a CrewAI Tool."""
    def __init__(self, name: str, ret):
        self.name = name
        self._ret = ret
    def _run(self, *args, **kwargs):
        return self._ret


def test_wrap_tool_emits_call_and_result(server):
    url, cap = server
    hf = Hopframe(url=url, async_delivery=True, buffer_size=8)
    run = new_run_id()
    tool = FakeCrewAITool("search", ret={"results": ["a", "b"]})
    wrap_tool(hf, tool, run_id=run)

    out = tool._run(query="hopframe", limit=2)
    assert out == {"results": ["a", "b"]}

    deadline = time.time() + 2
    while time.time() < deadline and len(cap.received) < 2:
        time.sleep(0.02)
    hf.close()

    assert len(cap.received) == 2
    parsed = [json.loads(b) for b in cap.received]
    inb = next(p for p in parsed if p["direction"] == "inbound")
    out = next(p for p in parsed if p["direction"] == "outbound")

    assert inb["agent_run_id"] == run
    assert inb["source"] == "crewai"
    assert inb["message"]["params"]["name"] == "search"
    assert inb["message"]["params"]["arguments"]["query"] == "hopframe"

    assert out["agent_run_id"] == run
    assert out["destination"] == "crewai"
    assert out["message"]["result"]["results"] == ["a", "b"]


def test_wrap_tool_records_error(server):
    url, cap = server
    hf = Hopframe(url=url, async_delivery=True, buffer_size=8)
    run = new_run_id()

    class Boom(FakeCrewAITool):
        def _run(self, *a, **k):
            raise RuntimeError("upstream timeout")

    tool = Boom("search", ret=None)
    wrap_tool(hf, tool, run_id=run)
    with pytest.raises(RuntimeError):
        tool._run(q="x")

    time.sleep(0.3)
    hf.close()

    parsed = [json.loads(b) for b in cap.received]
    out = next(p for p in parsed if p["direction"] == "outbound")
    assert out["message"]["error"]["message"] == "upstream timeout"


def test_wrap_agent_decorates_each_tool(server):
    url, cap = server
    hf = Hopframe(url=url, async_delivery=True, buffer_size=16)
    run = new_run_id()

    class FakeAgent:
        def __init__(self):
            self.tools = [FakeCrewAITool("a", 1), FakeCrewAITool("b", 2), FakeCrewAITool("c", 3)]

    agent = FakeAgent()
    wrap_agent(hf, agent, run_id=run)
    for t in agent.tools:
        t._run()

    deadline = time.time() + 2
    while time.time() < deadline and len(cap.received) < 6:
        time.sleep(0.02)
    hf.close()

    # 3 tools × 2 events each = 6
    assert len(cap.received) == 6
