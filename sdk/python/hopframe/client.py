"""Hopframe Python client, emits events to the control plane.

Mirrors the Go event schema in pkg/event so events from Python
agents land on the same timeline as events from the Go sensors.

Designed to be dependency-free at the base layer: only stdlib.
Framework integrations (LangChain, etc.) live under
hopframe.integrations and import their own deps lazily.
"""

from __future__ import annotations

import json
import os
import queue
import secrets
import threading
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from dataclasses import field as dc_field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .context import current_run_id

SCHEMA_VERSION = "hopframe.event/v1"


@dataclass
class Finding:
    rule_id: str
    category: str
    severity: str
    description: str = ""
    match: str = ""
    field: str = ""
    confidence: float = 0.0
    metadata: Dict[str, Any] = dc_field(default_factory=dict)


@dataclass
class Message:
    method: str = ""
    id: str = ""
    params: Optional[Dict[str, Any]] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[Dict[str, Any]] = None
    raw: str = ""


@dataclass
class Event:
    schema: str = SCHEMA_VERSION
    event_id: str = ""
    timestamp: str = ""
    sensor_id: str = ""
    tenant_id: str = ""
    agent_run_id: str = ""
    counterparty: str = ""
    protocol: str = "agent"  # "mcp" | "a2a" | "agent" | "behavior"
    direction: str = "inbound"
    source: str = ""
    destination: str = ""
    message: Message = dc_field(default_factory=Message)
    findings: List[Finding] = dc_field(default_factory=list)
    action: str = "allow"
    severity: str = "info"
    latency_micros: int = 0


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def _new_event_id() -> str:
    return "ev-" + secrets.token_hex(12)


class Hopframe:
    """Hopframe client, buffers events and ships them to the control plane.

    Args:
        url: control plane base URL (e.g. http://localhost:7090).
        api_token: bearer token for authenticated control planes.
        sensor_id: identifier under which this client's events appear.
        tenant_id: tenancy scope.
        buffer_size: in-memory queue size. Events past this are dropped
            (and the dropped count is counted internally).
        timeout: HTTP timeout per delivery, seconds.
        async_delivery: when True (default), events are delivered on a
            background thread so emit() never blocks the agent.
    """

    def __init__(
        self,
        url: str,
        api_token: Optional[str] = None,
        sensor_id: str = "hopframe-python",
        tenant_id: str = "",
        buffer_size: int = 1024,
        timeout: float = 5.0,
        async_delivery: bool = True,
    ) -> None:
        self._url = url.rstrip("/") + "/v1/events"
        self._token = api_token or os.environ.get("HOPFRAME_API_TOKEN", "")
        self._sensor_id = sensor_id
        self._tenant_id = tenant_id
        self._timeout = timeout
        self._dropped = 0
        self._delivered = 0
        self._lock = threading.Lock()
        self._async = async_delivery
        if async_delivery:
            self._queue: "queue.Queue[Optional[Event]]" = queue.Queue(maxsize=buffer_size)
            self._worker = threading.Thread(target=self._drain, daemon=True)
            self._worker.start()
        else:
            self._queue = None  # type: ignore[assignment]

    # -- builder helpers --

    def new_event(
        self,
        protocol: str = "agent",
        direction: str = "inbound",
        agent_run_id: str = "",
    ) -> Event:
        return Event(
            event_id=_new_event_id(),
            timestamp=_utc_now(),
            sensor_id=self._sensor_id,
            tenant_id=self._tenant_id,
            agent_run_id=agent_run_id or current_run_id(),
            protocol=protocol,
            direction=direction,
        )

    def emit_tool_call(
        self,
        tool: str,
        args: Optional[Dict[str, Any]] = None,
        run_id: str = "",
        framework: str = "",
        latency_micros: int = 0,
    ) -> Event:
        ev = self.new_event(direction="inbound", agent_run_id=run_id)
        ev.message = Message(
            method="tools/call",
            params={"name": tool, "arguments": args or {}},
            raw=json.dumps({"name": tool, "arguments": args or {}}),
        )
        if framework:
            ev.source = framework
        ev.latency_micros = latency_micros
        self.emit(ev)
        return ev

    def emit_tool_result(
        self,
        tool: str,
        result: Any,
        run_id: str = "",
        framework: str = "",
        latency_micros: int = 0,
        error: Optional[str] = None,
    ) -> Event:
        ev = self.new_event(direction="outbound", agent_run_id=run_id)
        msg = Message(method="tools/call")
        if error:
            msg.error = {"code": -32000, "message": error}
        else:
            msg.result = result if isinstance(result, dict) else {"value": result}
            msg.raw = json.dumps(msg.result, default=str)
        ev.message = msg
        if framework:
            ev.destination = framework
        ev.latency_micros = latency_micros
        self.emit(ev)
        return ev

    # -- delivery --

    def emit(self, event: Event) -> None:
        if self._async and self._queue is not None:
            try:
                self._queue.put_nowait(event)
            except queue.Full:
                with self._lock:
                    self._dropped += 1
            return
        try:
            self._post(event)
            with self._lock:
                self._delivered += 1
        except Exception:
            with self._lock:
                self._dropped += 1

    def stats(self) -> Dict[str, int]:
        with self._lock:
            return {"delivered": self._delivered, "dropped": self._dropped}

    def close(self, drain_timeout: float = 5.0) -> None:
        if not self._async:
            return
        # Sentinel: worker drains every queued event up to the None
        # marker, then exits. drain_timeout caps the wait.
        self._queue.put(None)
        self._worker.join(timeout=drain_timeout)

    # -- internals --

    def _drain(self) -> None:
        while True:
            ev = self._queue.get()
            if ev is None:
                return
            try:
                self._post(ev)
                with self._lock:
                    self._delivered += 1
            except Exception:
                with self._lock:
                    self._dropped += 1

    def _post(self, event: Event) -> None:
        body = json.dumps(_event_to_wire(event)).encode("utf-8")
        req = urllib.request.Request(
            self._url,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "X-Hopframe-Schema": SCHEMA_VERSION,
                **({"Authorization": f"Bearer {self._token}"} if self._token else {}),
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                _ = resp.read()
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"control plane responded {e.code}") from e


def _event_to_wire(event: Event) -> Dict[str, Any]:
    """Convert dataclass to the Go event schema's JSON shape.

    The Go side uses snake_case; our dataclass already does, so we
    can use asdict directly. We strip empty strings and None values
    to keep events compact on the wire.
    """
    raw = asdict(event)
    return _prune_empty(raw)


def _prune_empty(obj: Any) -> Any:
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            v = _prune_empty(v)
            if v in (None, "", [], {}):
                continue
            out[k] = v
        return out
    if isinstance(obj, list):
        return [_prune_empty(v) for v in obj]
    return obj


# -- convenience for run-id minting --

def new_run_id() -> str:
    return f"run-py-{secrets.token_hex(8)}-{int(time.time())}"
