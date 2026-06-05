"""Async Hopframe client. Buffers events and ships them in batches.

Same wire schema as the synchronous client in `hopframe.client`. Use
this in asyncio-native agent loops (LangGraph async, AsyncIO-based
tool-runners, FastAPI request handlers) where blocking on a thread
would cost the event loop.

Standard library only. Built on `asyncio` + `urllib.request` (run in a
default executor) so the SDK keeps zero hard dependencies. Operators
who already have httpx or aiohttp in scope can pass a `transport`
callable to override the default and get true non-blocking IO.
"""

from __future__ import annotations

import asyncio
import json
import os
import urllib.error
import urllib.request
from dataclasses import asdict
from typing import Any, Awaitable, Callable, Dict, List, Optional

from hopframe.client import Event, Message, Finding, _new_event_id, _utc_now

Transport = Callable[[Dict[str, Any]], Awaitable[None]]


class AsyncHopframe:
    """Asyncio-native Hopframe client with batch emit and retry.

    Args:
        url: control plane base URL.
        api_token: bearer token. Falls back to HOPFRAME_API_TOKEN.
        sensor_id: identity for emitted events.
        tenant_id: tenancy scope.
        batch_size: events buffered before a forced flush.
        flush_interval: seconds between background flushes.
        max_retries: per-batch retry budget on transient failure.
        transport: optional async callable that posts a single event.
            Override to plug in httpx / aiohttp; defaults to urllib in
            an executor.
        on_drop: callback invoked when retries are exhausted on a batch.
    """

    def __init__(
        self,
        url: str,
        api_token: Optional[str] = None,
        sensor_id: str = "hopframe-python-async",
        tenant_id: str = "",
        batch_size: int = 64,
        flush_interval: float = 1.0,
        max_retries: int = 3,
        timeout: float = 5.0,
        transport: Optional[Transport] = None,
        on_drop: Optional[Callable[[int, Exception], None]] = None,
    ) -> None:
        self._url = url.rstrip("/") + "/v1/events"
        self._token = api_token or os.environ.get("HOPFRAME_API_TOKEN", "")
        self._sensor_id = sensor_id
        self._tenant_id = tenant_id
        self._batch_size = batch_size
        self._flush_interval = flush_interval
        self._max_retries = max_retries
        self._timeout = timeout
        self._transport = transport or self._default_transport
        self._on_drop = on_drop

        self._buffer: List[Event] = []
        self._buffer_lock = asyncio.Lock()
        self._dropped = 0
        self._delivered = 0
        self._task: Optional[asyncio.Task[None]] = None
        self._closed = False

    # -- builders --

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
            agent_run_id=agent_run_id,
            protocol=protocol,
            direction=direction,
        )

    # -- buffering --

    async def emit(self, event: Event) -> None:
        async with self._buffer_lock:
            self._buffer.append(event)
            should_flush = len(self._buffer) >= self._batch_size
        if should_flush:
            await self.flush()
        self._ensure_periodic()

    async def emit_tool_call(
        self,
        tool: str,
        args: Optional[Dict[str, Any]] = None,
        run_id: str = "",
        framework: str = "",
    ) -> Event:
        ev = self.new_event(direction="inbound", agent_run_id=run_id)
        ev.message = Message(
            method="tools/call",
            params={"name": tool, "arguments": args or {}},
        )
        if framework:
            ev.source = framework
        await self.emit(ev)
        return ev

    async def emit_tool_result(
        self,
        tool: str,
        result: Any,
        run_id: str = "",
        framework: str = "",
        error: Optional[str] = None,
    ) -> Event:
        ev = self.new_event(direction="outbound", agent_run_id=run_id)
        msg = Message(method="tools/call")
        if error:
            msg.error = {"code": -32000, "message": error}
            ev.action = "warn"
            ev.severity = "high"
            ev.findings = [
                Finding(
                    rule_id="async_python.tool_error",
                    category="transport",
                    severity="high",
                    description=error,
                )
            ]
        else:
            msg.result = result if isinstance(result, dict) else {"value": result}
        ev.message = msg
        if framework:
            ev.destination = framework
        await self.emit(ev)
        return ev

    # -- delivery --

    async def flush(self) -> None:
        async with self._buffer_lock:
            if not self._buffer:
                return
            batch = self._buffer
            self._buffer = []
        await self._send_batch(batch)

    async def close(self) -> None:
        self._closed = True
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
        await self.flush()

    @property
    def stats(self) -> Dict[str, int]:
        return {"delivered": self._delivered, "dropped": self._dropped, "queued": len(self._buffer)}

    # -- internals --

    def _ensure_periodic(self) -> None:
        if self._task is not None and not self._task.done():
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return  # not inside a loop; caller will run flush() manually
        self._task = loop.create_task(self._periodic())

    async def _periodic(self) -> None:
        try:
            while not self._closed:
                await asyncio.sleep(self._flush_interval)
                await self.flush()
        except asyncio.CancelledError:
            return

    async def _send_batch(self, batch: List[Event]) -> None:
        delay = 0.1
        last_err: Optional[Exception] = None
        for attempt in range(self._max_retries + 1):
            try:
                await asyncio.gather(*(self._transport(self._encode(ev)) for ev in batch))
                self._delivered += len(batch)
                return
            except _PermanentError as e:
                # 4xx (except 429): drop immediately, no retries.
                self._dropped += len(batch)
                if self._on_drop:
                    self._on_drop(len(batch), e)
                return
            except Exception as e:
                last_err = e
                if attempt == self._max_retries:
                    break
                await asyncio.sleep(delay)
                delay = min(delay * 2, 5.0)
        self._dropped += len(batch)
        if self._on_drop and last_err is not None:
            self._on_drop(len(batch), last_err)

    def _encode(self, event: Event) -> Dict[str, Any]:
        d = asdict(event)
        return d

    async def _default_transport(self, payload: Dict[str, Any]) -> None:
        # Run blocking urllib in the executor so the loop stays free.
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._post_blocking, payload)

    def _post_blocking(self, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self._token:
            headers["Authorization"] = "Bearer " + self._token
        if payload.get("agent_run_id"):
            headers["X-Hopframe-Agent-Run-Id"] = payload["agent_run_id"]
        req = urllib.request.Request(self._url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                _ = resp.read()
        except urllib.error.HTTPError as e:
            if 400 <= e.code < 500 and e.code != 429:
                raise _PermanentError(f"hopframe: {e.code}") from e
            raise


class _PermanentError(Exception):
    """Non-retriable HTTP failure (4xx other than 429)."""
