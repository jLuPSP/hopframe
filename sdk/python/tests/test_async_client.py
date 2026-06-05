"""Tests for hopframe.async_client.AsyncHopframe.

Standard library only. We avoid pytest-asyncio so the SDK's test
matrix stays dependency-free; each test wraps its async body in
asyncio.run().
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List

from hopframe import AsyncHopframe
from hopframe.async_client import _PermanentError


class _FakeTransport:
    def __init__(self, fail_with: type | None = None, fail_n: int = 0):
        self.calls: List[Dict[str, Any]] = []
        self.fail_with = fail_with
        self.fail_n = fail_n

    async def __call__(self, payload: Dict[str, Any]) -> None:
        self.calls.append(payload)
        if self.fail_with and self.fail_n > 0:
            self.fail_n -= 1
            raise self.fail_with("forced")


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


def test_emit_buffers_until_batch_then_flushes() -> None:
    async def body() -> None:
        transport = _FakeTransport()
        hf = AsyncHopframe(
            url="http://localhost:7090",
            sensor_id="t",
            batch_size=3,
            transport=transport,
            flush_interval=60,
        )
        try:
            for _ in range(5):
                await hf.emit_tool_call(tool="x")
            assert len(transport.calls) == 3
            await hf.flush()
            assert len(transport.calls) == 5
        finally:
            await hf.close()

    _run(body())


def test_retry_then_succeed() -> None:
    async def body() -> None:
        transport = _FakeTransport(fail_with=RuntimeError, fail_n=2)
        dropped: List[int] = []
        hf = AsyncHopframe(
            url="http://localhost:7090",
            sensor_id="t",
            batch_size=10,
            max_retries=3,
            transport=transport,
            on_drop=lambda n, _e: dropped.append(n),
            flush_interval=60,
        )
        try:
            await hf.emit_tool_call(tool="x")
            await hf.flush()
            assert dropped == []
            assert len(transport.calls) == 3
            assert hf.stats["delivered"] == 1
        finally:
            await hf.close()

    _run(body())


def test_permanent_error_drops_without_retry() -> None:
    async def body() -> None:
        transport = _FakeTransport(fail_with=_PermanentError, fail_n=10)
        dropped: List[int] = []
        hf = AsyncHopframe(
            url="http://localhost:7090",
            sensor_id="t",
            batch_size=5,
            max_retries=5,
            transport=transport,
            on_drop=lambda n, _e: dropped.append(n),
            flush_interval=60,
        )
        try:
            await hf.emit_tool_call(tool="x")
            await hf.flush()
            assert dropped == [1]
            assert len(transport.calls) == 1
        finally:
            await hf.close()

    _run(body())


def test_close_flushes_pending() -> None:
    async def body() -> None:
        transport = _FakeTransport()
        hf = AsyncHopframe(
            url="http://localhost:7090",
            sensor_id="t",
            batch_size=100,
            transport=transport,
            flush_interval=60,
        )
        await hf.emit_tool_call(tool="x")
        await hf.emit_tool_call(tool="y")
        await hf.close()
        assert len(transport.calls) == 2

    _run(body())
