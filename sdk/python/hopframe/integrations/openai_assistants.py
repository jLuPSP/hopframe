"""OpenAI Assistants API integration.

The Assistants API exposes tool calls through `required_action.submit_tool_outputs`.
The wrap_tool_execution helper takes the run + tool_call and emits
events around your handler.

Usage:

    from openai import OpenAI
    from hopframe import Hopframe, new_run_id
    from hopframe.integrations.openai_assistants import wrap_tool_execution

    hf = Hopframe("http://localhost:7090")
    run_id = new_run_id()

    def my_tool_handler(call):
        if call.function.name == "fetch":
            return wrap_tool_execution(hf, call, run_id, fetch_impl)

The wrapper emits an inbound event before the handler runs and an
outbound event after, with latency.
"""

from __future__ import annotations

import json
import time
from typing import Any, Callable

from ..client import Hopframe


def wrap_tool_execution(
    hf: Hopframe,
    tool_call: Any,
    run_id: str,
    handler: Callable[[Any], Any],
    framework: str = "openai-assistants",
) -> Any:
    """Emit Hopframe events around an OpenAI Assistants tool handler.

    `tool_call` is the SDK's tool call object (has `.function.name` and
    `.function.arguments`). `handler` is your function that turns the
    call into a result.
    """
    name = getattr(getattr(tool_call, "function", None), "name", "unknown")
    args_raw = getattr(getattr(tool_call, "function", None), "arguments", "{}")
    try:
        args = json.loads(args_raw) if isinstance(args_raw, str) else args_raw
    except (TypeError, ValueError):
        args = {"_raw_arguments": args_raw}

    hf.emit_tool_call(tool=name, args=args, run_id=run_id, framework=framework)

    start = time.time()
    error = None
    try:
        result = handler(tool_call)
    except Exception as e:
        error = str(e)
        latency = int((time.time() - start) * 1_000_000)
        hf.emit_tool_result(
            tool=name,
            result=None,
            run_id=run_id,
            framework=framework,
            latency_micros=latency,
            error=error,
        )
        raise
    latency = int((time.time() - start) * 1_000_000)
    hf.emit_tool_result(
        tool=name,
        result=result,
        run_id=run_id,
        framework=framework,
        latency_micros=latency,
    )
    return result
