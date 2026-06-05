"""LangChain / LangGraph callback adapter.

LangChain agents (and LangGraph state machines) expose tool calls
through the BaseCallbackHandler interface. Plug a HopframeCallback
into your agent's `callbacks=` list and every tool invocation is
emitted to Hopframe with the same shape the Go MCP sensor emits.

This makes Hopframe relevant to agents that don't speak MCP at all -
raw LangChain ReAct agents, LangGraph state machines, agents
deployed to Vertex AI Agent Engine, etc.

Usage:

    from langchain_anthropic import ChatAnthropic
    from langgraph.prebuilt import create_react_agent
    from hopframe import Hopframe, new_run_id
    from hopframe.integrations.langchain import HopframeCallback

    hf = Hopframe("http://localhost:7090")
    cb = HopframeCallback(hf, run_id=new_run_id(), framework="langgraph")

    agent = create_react_agent(model, tools=[...])
    result = agent.invoke({"messages": [...]}, config={"callbacks": [cb]})

The callback emits one inbound event per tool call entry and one
outbound event per tool call exit/error, both tagged with the same
run_id so they appear together on Hopframe's agent-run timeline.
"""

from __future__ import annotations

import json
import time
from typing import Any, Dict, Optional

try:
    from langchain.callbacks.base import BaseCallbackHandler  # type: ignore
except ImportError as e:
    raise ImportError(
        "hopframe.integrations.langchain requires the `langchain` package. "
        "Install it with: pip install langchain"
    ) from e

from ..client import Hopframe, new_run_id


class HopframeCallback(BaseCallbackHandler):
    """Emits Hopframe events on tool entry/exit/error.

    Attaches to LangChain or LangGraph agents via `callbacks=` config.
    Events from the same agent run share an `agent_run_id` so they
    correlate on the Hopframe timeline (and with any concurrent MCP
    sensor events).
    """

    def __init__(
        self,
        hf: Hopframe,
        run_id: Optional[str] = None,
        framework: str = "langchain",
    ) -> None:
        self._hf = hf
        self._run_id = run_id or new_run_id()
        self._framework = framework
        # Track tool start times so we can compute latency on end.
        self._start_times: Dict[str, float] = {}

    @property
    def run_id(self) -> str:
        return self._run_id

    # -- LangChain hooks --

    def on_tool_start(
        self,
        serialized: Dict[str, Any],
        input_str: str,
        *,
        run_id=None,
        parent_run_id=None,
        tags=None,
        metadata=None,
        inputs=None,
        **kwargs: Any,
    ) -> None:
        tool = (serialized or {}).get("name") or (serialized or {}).get("id", ["unknown"])[-1]
        try:
            args = json.loads(input_str) if input_str else {}
        except (TypeError, ValueError):
            args = {"_raw_input": input_str}
        self._start_times[str(run_id or "")] = time.time()
        self._hf.emit_tool_call(
            tool=tool,
            args=args,
            run_id=self._run_id,
            framework=self._framework,
        )

    def on_tool_end(
        self,
        output: Any,
        *,
        run_id=None,
        parent_run_id=None,
        tags=None,
        **kwargs: Any,
    ) -> None:
        latency = self._latency_micros(run_id)
        try:
            tool = kwargs.get("name", "")
        except Exception:
            tool = ""
        result: Any
        if isinstance(output, (dict, list, str, int, float, bool)) or output is None:
            result = output
        else:
            result = str(output)
        self._hf.emit_tool_result(
            tool=tool or "unknown",
            result=result,
            run_id=self._run_id,
            framework=self._framework,
            latency_micros=latency,
        )

    def on_tool_error(
        self,
        error: BaseException,
        *,
        run_id=None,
        parent_run_id=None,
        tags=None,
        **kwargs: Any,
    ) -> None:
        latency = self._latency_micros(run_id)
        self._hf.emit_tool_result(
            tool=kwargs.get("name", "unknown"),
            result=None,
            run_id=self._run_id,
            framework=self._framework,
            latency_micros=latency,
            error=str(error),
        )

    # -- helpers --

    def _latency_micros(self, run_id: Any) -> int:
        start = self._start_times.pop(str(run_id or ""), None)
        if start is None:
            return 0
        return int((time.time() - start) * 1_000_000)
