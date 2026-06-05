"""CrewAI integration for Hopframe.

CrewAI agents wrap tools as callable objects with a `_run` method.
The `wrap_tool` helper here decorates any CrewAI Tool so each
invocation emits an inbound event before the call and an outbound
event after, with the same agent_run_id correlating the events on
the Hopframe timeline.

Usage:

    from crewai import Agent, Task, Crew
    from crewai_tools import SerperDevTool
    from hopframe import Hopframe, new_run_id
    from hopframe.integrations.crewai import wrap_tool

    hf = Hopframe("http://localhost:7090")
    run_id = new_run_id()

    raw_search = SerperDevTool()
    search = wrap_tool(hf, raw_search, run_id=run_id)

    agent = Agent(role="researcher", tools=[search], ...)
    crew = Crew(agents=[agent], tasks=[...])
    crew.kickoff()

If you want every tool in a crew traced without per-tool wrapping,
use `wrap_agent` to wrap all of an agent's tools at once:

    agent = Agent(role="researcher", tools=[t1, t2, t3], ...)
    wrap_agent(hf, agent, run_id=run_id)
"""

from __future__ import annotations

import json
import time
from typing import Any, Iterable

from ..client import Hopframe


def wrap_tool(hf: Hopframe, tool: Any, run_id: str, framework: str = "crewai") -> Any:
    """Decorate a CrewAI tool's `_run` method with Hopframe emission.

    Returns the same tool instance for fluent use. CrewAI tools are
    duck-typed; we only require `name` and `_run` on the object.
    """
    if not hasattr(tool, "_run"):
        raise TypeError("wrap_tool: object %r has no _run method" % tool)
    name = getattr(tool, "name", type(tool).__name__)

    original = tool._run  # type: ignore[attr-defined]

    def wrapped(*args: Any, **kwargs: Any) -> Any:
        try:
            args_dict = _coerce_args(args, kwargs)
        except Exception:
            args_dict = {"_args": [str(a) for a in args], "_kwargs": {k: str(v) for k, v in kwargs.items()}}
        hf.emit_tool_call(tool=name, args=args_dict, run_id=run_id, framework=framework)
        start = time.time()
        try:
            result = original(*args, **kwargs)
        except Exception as e:
            latency = int((time.time() - start) * 1_000_000)
            hf.emit_tool_result(
                tool=name, result=None, run_id=run_id, framework=framework,
                latency_micros=latency, error=str(e),
            )
            raise
        latency = int((time.time() - start) * 1_000_000)
        hf.emit_tool_result(
            tool=name,
            result=result if isinstance(result, (dict, list, str, int, float, bool)) or result is None else str(result),
            run_id=run_id, framework=framework, latency_micros=latency,
        )
        return result

    tool._run = wrapped  # type: ignore[attr-defined]
    return tool


def wrap_agent(hf: Hopframe, agent: Any, run_id: str, framework: str = "crewai") -> Any:
    """Wrap every tool on a CrewAI Agent with Hopframe emission.

    Looks at `agent.tools` (the standard CrewAI Agent attribute) and
    decorates each one in place. Returns the same agent for chaining.
    """
    tools: Iterable[Any] = getattr(agent, "tools", None) or []
    for t in tools:
        try:
            wrap_tool(hf, t, run_id=run_id, framework=framework)
        except TypeError:
            # tool isn't shaped as we expected, skip rather than blow up
            continue
    return agent


def _coerce_args(args: tuple, kwargs: dict) -> dict:
    """Best-effort: turn the tool invocation into a JSON-serializable dict."""
    out: dict = {}
    if args:
        # Try to JSON-serialize positional args; fall back to repr.
        try:
            out["_args"] = json.loads(json.dumps(list(args), default=str))
        except Exception:
            out["_args"] = [repr(a) for a in args]
    if kwargs:
        try:
            out.update(json.loads(json.dumps(kwargs, default=str)))
        except Exception:
            out["_kwargs"] = {k: repr(v) for k, v in kwargs.items()}
    return out
