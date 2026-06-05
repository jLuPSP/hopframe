"""hopframe, Python SDK for Hopframe.

The Go sensor handles MCP and A2A traffic. This Python SDK is for
agent frameworks that *don't* speak MCP or A2A natively, LangChain,
LangGraph, AutoGen, CrewAI, OpenAI Assistants, where you want
Hopframe events emitted directly from framework callbacks.

Two integration shapes are supported:

  1. Direct client: emit events from your own code.

       from hopframe import Hopframe
       hf = Hopframe("http://control-plane:7090", api_token="...")
       hf.emit_tool_call(tool="fetch", args={...}, run_id="run-x")

  2. Framework adapters (separately importable so this base package
     stays dependency-free):

       from hopframe.integrations.langchain import HopframeCallback
       cb = HopframeCallback(hf)
       agent.invoke({...}, config={"callbacks": [cb]})

The wire format is the same Hopframe event schema the Go sensors
use; the control plane doesn't care which side emitted the event.
"""

from .async_client import AsyncHopframe
from .client import Event, Finding, Hopframe, new_run_id

__all__ = ["Hopframe", "AsyncHopframe", "Event", "Finding", "new_run_id"]
__version__ = "0.1.0"
