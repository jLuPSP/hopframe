"""Minimal example: a LangGraph ReAct agent wired to Hopframe.

Run alongside `make demo` (which starts the control plane on :7090):

    pip install -e .[langchain]
    pip install langgraph langchain-anthropic
    python examples/langgraph_agent.py

Every tool call inside the agent run will appear on the Hopframe
live UI at http://localhost:7090, tagged with the run_id this
example mints. Open the UI, click the run in "agent runs", and you
get the forensic timeline of the agent's tool usage.
"""

from __future__ import annotations

import os

from hopframe import Hopframe, new_run_id
from hopframe.integrations.langchain import HopframeCallback


def main() -> None:
    # Lazy imports so this example doesn't fail to load just from
    # importing hopframe, only when actually run.
    from langchain_anthropic import ChatAnthropic
    from langchain_core.tools import tool
    from langgraph.prebuilt import create_react_agent

    @tool
    def fetch_url(url: str) -> str:
        """Fetch a URL and return its body. Demo tool, does nothing real."""
        return f"(simulated body of {url})"

    @tool
    def lookup_customer(record_id: str) -> str:
        """Look up a customer record by id. Demo tool, does nothing real."""
        return f"(simulated record for {record_id})"

    model = ChatAnthropic(model="claude-3-5-sonnet-latest")
    agent = create_react_agent(model, tools=[fetch_url, lookup_customer])

    hf = Hopframe(
        url=os.environ.get("HOPFRAME_URL", "http://localhost:7090"),
        api_token=os.environ.get("HOPFRAME_API_TOKEN", ""),
    )
    run_id = new_run_id()
    cb = HopframeCallback(hf, run_id=run_id, framework="langgraph")

    print(f"agent run_id: {run_id}")
    result = agent.invoke(
        {"messages": [("user", "Fetch https://example.com/health and look up customer A1B2C3.")]},
        config={"callbacks": [cb]},
    )
    print("final:", result["messages"][-1].content[:200])

    print("hopframe stats:", hf.stats())
    hf.close()


if __name__ == "__main__":
    main()
