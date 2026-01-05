"""
Minimal enrichment graph to satisfy startup and health checks.
"""

from typing import Any, TypedDict
from langgraph.graph import StateGraph, END


class GraphState(TypedDict, total=False):
    input: Any
    output: Any


def passthrough(state: GraphState) -> GraphState:
    return state


def create_enrichment_graph(checkpointer):
    builder = StateGraph(GraphState)
    builder.add_node("passthrough", passthrough)
    builder.set_entry_point("passthrough")
    builder.add_edge("passthrough", END)
    graph = builder.compile(checkpointer=checkpointer)
    return graph
