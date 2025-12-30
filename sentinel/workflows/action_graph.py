from langgraph.graph import StateGraph, START, END
from workflows.state import EnrichmentState, Phase3State
from workflows.nodes import plan_actions_node
from langgraph.checkpoint.memory import MemorySaver
from langgraph.prebuilt import tools_condition, ToolNode
from langchain_mcp_adapters.tools import load_mcp_tools

from langchain_core.messages import SystemMessage
from app.config import settings
from langchain_google_genai import ChatGoogleGenerativeAI
from langgraph.types import Interrupt

model = ChatGoogleGenerativeAI(
    model="gemini-2.0-flash", temperature=0, api_key=settings.GEMINI_API_KEY
)


# async def create_phase_three_graph(tools):
#     try:

#         print("HELLO FROM PLAN GRAPH")

#         graph_builder = StateGraph(Phase3State)
#         graph_builder.add_node("verdict_node", check_verdict_node)
#         graph_builder.add_node("plan_node", plan_actions_node)
        
#         graph_builder.add_node("tools",ToolNode(tools))
        
#         graph_builder.add_node("action_node", checking_action_node)

#         graph_builder.add_edge(START, "verdict_node")
#         graph_builder.add_edge("verdict_node", "plan_node")
#         graph_builder.add_edge("plan_node", END)

#         graph = graph_builder.compile(checkpointer=MemorySaver())

#         return graph

#     except Exception as error:
#         print(str(error), "FROM GRAPH")


# from app.main import execute_actions_node


from langchain_google_genai import ChatGoogleGenerativeAI
from app.config import settings

MCP_SERVER = "http://localhost:8000/analytics/mcp"

from langchain_mcp_adapters.client import MultiServerMCPClient
GEMINI_API_KEY = settings.GEMINI_API_KEY

client = MultiServerMCPClient(
    {
        "sentinel": {
            "transport": "http",
            "url": "http://localhost:8000/analytics/mcp",
        },
        "sentinel_phase_3": {
            "transport": "http",
            "url": "http://localhost:8000/actions/mcp",
        },
    }
)


llm = ChatGoogleGenerativeAI(
    model="gemini-2.0-flash", temperature=0, api_key=GEMINI_API_KEY
)


async def execute_actions_node(state: Phase3State) -> Phase3State:
    async with client.session("sentinel_phase_3") as session:
        tools = await load_mcp_tools(session)

        for action in state["plan"]["actions"]:
            if action["action"] == "block_ip":
                await tools["block_ip"]({"ip": "49.205.34.164"})

    state["status"] = "executed"
    return state



async def create_phase_three_graph(session,tools):
    graph = StateGraph(Phase3State)

    graph.add_node("chat_node",chat_node)
    # graph.add_node("verdict_node", check_verdict_node)
    graph.add_node("plan_node", plan_actions_node)
    # graph.add_node("tool_node", ToolNode(tools, Interrupt=))

    graph.set_entry_point("verdict_node")
    graph.add_edge("verdict_node", "plan_node")

    graph.add_conditional_edges(
        "plan_node",
        approval_gate_node,
        {
            "pending": END,
            "rejected": END,
            "approved": "tool_node",
        },
    )

    graph.add_conditional_edges("chat_node", tools_condition, {"tools": "tool_node", "__end__": END})
    
    # graph.add_edge("execute_node", END)

    return graph.compile(checkpointer=MemorySaver())



from typing import Dict, List, Any, TypedDict, Annotated,Literal
from langchain.messages import AIMessage

def chat_after_plan_node(state: Phase3State) -> Phase3State:
    """
    LLM decides:
    - If more info is needed: ask a question, set awaiting_user=True => graph pauses.
    - If sufficient info: route directly to tools.
    """
    # Call your model here (pseudo)
    # result = llm([...state["messages"], system + instructions based on state["plan"]])
    # Decide whether to ask question or go to tools

    needs_more_info = ...  
    if needs_more_info:
        question = "Before proceeding, please confirm X / provide Y."
        return {
            "messages": state["messages"] + [AIMessage(content=question)],
            "awaiting_user": True,
        }

    return {
        "awaiting_user": False,
        # maybe also add a “go ahead with tools” message
    }
    
    
def route_after_chat(state: Phase3State) -> Literal["tool_node", "__end__"]:
    # If we still need user input, stop graph here (your app waits for user).
    if state.get("awaiting_user"):
        return "__end__"  # stop run; your app will resume with new user msg
    return "tool_node"




async def create_phase_three_graph(session, tools):
    graph = StateGraph(Phase3State)

    graph.add_node("chat_node", chat_node)              # your existing chat node
    # graph.add_node("verdict_node", check_verdict_node)
    graph.add_node("plan_node", plan_actions_node)
    graph.add_node("clarify_node", chat_after_plan_node)  # NEW
    graph.add_node("tool_node", ToolNode(tools))

    graph.set_entry_point("verdict_node")
    graph.add_edge("verdict_node", "plan_node")

    # After plan -> go to clarify_node, which might ask questions
    graph.add_edge("plan_node", "clarify_node")

    # From clarify_node decide: stop (await user) or go to tools
    graph.add_conditional_edges(
        "clarify_node",
        route_after_chat,
        {
            "tool_node": "tool_node",
            "__end__": END,
        },
    )

    # Existing chat_node -> tools logic (if you still need it)
    graph.add_conditional_edges(
        "chat_node",
        tools_condition,
        {"tools": "tool_node", "__end__": END},
    )

    return graph.compile(checkpointer=MemorySaver())
