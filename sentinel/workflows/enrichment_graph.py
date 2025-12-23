from langgraph.graph import StateGraph,START,END
from workflows.state import EnrichmentState
from workflows.nodes import whois_node, geoip_node, vt_node
from langgraph.checkpoint.memory import MemorySaver
from langgraph.prebuilt import tools_condition, ToolNode
from langchain_mcp_adapters.tools import load_mcp_tools

from langchain_core.messages import SystemMessage
from app.config import settings
from langchain_google_genai import ChatGoogleGenerativeAI


model = ChatGoogleGenerativeAI(
    model="gemini-2.0-flash", temperature=0, api_key=settings.GEMINI_API_KEY
)



async def soc_reasoning_node(state):
    prompt = SystemMessage(
        content="""
You are a SOC analyst assistant.

You are given ONE indicator.

You MUST:
- Call whois_info
- Call geoip_info
- Call virustotal_info

Use the available tools.
Do NOT invent facts.
"""
    )

    response = await model.ainvoke(
        [prompt] + state["messages"]
    )

    return {
        "messages": state["messages"] + [response]
    }


async def create_graph(session):
    try:
        
        print("HELLO FROM GRAPH")

        graph_builder = StateGraph(EnrichmentState)

        # graph_builder.add_node("whois_node", whois_node)
        # graph_builder.add_node("geo_node", geoip_node)
        # graph_builder.add_node("vt_node", vt_node)

        # graph_builder.add_edge(START,"whois_node")
        # graph_builder.add_edge("whois_node","geo_node")
        # graph_builder.add_edge("geo_node","vt_node")
        # graph_builder.add_edge("vt_node",END)
        tools = await load_mcp_tools(session)
        model.bind_tools(tools=tools)
        
        print(tools)

        
        graph_builder.add_node("reasoner", soc_reasoning_node)
        graph_builder.add_node("tools", ToolNode(tools))

        graph_builder.add_edge(START, "reasoner")
        graph_builder.add_edge("reasoner", "tools")
        graph_builder.add_conditional_edges(
            "tools",
            tools_condition,
            {
                "tools": "tools",   # loop if more tools needed
                "__end__": END
            }
        )


        graph = graph_builder.compile(checkpointer=MemorySaver())

        return graph

    except Exception as error:
        return None
