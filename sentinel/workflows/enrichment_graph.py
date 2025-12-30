from langgraph.graph import StateGraph,START,END
from workflows.state import EnrichmentState
from workflows.nodes import  alert_ingest, phase_1_enrichment,phase_2_enrichment,phase_3_approval_node
from langgraph.checkpoint.memory import MemorySaver
from langgraph.prebuilt import tools_condition, ToolNode
from langchain_mcp_adapters.tools import load_mcp_tools

from langchain_core.messages import SystemMessage
from app.config import settings
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.redis.aio import AsyncRedisSaver
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from langgraph.store.postgres.aio import AsyncPostgresStore  
from langgraph.store.base import BaseStore
from app.config import settings

from langgraph.types import Command,interrupt
from psycopg import Connection

from langgraph.checkpoint.postgres import PostgresSaver

model = ChatGoogleGenerativeAI(
    model="gemini-2.0-flash", temperature=0, api_key=settings.GEMINI_API_KEY
)


DB_URI = settings.DB_URI



async def create_enrichment_graph(store: BaseStore, checkpointer):
    try:
    
        graph_builder = StateGraph(EnrichmentState)

        # graph_builder.add_node("call_model", call_model)

        graph_builder.add_node("alert_ingest", alert_ingest)
        graph_builder.add_node("approval_node", approval_node)
        graph_builder.add_node("phase_1_enrichment", phase_1_enrichment)
        graph_builder.add_node("phase_2_enrichment", phase_2_enrichment)
        graph_builder.add_node("phase_3_approval_node", phase_3_approval_node)

        graph_builder.add_edge(START, "alert_ingest")
        # graph_builder.add_edge("    ", "alert_ingest")
        graph_builder.add_edge("alert_ingest", "phase_1_enrichment")
        graph_builder.add_edge("phase_1_enrichment", "phase_2_enrichment")

        graph_builder.add_edge("phase_2_enrichment", "phase_3_approval_node")

        graph_builder.add_conditional_edges('phase_3_approval_node',approval_router,{
            "approved": "phase_3_approval_node",
            "not_approved": END
        })


        graph_builder.add_edge("phase_3_approval_node", "phase_3_approval_node")


    #     graph_builder.add_conditional_edges(
    #         "approval_node",
    #         approval_router,
    #         {
    #             "approved": "phase_1_enrichment",
    #             "not_approved": END
    #         }
    # )
        graph_builder.add_edge("phase_3_approval_node", END)
        # graph_builder.add_edge("approval_node", END)

        graph = graph_builder.compile(checkpointer=checkpointer,store=store)

        return graph

    except Exception as error:
        print(error)
        return None



def phase_3_approval_node(state: EnrichmentState):
    need_human_review = state.get("phase_2_enrichment",None).get("requires_human_review",False)
    if need_human_review:
        message = "This ip needs phase three check , what do you want to do?"
        state["approved"] = True
    else:
        message = "This ip does not need phase three check , what do you want to do?"
        state["approved"] = False

    decision = interrupt(message)
    return {"approved": decision}




def approval_node(state: EnrichmentState):
    decision = interrupt("Do you approve this action?")
    print("_------- approval_node",decision)
    return {"approved": decision}

def approval_router(state: EnrichmentState):
    print("_------- approval_router",state)
    return "approved" if state["approved"] else "not_approved"



