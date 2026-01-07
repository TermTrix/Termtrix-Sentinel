from langgraph.graph import StateGraph,START,END
from sentinel.workflows.core.state import EnrichmentState
# from workflows.nodes import phase_1_enrichment,phase_2_enrichment,phase_3_approval_node


from langgraph.store.base import BaseStore
from sentinel.app.config import settings



#NODES

from sentinel.workflows.phases.phase1 import Phase1Enrichment
from sentinel.workflows.phases.phase2 import Phase2Triage
from sentinel.workflows.phases.phase3 import ActionPlanner
from sentinel.workflows.phases.ingest import AlertIngestPhase

from sentinel.workflows.action.action import IsMoreActionNeeded,WaitingForApproval
from sentinel.workflows.action.close_ticket_and_email import CloseTicketAndEmail


DB_URI = settings.DB_URI



async def create_enrichment_graph(store: BaseStore, checkpointer):
    graph = StateGraph(EnrichmentState)

    graph.add_node("ingest", AlertIngestPhase())
    graph.add_node("phase1", Phase1Enrichment())
    graph.add_node("phase2", Phase2Triage())
    graph.add_node("phase3", ActionPlanner())
    graph.add_node("is_action_needed", IsMoreActionNeeded())
    graph.add_node("close_ticket_and_email", CloseTicketAndEmail())
    graph.add_node("waiting_for_approval", WaitingForApproval())

    graph.add_edge(START, "ingest")
    graph.add_edge("ingest", "phase1")
    graph.add_edge("phase1", "phase2")

    graph.add_edge("phase2", "phase3")
    graph.add_edge("phase3", "is_action_needed")


    graph.add_conditional_edges(
        "is_action_needed",
        action_router,
        {
            "proceed": "waiting_for_approval",
            "close": "close_ticket_and_email",
        },
    )
    graph.add_edge("close_ticket_and_email", END)


    

    return graph.compile(store=store, checkpointer=checkpointer)





def action_router(state: EnrichmentState):
    return "proceed" if state.get("requires_further_action") else "close"
















# async def create_enrichment_graph(store: BaseStore, checkpointer):
#     try:
    
#         graph_builder = StateGraph(EnrichmentState)

#         # graph_builder.add_node("call_model", call_model)

#         graph_builder.add_node("alert_ingest", alert_ingest)
#         graph_builder.add_node("approval_node", approval_node)
#         graph_builder.add_node("phase_1_enrichment", phase_1_enrichment)
#         graph_builder.add_node("phase_2_enrichment", phase_2_enrichment)
#         graph_builder.add_node("phase_3_approval_node", phase_3_approval_node)
#         graph_builder.add_node("is_pahse_3_required", is_pahse_3_required)

#         graph_builder.add_edge(START, "alert_ingest")
#         # graph_builder.add_edge("    ", "alert_ingest")
#         graph_builder.add_edge("alert_ingest", "phase_1_enrichment")
#         graph_builder.add_edge("phase_1_enrichment", "phase_2_enrichment")

#         graph_builder.add_edge("phase_2_enrichment", "is_pahse_3_required")

#         # graph_builder.add_edge("is_pahse_3_required", "is_pahse_3_required_router")

#         graph_builder.add_conditional_edges("is_pahse_3_required",is_pahse_3_required_router,{
#             "proceed": "phase_3_approval_node",
#             "close": END
#         })


#         graph_builder.add_edge("phase_3_approval_node", "phase_3_approval_node")

#         graph_builder.add_edge("phase_3_approval_node", END)

#         graph = graph_builder.compile(checkpointer=checkpointer,store=store)

#         return graph

#     except Exception as error:
#         print(error)
#         return None



# def is_pahse_3_required(state: EnrichmentState):
#     need_human_review = state.get("phase_2_enrichment",None).get("requires_human_review",False)
#     if need_human_review:
#         message = "This ip needs phase three check , so agent will procced to phase 3 check"
#         state["is_pahse_3_required"] = "proceed"
#         state["audit_log"].append(message)
#         return state
#     else:
#         message = "This ip does not need phase three check , so agent will close the alert"
#         state["is_pahse_3_required"] = "close"
#         state["audit_log"].append(message)
#         return state

    




# def is_pahse_3_required_router(state: EnrichmentState):
#     if state["is_pahse_3_required"] == "proceed":
#         return "phase_3_approval_node"
#     else:
#         return "close"




# def approval_node(state: EnrichmentState):
#     decision = interrupt("Do you approve this action?")
#     print("_------- approval_node",decision)
#     return {"approved": decision}

# def approval_router(state: EnrichmentState):
#     print("_------- approval_router",state)
#     return "approved" if state["approved"] else "not_approved"






