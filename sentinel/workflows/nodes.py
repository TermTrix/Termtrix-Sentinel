from mcp_server.threat_intel.tools.whois import call_whois, call_virustotal, call_geoip
from workflows.state import EnrichmentState
from app.config import settings
from langgraph.types import interrupt


import asyncio




phase2_result = {
    "triage": {
        "verdict": "malicious",
        "confidence": 0.8,
        "reason": "The IP address is associated with a known ISP in India and has no malicious detections on VirusTotal.",
    },
    "recommended_action": "close_alert",
    "requires_human_review": False,
}


# async def alert_ingest(state:EnrichmentState) -> EnrichmentState:
#     try:
#         if "audit_log" not in state or state["audit_log"] is None:
#             state["audit_log"] = []

#         state["audit_log"].append("Alert ingested")
#         return state
#     except Exception as error:
#         print(error)
#         return None



async def phase_1_enrichment(state:EnrichmentState) -> EnrichmentState:
   try:
        whois, geoip, virustotal = await asyncio.gather(
            call_whois(indicator=state["indicator"]),
            call_geoip(indicator=state["indicator"]),
            call_virustotal(indicator=state["indicator"]),
        )
        state["enrichment"] = {
            "whois":whois,
            "geoip":geoip,
            "virustotal":virustotal
        }
        return state
   except Exception as error:
        print(error)
        return None


async def phase_2_enrichment(state:EnrichmentState) -> EnrichmentState:
    try:
        print("Phase 2 Enrichment")
        state['phase_2_enrichment'] = phase2_result
        return state
    except Exception as error:
        print(error)
        return None



async def phase_3_approval_node(state: EnrichmentState):
    return state



# async def whois_node(state: StateGraph) -> StateGraph:
#     state["whois"] = await call_whois(indicator=state["indicator"])
#     return state


# async def geoip_node(state: StateGraph) -> StateGraph:
#     state["geoip"] = await call_geoip(indicator=state["indicator"])
#     return state


# async def vt_node(state: StateGraph) -> StateGraph:
#     state["virustotal"] = await call_virustotal(indicator=state["indicator"])
#     return state


# async def summary_node (state:StateGraph) -> StateGraph:
#     state['sumary'] =


# phase_3 Nodes

import httpx

TIMEOUT = 15.0





async def fetch_phase_two_result(id: str) -> dict:
    print(f"ID-> {id}")
    return phase2_result


async def make_plan(id: str) -> dict:
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        response = await client.post(
            url=f"{settings.MAIN_SERVER}/actions/plan", json={"id": id}
        )
        response.raise_for_status()
        return response.json()



# async def check_verdict_node(state: Phase3State) -> Phase3State:
#     try:
#         response = await fetch_phase_two_result(id=state["id"])
#         state["triage_result"] = response
#         state["isVerdictAvailable"] = True
#         return state

#     except Exception as error:
#         return None




# async def plan_actions_node(state: Phase3State) -> Phase3State:
#     try:

#         print(state, "++++++++++++++++")
#         response = await make_plan(id=state["id"])
#         state['plan'] = response
#         return state

#     except Exception as error:
#         return None

async def plan_actions_node(state:dict):
    triage = state["triage_result"]["triage"]["verdict"]

    if triage == "benign":
        state["plan"] = {
            "actions": [
                {
                    "action": "close_alert",
                    "requires_approval": False
                }
            ]
        }
        state["approval_required"] = False

    else:
        state["plan"] = {
            "actions": [
                {
                    "action": "block_ip",
                    "requires_approval": True
                }
            ]
        }
        state["approval_required"] = True

    return state




# def approval_gate_node(state: Phase3State) -> str:
#     if state["approval_required"] and not state.get("approved", False):
#         return "pending"

#     if state.get("approved") is False:
#         return "rejected"

#     return "approved"







# async def checking_action_node(state:Phase3State) ->Phase3State:
#     try:
#         pass
#     except Exception as error:
#         return None