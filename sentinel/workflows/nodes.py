
from mcp_server.threat_intel.tools.whois import call_whois,call_virustotal,call_geoip
from workflows.state import EnrichmentState as StateGraph


async def whois_node(state:StateGraph) -> StateGraph :
    state["whois"] = await call_whois(indicator=state["indicator"])
    return state

async def geoip_node(state:StateGraph) -> StateGraph :
    state["geoip"] = await call_geoip(indicator=state["indicator"])
    return state

async def vt_node(state:StateGraph) -> StateGraph :
    state["virustotal"] = await call_virustotal(indicator=state["indicator"])
    return state



# async def summary_node (state:StateGraph) -> StateGraph:
#     state['sumary'] = 