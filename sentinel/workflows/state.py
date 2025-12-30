from typing import Dict, List, Any, TypedDict, Annotated
from langgraph.graph.message import AnyMessage, add_messages


class EnrichmentState(TypedDict):
    alert_id: str
    indicator: str
    indicator_type: str = "49.205.34.164"
    state: str
    enrichment: Dict = Dict[str, Any]
    # geoip: Dict = Dict[str, Any]
    # virustotal: Dict = Dict[str, Any]
    execution_result: Dict = Dict[str, Any]
    phase_2_enrichment: Dict = Dict[str, Any]
    audit_log: List = List[str]
    decision: dict
    approved: bool = False
    messages: Annotated[List[AnyMessage], add_messages]
    


class Phase3State(TypedDict):
    id: str
    triage_result: Dict[str, Any]
    plan: Dict[str, Any]
    approval_required: bool
    approved: bool
    status: str
    messages: Annotated[List[AnyMessage], add_messages]



class SentinelState(TypedDict):
    alert_id: str
    indicator: str
    indicator_type: str

    enrichment: dict
    triage: dict

    decision: dict
    execution_result: dict

    
