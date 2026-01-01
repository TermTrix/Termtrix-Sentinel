from typing import Dict, List, Any, TypedDict, Annotated
from langgraph.graph.message import AnyMessage, add_messages



class EnrichmentState(TypedDict, total=False):
    alert_id: str
    indicator: str
    indicator_type: str

    enrichment: Dict[str, Any]
    phase_2_result: Dict[str, Any]

    decision: Dict[str, Any]
    requires_phase_3: bool
    approved: bool

    audit_log: List[str]
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

    
