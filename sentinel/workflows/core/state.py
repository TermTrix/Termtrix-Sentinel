from typing import Dict, List, Any, TypedDict, Annotated
from langgraph.graph.message import AnyMessage, add_messages

import operator


class Action(TypedDict):
    action: str
    target: str
    system: str | None
    reason: str
    requires_approval: bool
    action_category: str
    policy_version: str


class EnrichmentState(TypedDict, total=False):
    alert_id: str
    indicator: str
    indicator_type: str

    enrichment: Dict[str, Any]
    phase_2_result: Dict[str, Any]

    decision: Dict[str, Any]
    requires_further_action: bool
    status: str
    approved: bool = False

    actions : List[Action]

    audit_log: List[str]
    messages: Annotated[List[AnyMessage], add_messages]

    


