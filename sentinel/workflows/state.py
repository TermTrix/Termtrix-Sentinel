from typing import Dict, List, Any, TypedDict,Annotated
from langgraph.graph.message import AnyMessage, add_messages

class EnrichmentState():
    state: str = ""
    indicator: str = ""
    whois: Dict = Dict[str, Any]
    geoip: Dict = Dict[str, Any]
    virustotal: Dict = Dict[str, Any]
    sumary: Dict = Dict[str, Any]
    messages: Annotated[List[AnyMessage], add_messages]



