from pydantic import BaseModel
from typing import Optional


class Action(BaseModel):
    action: str                  # block_ip, close_alert, isolate_host
    target: str                  # ip, host, alert_id
    system: Optional[str] = None # firewall, edr, jira
    reason: str
    requires_approval: bool
    action_category: str
    policy_version: str
