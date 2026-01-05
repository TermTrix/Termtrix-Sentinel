# ==================================
# NEW CODE IMPLEMENTATION (05-01-2026)
# ==================================


"""
Action models for Phase 3
"""
from pydantic import BaseModel
from typing import Optional
from enum import Enum
from datetime import datetime


class ActionType(str, Enum):
    """Types of actions that can be executed"""
    BLOCK_IP = "block_ip"
    BLOCK_DOMAIN = "block_domain"
    ISOLATE_HOST = "isolate_host"
    KILL_PROCESS = "kill_process"
    QUARANTINE_FILE = "quarantine_file"
    CREATE_TICKET = "create_ticket"
    NOTIFY_SLACK = "notify_slack"
    NOTIFY_EMAIL = "notify_email"
    CLOSE_ALERT = "close_alert"
    ESCALATE = "escalate"
    MONITOR = "monitor"


class ActionCategory(str, Enum):
    """Categories of actions"""
    CONTAINMENT = "containment"      # Block, isolate
    ERADICATION = "eradication"      # Kill, quarantine
    COMMUNICATION = "communication"  # Notify, create ticket
    TRIAGE = "triage"                # Close, escalate, monitor


class ActionPriority(str, Enum):
    """Action priority levels"""
    IMMEDIATE = "immediate"  # Execute ASAP
    HIGH = "high"            # Within 5 minutes
    MEDIUM = "medium"        # Within 30 minutes
    LOW = "low"              # Best effort


class Action(BaseModel):
    """
    Represents a single action to be executed
    """
    # What to do
    action: ActionType
    
    # Target (IP, hostname, process, etc.)
    target: str
    
    # Which system to execute on (firewall, EDR, ITSM, etc.)
    system: Optional[str] = None
    
    # Why we're doing this
    reason: str
    
    # Does this need human approval? 
    requires_approval: bool = True
    
    # Does this need written justification?
    justification_required: bool = False
    
    # Action category
    action_category: ActionCategory
    
    # Priority
    priority: ActionPriority = ActionPriority.HIGH
    
    # Policy version (for audit)
    policy_version: str = "1.0"
    
    # Audit fields
    created_at: Optional[datetime] = None
    executed_at: Optional[datetime] = None
    executed_by: Optional[str] = None
    execution_result: Optional[dict] = None


# ==================================
# OLD CODE - TO BE DELETED
# ==================================


# from pydantic import BaseModel
# from typing import Optional


# class Action(BaseModel):
#     action: str                  # block_ip, close_alert, isolate_host
#     target: str                  # ip, host, alert_id
#     system: Optional[str] = None # firewall, edr, jira
#     reason: str
#     requires_approval: bool
#     action_category: str
#     policy_version: str
