# ==================================
# NEW CODE IMPLEMENTATION (05-01-2026)
# ==================================


"""
Approval workflow models for Phase 3
"""
from pydantic import BaseModel, Field
from typing import List, Optional
from enum import Enum
from datetime import datetime
from app.models.action import Action


class ApprovalStatus(str, Enum):
    """Approval request status"""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


class ApprovalDecisionReason(str, Enum):
    """Reasons for approval/rejection"""
    # Approval reasons
    CONFIRMED_THREAT = "confirmed_threat"
    HIGH_CONFIDENCE = "high_confidence"
    STANDARD_PROCEDURE = "standard_procedure"
    
    # Rejection reasons
    FALSE_POSITIVE = "false_positive"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    TOO_AGGRESSIVE = "too_aggressive"
    NEEDS_MORE_INVESTIGATION = "needs_more_investigation"


class Approval(BaseModel):
    """
    Represents an approval request for actions
    """
    # Unique identifier
    approval_id: str
    
    # Actions to be approved
    actions: List[Action] = Field(min_length=1)
    
    # Current status
    status: ApprovalStatus = ApprovalStatus. PENDING
    
    # Who approved/rejected
    approved_by: Optional[str] = None
    
    # Why approved/rejected
    decision_reason: Optional[ApprovalDecisionReason] = None
    
    # Additional notes from approver
    notes: Optional[str] = None
    
    # Context from alert
    alert_id: Optional[str] = None
    indicator:  Optional[str] = None
    triage_verdict: Optional[str] = None
    triage_confidence: Optional[float] = None
    
    # Audit timestamps
    created_at: datetime = Field(default_factory=datetime.utcnow)
    approved_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None  # Auto-expire after X hours
    
    # Expiry configuration
    ttl_seconds: int = 3600  # 1 hour default

    def is_expired(self) -> bool:
        """Check if approval has expired"""
        if self.expires_at and datetime.utcnow() > self.expires_at:
            return True
        return False
    
# ==================================
# OLD CODE - TO BE DELETED
# ==================================



# from pydantic import BaseModel
# from typing import List
# from app.models.action import Action


# class Approval(BaseModel):
#     approval_id: str
#     actions: List[Action]
#     status: str                  # pending / approved / rejected
#     approved_by: str | None = None
