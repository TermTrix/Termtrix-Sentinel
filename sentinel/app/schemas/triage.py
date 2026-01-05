from enum import Enum
from pydantic import BaseModel, Field
from typing import Dict


class Verdict(str, Enum):
    """Triage verdict options (lowercase to match LLM output)"""
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    NEEDS_INVESTIGATION = "needs_investigation" # underscore, not space


class RecommendedAction(str, Enum):
    """Recommend actions based on triage verdict"""
    CLOSE_ALERT = "close_alert"
    MONITOR = "monitor"
    ESCALATE_TO_TIER2 = "escalate_to_tier2"
    INVESTIGATE_FURTHER = "investigate_further"


class Triage(BaseModel):
    """Triage result from AI analysis"""

    # Correction : Type is Verdict enum (not str)
    verdict: Verdict
    confidence: float = Field(
        ge=0.0, 
        le=1.0, 
        description="Confidence score between 0 and 1"
    )

    reason: str = Field(description="short, evidence-based explanation")

    # Correction : Type is RecommendedAction enum (not str)
    recommended_action: RecommendedAction
    requires_human_review: bool

class TriageResult(BaseModel):
    """Top-level triage response"""
    
    # Correction : Direct Triage object (not Dict[str, Triage])
    triage: Triage
   
