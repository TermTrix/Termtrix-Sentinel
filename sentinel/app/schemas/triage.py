from enum import Enum
from pydantic import BaseModel, Field
from typing import Dict


class Verdict(str, Enum):
    BENIGN = "BENIGN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    NEEDS_INVESTIGATION = "NEEDS INVESTIGATION"


class RecommendedAction(str, Enum):
    CLOSE_ALERT = "close_alert"
    MONITOR = "monitor"
    ESCALATE_TO_TIER2 = "escalate_to_tier2"
    INVESTIGATE_FURTHER = "investigate_further"


class Triage(BaseModel):
    verdict: str = Verdict
    confidence: float = Field(
        ge=0.0, le=1.0, description="Confidence score between 0 and 1"
    )

    reason: str = Field(description="short, evidence-based explanation")

    recommended_action: str = RecommendedAction
    requires_human_review: bool

class TriageResult(BaseModel):
    triage: Dict[str, Triage]
   
