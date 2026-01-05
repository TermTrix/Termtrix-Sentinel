# ==================================
# NEW CODE IMPLEMENTATION (05-01-2026)
# ==================================

"""
Action planning logic
Converts triage verdict into concrete actions
"""
from typing import List
from app.models.action import Action, ActionType, ActionCategory, ActionPriority
from app. logger import logger

# Configurable threshold
AUTO_CLOSE_CONFIDENCE = 0.7


async def plan_actions(state: dict) -> List[Action]:
    """
    Plan actions based on triage verdict
    
    Args:
        state: Dictionary containing: 
            - phase_2_result:  Triage verdict and confidence
            - indicator: The suspicious indicator (IP, domain, etc.)
            - alert_id: Alert identifier
    
    Returns:
        List of Action objects
    """
    triage = state.get("phase_2_result", {})
    verdict = triage.get("verdict", "").lower()
    confidence = triage.get("confidence", 0.0)
    indicator = state.get("indicator", "unknown")
    
    logger.info(f"Planning actions for verdict={verdict}, confidence={confidence}")
    
    actions = []
    
    # BENIGN:  High confidence → Auto-close
    if verdict == "benign" and confidence >= AUTO_CLOSE_CONFIDENCE: 
        actions.append(Action(
            action=ActionType. CLOSE_ALERT,
            target=state.get("alert_id", "unknown"),
            system="sentinel",
            reason=f"Benign verdict with high confidence ({confidence:. 2f})",
            requires_approval=False,
            action_category=ActionCategory.TRIAGE,
            priority=ActionPriority.LOW
        ))
    
    # BENIGN: Low confidence → Monitor
    elif verdict == "benign" and confidence < AUTO_CLOSE_CONFIDENCE:
        actions. append(Action(
            action=ActionType.MONITOR,
            target=indicator,
            system="sentinel",
            reason=f"Benign but low confidence ({confidence:.2f}) - monitor for 24h",
            requires_approval=True,
            action_category=ActionCategory.TRIAGE,
            priority=ActionPriority.LOW
        ))
    
    # SUSPICIOUS:  Escalate to L2
    elif verdict == "suspicious": 
        actions.append(Action(
            action=ActionType. ESCALATE,
            target=state.get("alert_id", "unknown"),
            system="ticketing",
            reason=f"Suspicious activity detected (confidence: {confidence:.2f})",
            requires_approval=True,
            action_category=ActionCategory.TRIAGE,
            priority=ActionPriority. MEDIUM
        ))
        
        actions.append(Action(
            action=ActionType.CREATE_TICKET,
            target="security-ops-team",
            system="jira",
            reason=f"Investigation required for {indicator}",
            requires_approval=False,
            action_category=ActionCategory.COMMUNICATION,
            priority=ActionPriority. MEDIUM
        ))
    
    # MALICIOUS: Block and isolate
    elif verdict == "malicious":
        # Block IP/domain
        actions.append(Action(
            action=ActionType. BLOCK_IP if "." in indicator else ActionType.BLOCK_DOMAIN,
            target=indicator,
            system="firewall",
            reason=f"Malicious indicator confirmed (confidence: {confidence:.2f})",
            requires_approval=True,
            justification_required=True,
            action_category=ActionCategory. CONTAINMENT,
            priority=ActionPriority. IMMEDIATE
        ))
        
        # Isolate affected host (if we have that info)
        affected_host = state.get("affected_host")
        if affected_host: 
            actions.append(Action(
                action=ActionType.ISOLATE_HOST,
                target=affected_host,
                system="edr",
                reason=f"Host contacted malicious indicator {indicator}",
                requires_approval=True,
                action_category=ActionCategory.CONTAINMENT,
                priority=ActionPriority.IMMEDIATE
            ))
        
        # Create high-priority ticket
        actions.append(Action(
            action=ActionType.CREATE_TICKET,
            target="incident-response-team",
            system="jira",
            reason=f"Confirmed malware:  {indicator}",
            requires_approval=False,
            action_category=ActionCategory.COMMUNICATION,
            priority=ActionPriority. IMMEDIATE
        ))
        
        # Notify security team
        actions.append(Action(
            action=ActionType.NOTIFY_SLACK,
            target="#security-alerts",
            system="slack",
            reason=f"🚨 Malicious activity:  {indicator}",
            requires_approval=False,
            action_category=ActionCategory.COMMUNICATION,
            priority=ActionPriority. IMMEDIATE
        ))
    
    # NEEDS_INVESTIGATION: Create detailed ticket
    elif verdict == "needs_investigation":
        actions.append(Action(
            action=ActionType.CREATE_TICKET,
            target="security-ops-team",
            system="jira",
            reason=f"Ambiguous indicator requires investigation:  {indicator}",
            requires_approval=False,
            action_category=ActionCategory.COMMUNICATION,
            priority=ActionPriority.HIGH
        ))
        
        actions.append(Action(
            action=ActionType. ESCALATE,
            target=state.get("alert_id", "unknown"),
            system="ticketing",
            reason="Insufficient data for automated decision",
            requires_approval=True,
            action_category=ActionCategory.TRIAGE,
            priority=ActionPriority.HIGH
        ))
    
    logger.info(f"Planned {len(actions)} actions")
    return actions













# ==================================
# OLD CODE - TO BE DELETED
# ==================================


# from app.models.action import Action
# from typing import List


# phase2_result = {
#     "verdict": "benign",
#     "confidence": 0.8,
#     "reason": "The IP address is associated with a known ISP in India and has no malicious detections on VirusTotal.",
#     "recommended_action": "close_alert",
#     "requires_human_review": False
# }


# AUTO_CLOSE_CONFIDENCE = 0.7

# async def plan_actions(state: dict) -> List[Action]:
#     # triage = state.get("phase_2_result")
#     verdict = state.get("phase_2_result",{}).get("verdict")
#     confidence = state.get("phase_2_result",{}).get("confidence", 0.0)

#     indicator = state.get("indicator")
#     alert_id = state.get("alert_id", "unknown")

#     actions: List[Action] = []

#     print(state,"PHASE 2")

#     # 🟢 BENIGN
#     if verdict == "benign":
#         if confidence >= AUTO_CLOSE_CONFIDENCE:
#             actions.append(
#                 Action(
#                     action="close_alert",
#                     target=alert_id,
#                     reason="Benign verdict with high confidence",
#                     requires_approval=False,
#                     action_category="auto",
#                     policy_version="v1"
#                 )
#             )
#         else:
#             actions.append(
#                 Action(
#                     action="monitor",
#                     target=indicator,
#                     reason="Benign verdict but confidence below threshold",
#                     requires_approval=True,
#                     action_category="approval",
#                     policy_version="v1"
#                 )
#             )

#     # 🟡 SUSPICIOUS
#     elif verdict == "suspicious":
#         actions.append(
#             Action(
#                 action="escalate_to_tier2",
#                 target=alert_id,
#                 reason="Suspicious activity requires analyst review",
#                 requires_approval=True,
#                 action_category="approval",
#                 policy_version="v1"
#             )
#         )

#     # 🔴 MALICIOUS
#     elif verdict == "malicious":
#         actions.append(
#             Action(
#                 action="block_ip",
#                 target=indicator,
#                 system="firewall",
#                 reason="Malicious indicator confirmed",
#                 requires_approval=True,
#                 justification_required=True,
#                 action_category="high_risk",
#                 policy_version="v1"
#             )
#         )

#     return actions
