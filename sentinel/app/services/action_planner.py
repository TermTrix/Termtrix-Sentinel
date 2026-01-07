from sentinel.app.models.action import Action
from typing import List


phase2_result = {
    "verdict": "benign",
    "confidence": 0.8,
    "reason": "The IP address is associated with a known ISP in India and has no malicious detections on VirusTotal.",
    "recommended_action": "close_alert",
    "requires_human_review": False
}


AUTO_CLOSE_CONFIDENCE = 0.7

async def plan_actions(state: dict) -> List[Action]:
    # triage = state.get("phase_2_result")
    verdict = state.get("phase_2_result",{}).get("verdict")
    confidence = state.get("phase_2_result",{}).get("confidence", 0.0)

    indicator = state.get("indicator")
    alert_id = state.get("alert_id", "unknown")

    actions: List[Action] = []

    print(state,"PHASE 2")

    # 🟢 BENIGN
    if verdict == "benign":
        if confidence >= AUTO_CLOSE_CONFIDENCE:
            actions.append(
                Action(
                    action="close_alert",
                    target=alert_id,
                    reason="Benign verdict with high confidence",
                    requires_approval=False,
                    action_category="auto",
                    policy_version="v1"
                )
            )
        else:
            actions.append(
                Action(
                    action="monitor",
                    target=indicator,
                    reason="Benign verdict but confidence below threshold",
                    requires_approval=True,
                    action_category="approval",
                    policy_version="v1"
                )
            )

    # 🟡 SUSPICIOUS
    elif verdict == "suspicious":
        actions.append(
            Action(
                action="escalate_to_tier2",
                target=alert_id,
                reason="Suspicious activity requires analyst review",
                requires_approval=True,
                action_category="approval",
                policy_version="v1"
            )
        )

    # 🔴 MALICIOUS
    elif verdict == "malicious":
        actions.append(
            Action(
                action="block_ip",
                target=indicator,
                system="firewall",
                reason="Malicious indicator confirmed",
                requires_approval=True,
                justification_required=True,
                action_category="high_risk",
                policy_version="v1"
            )
        )

    return actions
