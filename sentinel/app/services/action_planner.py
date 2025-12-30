from app.models.action import Action
from typing import List


phase2_result = {
    "triage": {
        "verdict": "benign",
        "confidence": 0.8,
        "reason": "The IP address is associated with a known ISP in India and has no malicious detections on VirusTotal.",
    },
    "recommended_action": "close_alert",
    "requires_human_review": False,
    "enriched_indicators": [],
}


async def plan_actions(phase2_result: dict) -> List[Action]:
    try:
        verdict = phase2_result.get("triage", {}).get("verdict")
        confidence = phase2_result.get("triage", {}).get("confidence")
        indicator = ""

        actions: List[Action] = []

        if verdict == "benign":
            actions.append(
                Action(
                    action="close_alert",
                    target=phase2_result.get("alert_id", "unknown"),
                    reason="Benign verdict with high confidence",
                    requires_approval=False,
                )
            )

        elif verdict == "suspicious":
            actions.append(
                Action(
                    action="monitor",
                    target=indicator,
                    reason="Suspicious activity requires monitoring",
                    requires_approval=True,
                )
            )

        elif verdict == "malicious":
            actions.append(
                Action(
                    action="block_ip",
                    target=indicator,
                    system="firewall",
                    reason="Malicious indicator confirmed",
                    requires_approval=True,
                )
            )

        return actions

    except Exception as erro:
        return None
