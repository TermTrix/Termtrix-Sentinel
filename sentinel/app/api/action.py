from fastapi import APIRouter
from uuid import uuid4
from app.models.approval import Approval
from app.storage.approvals import APPROVAL_STORE
from app.services.action_planner import plan_actions

# from app.services.executor import execute_action

router = APIRouter(prefix="/actions", tags=["Phase-3"])

RESULT = {
    "id": "1",
    "triage": {
        "verdict": "benign",
        "confidence": 0.8,
        "reason": "The IP address is associated with a known ISP in India and has no malicious detections on VirusTotal.",
    },
    "recommended_action": "close_alert",
    "requires_human_review": False,
}


from pydantic import BaseModel


class PlanRequest(BaseModel):
    id:str

@router.post("/plan")
async def create_action_plan(req: PlanRequest):
    
    print(f"ID <== {req.id}")
    actions = await plan_actions(phase2_result=RESULT)

    approval_id = str(uuid4())
    approval = Approval(approval_id=approval_id, actions=actions, status="pending")

    APPROVAL_STORE[approval_id] = approval

    return approval


@router.post("/approve/{approval_id}")
async def approve_actions(approval_id: str, approved_by: str, decision: str):
    approval = APPROVAL_STORE.get(approval_id)

    if not approval:
        return {"error": "Approval not found"}

    approval.status = decision
    approval.approved_by = approved_by

    return approval


@router.post("/execute/{approval_id}")
async def execute_approved_actions(approval_id: str):
    approval = APPROVAL_STORE.get(approval_id)

    if not approval:
        return {"error": "Approval not found"}

    if approval.status != "approved":
        return {"error": "Actions not approved"}

    results = []
    for action in approval.actions:
        result = await execute_action(action)
        results.append(result)

    return {"approval_id": approval_id, "execution_results": results}


async def execute_action(action):
    # In real life this calls MCP tools
    # firewall.block_ip, edr.isolate_host, jira.create_ticket

    if action.action == "block_ip":
        return {
            "action": action.action,
            "target": action.target,
            "result": "success",
        }

    if action.action == "close_alert":
        return {
            "action": action.action,
            "target": action.target,
            "result": "success",
        }

    return {
        "action": action.action,
        "target": action.target,
        "result": "skipped",
    }
