
# ============================================
# NEW CODE IMPLEMENTATION (05-01-2026)
# ============================================
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List
from app.models.action import Action
from app.models.approval import Approval
from app.services.action_planner import plan_actions
from app.storage.approvals import approval_store # Changed
import uuid

router = APIRouter()

@router.post("/actions/plan")
async def create_action_plan(id: str): # Made async
    """
    Phase 3: Create action plan based on triage result
    """

    # TODO: Get real triage result from database
    # For now, using placeholder
    state = {
        "phase_2_result": {
            "verdict": "malicious",
            "confidence": 0.95
        },
        "indicator": "45.142.212.61",
        "alert_id": id
    }

    # Plan actions
    actions = await plan_actions(state)

    # Create approval request
    approval_id = str(uuid.uuid4())
    approval = Approval(
        approval_id=approval_id,
        actions=actions,
        status="pending",
        approved_by=None
    )

    # Save to Redis
    await approval_store.save(approval)

    return {
        "approval_id":approval_id,
        "status":"pending",
        "actions":[a.model_dump() for a in actions]
    }

class ApprovalDecision(BaseModel):
    decision: str # "approved" or "rejected"
    approved_by: str
    reason: str = ""

@router.post("/actions/approve/{approval_id}")
async def approve_actions(approval_id: str, decision: ApprovalDecision): # Made async
    """
    Phase 3: Human approves or rejects actions
    """
    # Get from Redis
    approval = await approval_store.get(approval_id)
    
    if not approval:
        raise HTTPException(status_code=404, detail="Approval request not found")
    
    if decision.decision == "approved": 
        approval.status = "approved"
        approval.approved_by = decision. approved_by
    elif decision.decision == "rejected": 
        approval.status = "rejected"
        approval.approved_by = decision.approved_by
    else:
        raise HTTPException(status_code=400, detail="Decision must be 'approved' or 'rejected'")
    
    # ✅ Update in Redis
    await approval_store.update(approval)
    
    return {
        "approval_id": approval_id,
        "status": approval.status,
        "approved_by": approval.approved_by
    }

@router.post("/actions/execute/{approval_id}")
async def execute_actions(approval_id: str): # Made async
    """
    Phase 3: Execute approved actions
    """
    # ✅ Get from Redis
    approval = await approval_store.get(approval_id)
    
    if not approval: 
        raise HTTPException(status_code=404, detail="Approval request not found")
    
    if approval.status != "approved": 
        raise HTTPException(
            status_code=400, 
            detail=f"Cannot execute actions with status:  {approval.status}"
        )

    # Execute each action
    results = []
    for action in approval.actions:
        result = await execute_action(action) # Made async
        results.append(result)

    return {
        "approval_id": approval_id,
        "status":"executed",
        "results":results
    }

async def execute_action(action: Action) -> dict: # Made async
    """
    Execute a single action via MCP tools

    TODO: Implement real MCP tool calls
    Currently returns stub responses
    """

    # TODO: Call real MCP action tools
    # Example: await block_ip_tool(action.target)

    return{
        "action": action.action,
        "target": action.target,
        "status": "success", # Still stubbed
        "message": f"[STUB] Would execute: {action.action} on {action.target}"
    }
    
