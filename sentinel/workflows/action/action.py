from workflows.core.state import EnrichmentState
from workflows.phases.base import BasePhase
from app.config import settings

from langgraph.types import interrupt,Command

class IsMoreActionNeeded(BasePhase):
    name = "is_more_action_needed"
    event = "checked"

    async def run(self, state: EnrichmentState) -> EnrichmentState:
        actions = state.get("actions",[])
        
        for action in actions:
            if action.get("action") == "close_alert" and action.get("requires_approval") == False:
                state["requires_further_action"] = False
            else:
                state["requires_further_action"] = True
        return state


class WaitingForApproval(BasePhase):
    name = "waiting_for_approval"
    event = "waiting for approval"

    async def run(self, state: EnrichmentState) -> EnrichmentState:
        ip = state.get("indicator")
        verdict = state.get("phase_2_result",{}).get("verdict")
        alert_id = state.get("alert_id","alert:123")
        message = f"This is an alert for {ip} with verdict {verdict} and alert id {alert_id}.For more action we need approval."

        await notify_alert(message)
    
        decision = interrupt(message)
       
    

        return {"action":decision}



import httpx
async def notify_alert(message: str):
    try:
        async with httpx.AsyncClient() as client:
            payload = {"message": message}
            print(payload)
            resp = await client.post(url=f"{settings.MAIN_SERVER}/notification-alert", json=payload)
            resp.raise_for_status()
            res = resp.json()
            print(res)
            return res
    except Exception as error:
        print(str(error),"FROM NOTIFY ALERT")