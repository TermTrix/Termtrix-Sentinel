phase2_result = {
    "triage": {
        "verdict": "malicious",
        "confidence": 0.8,
        "reason": "The IP address is associated with a known ISP in India and has no malicious detections on VirusTotal.",
    },
    "recommended_action": "close_alert",
    "requires_human_review": False,
    "enriched_indicators": [],
}


class ToolState:
    pass


from typing import Dict, Any


class StoreActionToolInfo:
    def __init__(self):
        self.verdict: dict = {}
        self.plans: dict = {}
        self.id: str
        self.triage_result: Dict[str, Any]
        self.plan: Dict[str, Any]
        self.approval_required: bool
        self.approved: bool
        self.status: str

    async def find_verdict(self, action_id: str):
        try:
            self.triage_result = phase2_result
            return self.triage_result
        except Exception as error:
            return {"Error": f"Coundn't find the verdict {str(error)}"}

    async def create_plan(self, action_id: str):
        try:
            triage = self.triage_result["triage"]["verdict"]
            if triage == "benign":
                self.plan = {
                    "actions": [{"action": "close_alert", "requires_approval": False}]
                }
                self.approval_required = False
                message = "no more action needed"

            else:
                self.plan = {
                    "actions": [{"action": "block_ip", "requires_approval": True}]
                }
                self.approval_required = True
                message = "you need to close close this"

            return {"response": f"triage is {triage}  {message}"}

        except Exception as error:
            return {"Error":f"Error while creating plan {str(error)}"}

    # async def find_verdict(self,action_id:str):
    #     try:
    #         pass
    #     except Exception as error:
    #         pass

    #  async def find_verdict(self,action_id:str):
    #     try:
    #         pass
    #     except Exception as error:
    #         pass


action_info = StoreActionToolInfo()


async def plan_actions_node(state: dict):
    triage = state["triage_result"]["triage"]["verdict"]

    if triage == "benign":
        state["plan"] = {
            "actions": [{"action": "close_alert", "requires_approval": False}]
        }
        state["approval_required"] = False

    else:
        state["plan"] = {"actions": [{"action": "block_ip", "requires_approval": True}]}
        state["approval_required"] = True

    return state


# def approval_gate_node(state: Phase3State) -> str:
#     if state["approval_required"] and not state.get("approved", False):
#         return "pending"

#     if state.get("approved") is False:
#         return "rejected"

#     return "approved"
