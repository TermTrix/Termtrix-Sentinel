
from workflows.phases.base import BasePhase
from workflows.core.state import EnrichmentState
from app.services.action_planner import plan_actions
from app.logger import logger
from datetime import datetime


from langgraph.types import Overwrite

class ActionPlanner(BasePhase):
    name = "action_planner"
    event = "planned"

    async def run(self, state: EnrichmentState) -> EnrichmentState:
        triage = state.get("phase_2_result")

        if not triage:
            raise ValueError("No triage data available")

        actions = await plan_actions(triage)

        if not actions:
            raise ValueError("No actions could be planned")

        parsed = [a.model_dump() for a in actions]
        state["actions"] = parsed

        return state
