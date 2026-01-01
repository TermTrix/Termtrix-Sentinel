
from workflows.phases.base import BasePhase
from workflows.core.state import EnrichmentState
from workflows.services.info_collectors import triage_analyze
from app.logger import logger
from datetime import datetime



class Phase2Triage(BasePhase):
    name = "phase_2_enrichment"
    event = "triaged"

    async def run(self, state: EnrichmentState) -> EnrichmentState:
        try:
              # state["phase_2_result"] = {
        #     "verdict": "malicious",
        #     "confidence": 0.8,
        #     "recommended_action": "close_alert",
        #     "requires_human_review": False,
        # }

            response = await triage_analyze(state)
            print(response,"RESPONSE")
            state["phase_2_result"] = response.get("triage",{})

            # state["requires_phase_3"] = state["phase_2_result"]["requires_human_review"]
            return state
        
        except Exception as error:
            print(error)
            logger.error(error)
            return state
      
