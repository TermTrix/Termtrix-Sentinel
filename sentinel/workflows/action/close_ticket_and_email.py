from workflows.core.state import EnrichmentState
from workflows.phases.base import BasePhase

class CloseTicketAndEmail(BasePhase):
    name = "close_ticket_and_email"
    event = "closed"

    async def run(self, state: EnrichmentState) -> EnrichmentState:
        state["status"] = "closed"
        state["approved"] = True
        return state