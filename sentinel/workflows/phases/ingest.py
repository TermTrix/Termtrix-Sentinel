
from workflows.phases.base import BasePhase
from workflows.core.state import EnrichmentState


class AlertIngestPhase(BasePhase):
    name = "alert_ingest"
    event = "ingested"

    async def run(self, state: EnrichmentState) -> EnrichmentState:
        return state
