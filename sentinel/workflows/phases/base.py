from abc import ABC, abstractmethod
from workflows.core.state import EnrichmentState
from datetime import datetime


class BasePhase(ABC):
    name: str
    event: str

    async def __call__(self, state: EnrichmentState) -> EnrichmentState:
        state.setdefault("audit_log", [])

        try:
            result = await self.run(state)

            state["audit_log"].append(
                {
                    "timestamp": datetime.now().isoformat(),
                    "phase": self.name,
                    "event": self.event,
                    "actor": "system",
                    "status": "success",
                }
            )
            return result

        except Exception as exc:
            state["audit_log"].append(
                {
                    "timestamp": datetime.now().isoformat(),
                    "phase": self.name,
                    "event": self.event,
                    "actor": "system",
                    "status": "failed",
                    "error": str(exc),
                }
            )
            raise


    @abstractmethod
    async def run(self, state: EnrichmentState) -> EnrichmentState:
        pass



# {
#   "timestamp": "2026-01-01T12:00:10Z",
#   "phase": "phase_1_enrichment",
#   "event": "started",
#   "actor": "system"
# }
