# phases/phase1.py
import asyncio
from sentinel.workflows.phases.base import BasePhase
from sentinel.workflows.core.state import EnrichmentState
from sentinel.workflows.services.info_collectors import call_whois, call_geoip, call_virustotal
from datetime import datetime


class Phase1Enrichment(BasePhase):
    name = "phase_1_enrichment"
    event = "enriched"

    async def run(self, state: EnrichmentState) -> EnrichmentState:
        print("PHASE1")
        whois, geoip, vt = await asyncio.gather(
            call_whois(state["indicator"]),
            call_geoip(state["indicator"]),
            call_virustotal(state["indicator"]),
        )

        state["enrichment"] = {
            "whois": whois,
            "geoip": geoip,
            "virustotal": vt,
        }
        return state
