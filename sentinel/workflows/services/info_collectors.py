from ipwhois import IPWhois
import httpx,anyio
from app.config import settings

SERVER_URL = settings.MAIN_SERVER

DEFAULT_TIMEOUT = 15.0  # seconds


async def call_whois(indicator: str) -> dict:
    async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
        response = await client.post(
            f"{SERVER_URL}/whois/whois_lookup",
            json={"indicator": indicator}
        )
        response.raise_for_status()
        return response.json()


async def call_geoip(indicator: str) -> dict:
    async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
        response = await client.post(
            f"{SERVER_URL}/whois/geo_lookup",
            json={"indicator": indicator},
        )
        response.raise_for_status()
        return response.json()


async def call_virustotal(indicator: str) -> dict:
    async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
        response = await client.post(
            f"{SERVER_URL}/whois/virustotal",
            json={"indicator": indicator},
        )
        response.raise_for_status()
        return response.json()




# FOR TRIAGE 


async def triage_analyze(state: str) -> dict:
    try:

        payload = {
            "indicator": state.get("indicator",None),
            "enrichment": state.get("enrichment",{}),
        }

        async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
            response = await client.post(
                f"{SERVER_URL}/triage/analyze",
                json={"payload": payload},
            )
            response.raise_for_status()
            return response.json()

    except Exception as error:
        print(error)
        return None