
from fastmcp import FastMCP
# from ipwhois import IPWhois
from ipwhois import IPWhois
import httpx,anyio

SERVER_URL = "http://localhost:8000"



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



def register_intel_tools(mcp: FastMCP):
    """
    Register threat-intelligence MCP tools.
    All tools:
    - Accept a generic `indicator` (IP / domain)
    - Return structured, normalized data (dict)
    """

    @mcp.tool(
        name="whois_info",
        description="Get WHOIS ownership, ASN, and abuse contact information for an IP or domain",
        tags={"whois"},
        meta={"version": "1.0.0", "author": "Termtrix"},
    )
    async def whois_info(indicator: str) -> dict:
        print(f"FROM WHOIS: {indicator}")
        res = await call_whois(indicator)
        print(res)
        return res

    @mcp.tool(
        name="geoip_info",
        description="Get GeoIP location context (country, region, city) for an IP or domain",
        tags={"geoip"},
        meta={"version": "1.0.0", "author": "Termtrix"},
    )
    async def geoip_info(indicator: str) -> dict:
        print(f"FROM GEOIP: {indicator}")
        return await call_geoip(indicator)

    @mcp.tool(
        name="virustotal_info",
        description="Get VirusTotal reputation and detection summary for an IP or domain",
        tags={"virustotal"},
        meta={"version": "1.0.0", "author": "Termtrix"},
    )
    async def virustotal_info(indicator: str) -> dict:
        return await call_virustotal(indicator)




