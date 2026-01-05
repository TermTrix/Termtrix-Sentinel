"""
MCP Tools for WHOIS, GeoIP, and VirusTotal lookups
"""
from fastmcp import FastMCP
import httpx
import json

# Create MCP app instance
mcp = FastMCP("Threat Intelligence Tools")


@mcp.tool()
async def whois_info(indicator:  str) -> dict:
    """
    Get WHOIS information for an IP address
    
    Args: 
        indicator: IP address to lookup
    
    Returns:
        Dictionary containing ASN, organization, country, network info
    """
    try: 
        # Call internal WHOIS API
        url = "http://localhost:8000/whois/whois_lookup"
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                url,
                json={"indicator": indicator},
                timeout=10.0
            )
            response.raise_for_status()
            data = response.json()
        
        return data
        
    except Exception as e:
        return {"error": f"WHOIS lookup failed: {str(e)}"}


@mcp.tool()
async def geoip_info(indicator: str) -> dict:
    """
    Get GeoIP information for an IP address
    
    Args: 
        indicator: IP address to lookup
    
    Returns:
        Dictionary containing country, city, latitude, longitude, ISP
    """
    try: 
        # Call internal GeoIP API
        url = "http://localhost:8000/whois/geo_lookup"
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                url,
                json={"indicator": indicator},
                timeout=10.0
            )
            response.raise_for_status()
            data = response.json()
        
        return data
        
    except Exception as e:
        return {"error": f"GeoIP lookup failed: {str(e)}"}


@mcp.tool()
async def virustotal_info(indicator: str) -> dict:
    """
    Get VirusTotal reputation information
    
    Args:
        indicator: IP address, domain, or hash to check
    
    Returns:
        Dictionary containing malicious count, reputation, verdict
    """
    try: 
        # Call internal VirusTotal API
        url = "http://localhost:8000/whois/virustotal"
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                url,
                json={"indicator": indicator},
                timeout=10.0
            )
            response.raise_for_status()
            data = response.json()
        
        return data
        
    except Exception as e:
        return {"error": f"VirusTotal lookup failed: {str(e)}"}