# =============================================
# NEW CODE - TO BE ADDED (05-01-2026)
# =============================================

"""
Internal WHOIS, GeoIP, and VirusTotal APIs
These endpoints are called by MCP tools, not directly by users.
"""

from fastapi import APIRouter, HTTPException
import httpx # Changed from requests (async HTTP client)
from ipwhois import IPWhois # Library for WHOIS lookups
from app.config import settings
from app.logger import logger

# Create FastAPI router
router = APIRouter()

@router.post("/whois/whois_lookup")
async def whois_lookup(indicator: str):
    """
    WHOIS lookup using IPWhois library

    Args:
        indicator: IP address to lookup

    Returns:
        Dictionary containing:
        - asn: Autonomous System Number
        - asn_description: ASN description
        - organization: Organization name
        - country: Country code
        - network: Network CIDR block
        - rir: Regional Internet Registry

    Example:
        POST /whois/whois_lookup
        Body: {"indicator": "8.8.8.8"}

        Response: {
            "asn": "AS15169",
            "asn_description": "GOOGLE, US",
            "organization": "Google LLC",
            "country": "US",
            "network": "8.8.8.0/24",
            "rir": "ARIN"
        }
    """
    try:
        logger.info(f"WHOIS lookup: {indicator}")

        # Use IPWhois library (RDAP protocol)
        obj = IPWhois(indicator)
        result = obj.lookup_rdap() # Query RDAP (modern WHOIS)

        # Extract relevant fields
        whois_data = {
            "asn":  result.get("asn"),
            "asn_description": result.get("asn_description"),
            "organization": result.get("network", {}).get("name"),
            "country": result.get("asn_country_code"),
            "network": result. get("network", {}).get("cidr"),
            "rir": result.get("network", {}).get("remarks")
        }

        logger.info(f"WHOIS lookup successful for {indicator}")
        return whois_data
        
    except Exception as e:
        logger.error(f"WHOIS lookup failed for {indicator}: {e}")
        raise HTTPException(status_code=500, detail=f"WHOIS lookup failed: {str(e)}")



@router.post("/whois/geo_lookup")
async def geo_lookup(indicator:str):
    """
    GeoIP lookup using IPStack API
    
    Args:
        indicator:  IP address to lookup
    
    Returns:
        Dictionary containing: 
        - country: Country name
        - city: City name
        - latitude: Latitude coordinate
        - longitude: Longitude coordinate
        - isp: Internet Service Provider
        - region: Region/state name
    
    Example: 
        POST /whois/geo_lookup
        Body: {"indicator": "8.8.8.8"}
        
        Response: {
            "country": "United States",
            "city": "Mountain View",
            "latitude":  37.386,
            "longitude": -122.0838,
            "isp":  "Google LLC",
            "region": "California"
        }
    """
    try:
        logger.info(f"GeoIP lookup: {indicator}") 

        # Build IPStack API URL
        url = f"http://apiip.net/api/check?ip={indicator}&accessKey={settings.IPSTACK_API_KEY}"

        # Use httpx (async) instead of requests (blocking)
        async with httpx.AsyncClient() as client:
            response = await client.get(url, timeout=10.0)
            response.raise_for_status()
            data = response.json()

        # Extract relevant fields
        geoip_data = {
            "country":data.get("countryName"),
            "city":data.get("city"),
            "latitude":data.get("latitude"),
            "longitude":data.get("longitude"),
            "isp":data.get("isp"),
            "region":data.get("regionName")
        }
        logger.info(f"GeoIP lookup successful for {indicator}")
        return geoip_data
    
    except httpx.HTTPStatusError as e: 
        # Handle HTTP errors (4xx, 5xx)
        logger.error(f"GeoIP  API error for {indicator}: HTTP {e.response.status_code}")

        if e.response.status_code == 401:
            raise HTTPException(
                status_code=500,
                detail="GeoIP API authentication failed (invalid API key)"
            )
        elif e.response.status_code == 429:
            raise HTTPException(
                status_code=429,
                detail="GeoIP API rate limit exceeded"
            )
        else:
            raise HTTPException(
                status_code=500,
                detail=f"GeoIP API error: HTTP {e.response.status_code}"
            )
        
    except httpx.TimeoutException:
        # Handle timeout
        logger.error(f"❌ GeoIP lookup timeout for {indicator}")
        raise HTTPException(
            status_code=504,
            detail="GeoIP API request timeout"
        )
    
    except Exception as e:
        # Handle other errors
        logger.error(f"❌ GeoIP lookup failed for {indicator}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"GeoIP lookup failed for {indicator}: {str(e)}"
        )

@router.post("/whois/virustotal")
async def virustotal(indicator:  str):
    """
    VirusTotal reputation check
    
    Args:
        indicator: IP address, domain, or hash to check
    
    Returns:
        Dictionary containing:
        - malicious: Number of security vendors flagging as malicious
        - suspicious: Number of security vendors flagging as suspicious
        - harmless: Number of security vendors flagging as harmless
        - undetected: Number of security vendors with no detection
        - reputation: Reputation score (negative = bad)
        - verdict: Overall verdict (clean or malicious)
    
    Example:
        POST /whois/virustotal
        Body: {"indicator": "8.8.8.8"}
        
        Response: {
            "malicious":  0,
            "suspicious": 0,
            "harmless": 70,
            "undetected":  0,
            "reputation":  0,
            "verdict": "clean"
        }
    """
    try:
        logger. info(f"VirusTotal lookup: {indicator}")
        
        # Build VirusTotal API v3 URL
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}"
        headers = {"x-apikey":  settings.VIRUSTOTAL_API_KEY}
        
        # ✅ Use httpx (async) instead of requests (blocking)
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers, timeout=10.0)
            response.raise_for_status()
            data = response.json()
        
        # Extract last analysis statistics
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        reputation = data.get("data", {}).get("attributes", {}).get("reputation", 0)
        
        # Determine verdict
        malicious_count = stats.get("malicious", 0)
        suspicious_count = stats.get("suspicious", 0)
        
        # Verdict logic:  malicious if any vendor flags it
        if malicious_count > 0:
            verdict = "malicious"
        elif suspicious_count > 0:
            verdict = "suspicious"
        else:
            verdict = "clean"
        
        vt_data = {
            "malicious": malicious_count,
            "suspicious": suspicious_count,
            "harmless": stats.get("harmless", 0),
            "undetected":  stats.get("undetected", 0),
            "reputation":  reputation,
            "verdict": verdict
        }
        
        logger.info(f"✅ VirusTotal lookup successful for {indicator}:  verdict={verdict}")
        return vt_data
        
    except httpx.HTTPStatusError as e:
        # Handle HTTP errors (4xx, 5xx)
        logger.error(f"❌ VirusTotal API error for {indicator}: HTTP {e.response.status_code}")
        
        if e.response.status_code == 401:
            raise HTTPException(
                status_code=500,
                detail="VirusTotal API authentication failed (invalid API key)"
            )
        elif e.response.status_code == 429:
            raise HTTPException(
                status_code=429,
                detail="VirusTotal API rate limit exceeded"
            )
        elif e.response.status_code == 404:
            # Indicator not found in VT database
            logger.warning(f"⚠️ Indicator {indicator} not found in VirusTotal")
            return {
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "reputation": 0,
                "verdict": "unknown",
                "note": "Indicator not found in VirusTotal database"
            }
        else:
            raise HTTPException(
                status_code=500,
                detail=f"VirusTotal API error: HTTP {e.response.status_code}"
            )
    
    except httpx.TimeoutException:
        # Handle timeout
        logger.error(f"❌ VirusTotal lookup timeout for {indicator}")
        raise HTTPException(
            status_code=504,
            detail="VirusTotal API request timeout"
        )
    
    except Exception as e: 
        # Handle other errors
        logger.error(f"❌ VirusTotal lookup failed for {indicator}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"VirusTotal lookup failed: {str(e)}"
        )


# =============================================
# OLD CODE - TO BE DELETED
# =============================================


# from fastapi import APIRouter
# # from ipwhois import IPWhois
# # from app.schemas.whois_loopup_response_schema import WhoisLookupResponse
# # from app.config import Settings
# from app.config import settings

# import requests

# import httpx


# whois = APIRouter(prefix="/whois", tags=["whois"])

# from pydantic import BaseModel

# class IndicatorRequest(BaseModel):
#     indicator: str


# IPSTACK_API_KEY = settings.IPSTACK_API_KEY

# @whois.post("/whois_lookup",response_model=dict)
# async def whois_lookup(request:IndicatorRequest):
#     print(request.indicator)
#     obj = IPWhois(request.indicator)
#     res = obj.lookup_rdap()

#     data = {
#         "asn": res["asn"],
#         "organization": res["asn_description"],
#         "network": res["asn_cidr"],
#         "rir": res["asn_registry"],
#         "country": res["asn_country_code"],
#         # "abuse_contact": res["entities"]["IRT-RELIANCEJIO-IN"]["contact"]["email"][0]["value"],
#         "registration_date": res["asn_date"],
#         # "last_updated": res["events"][1]["timestamp"],
#         # "source": res["source"]
#     }

#     return data


# @whois.post("/geo_lookup",response_model=dict)
# async def geo_lookup(request:IndicatorRequest):
    
    
#     print(IPSTACK_API_KEY,"IPSTACK")

#     API_URL = f'https://apiip.net/api/check?accessKey={IPSTACK_API_KEY}'

#     IP_FOR_SEARCH = f'&ip={request.indicator}'

#     res = requests.get(API_URL+IP_FOR_SEARCH)

#     data = res.json()

#     print(data,"FROM GEOIP")



#     return {
#         "country":data.get("countryName"),
#         "country_code":data.get("countryCode"),
#         "region":data.get("regionName"),
#         "region_code":data.get("regionCode"),
#         "city":data.get("city"),
#         "latitude":data.get("latitude"),
#         "longitude":data.get("longitude"),
#         "is_eu":data.get("isEu"),
#         "source":"geoip"
#     }





# @whois.post("/virustotal",response_model=dict)
# def virustotal(request:IndicatorRequest):
#     url = f"https://www.virustotal.com/api/v3/ip_addresses/{request.indicator}"

#     headers = {
#         "accept": "application/json", 
#         "x-apikey": settings.VIRUSTOTAL_API_KEY
#     }

#     response = requests.get(url, headers=headers)

#     data = response.json()
    
#     # print(data,"FROM VT")
    
#     # return data

#     malicious = data.get("data",{}).get("attributes",{}).get("last_analysis_stats").get("malicious")
#     harmless = data.get("data",{}).get("attributes",{}).get("last_analysis_stats").get("harmless")
#     suspicious = data.get("data",{}).get("attributes",{}).get("last_analysis_stats").get("suspicious")
#     reputation = data.get("data",{}).get("attributes",{}).get("reputation",None)


#     print(malicious + harmless + suspicious,"====",malicious)
#     confidence = malicious / (malicious + harmless + suspicious) if malicious != 0  else 0

#     vertict = normalize_vertict(malicious, harmless, suspicious)

#     return {
#         "confidence": confidence,
#         "vertict": "|".join(vertict),
#         "stats":{
#              "malicious": malicious,
#         "harmless": harmless,
#         "suspicious": suspicious,
#         },
#         "reputation": reputation
#     }




# def normalize_vertict(malicious, harmless, suspicious):
#     vertict = []
#     if malicious > 0:
#         vertict.append("malicious")
#     elif suspicious >  0:
#         vertict.append("suspicious")
#     else:
#         vertict.append("clean")

#     return vertict

