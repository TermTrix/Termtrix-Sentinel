from fastapi import APIRouter
from ipwhois import IPWhois
from app.schemas.whois_loopup_response_schema import WhoisLookupResponse
from app.config import Settings

import requests




whois = APIRouter(prefix="/whois", tags=["whois"])

from pydantic import BaseModel

class IndicatorRequest(BaseModel):
    indicator: str


IPSTACK_API_KEY = Settings.IPSTACK_API_KEY

@whois.post("/whois_lookup",response_model=dict)
async def whois_lookup(request:IndicatorRequest):
    obj = IPWhois(request.indicator)
    res = obj.lookup_rdap()

    data = {
        "asn": res["asn"],
        "organization": res["asn_description"],
        "network": res["asn_cidr"],
        "rir": res["asn_registry"],
        "country": res["asn_country_code"],
        # "abuse_contact": res["entities"]["IRT-RELIANCEJIO-IN"]["contact"]["email"][0]["value"],
        "registration_date": res["asn_date"],
        # "last_updated": res["events"][1]["timestamp"],
        # "source": res["source"]
    }

    return data


@whois.post("/geo_lookup",response_model=dict)
async def geo_lookup(request:IndicatorRequest):

    API_URL = f'https://apiip.net/api/check?accessKey={IPSTACK_API_KEY}'

    IP_FOR_SEARCH = f'&ip={request.indicator}'

    res = requests.get(API_URL+IP_FOR_SEARCH)

    data = res.json()

    print(data,"FROM GEOIP")



    return {
        "country":data.get("countryName"),
        "country_code":data.get("countryCode"),
        "region":data.get("regionName"),
        "region_code":data.get("regionCode"),
        "city":data.get("city"),
        "latitude":data.get("latitude"),
        "longitude":data.get("longitude"),
        "is_eu":data.get("isEu"),
        "source":"geoip"
    }





@whois.post("/virustotal",response_model=dict)
def virustotal(request:IndicatorRequest):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{request.indicator}"

    headers = {
        "accept": "application/json", 
        "x-apikey": Settings.VIRUSTOTAL_API_KEY
    }

    response = requests.get(url, headers=headers)

    data = response.json()

    malicious = data.get("data",{}).get("attributes",{}).get("last_analysis_stats").get("malicious")
    harmless = data.get("data",{}).get("attributes",{}).get("last_analysis_stats").get("harmless")
    suspicious = data.get("data",{}).get("attributes",{}).get("last_analysis_stats").get("suspicious")
    reputation = data.get("data",{}).get("attributes",{}).get("reputation")

    confidence = malicious / (malicious + harmless + suspicious)

    vertict = normalize_vertict(malicious, harmless, suspicious)

    return {
        "confidence": confidence,
        "vertict": "|".join(vertict),
        "stats":{
             "malicious": malicious,
        "harmless": harmless,
        "suspicious": suspicious,
        },
        "reputation": reputation
    }




def normalize_vertict(malicious, harmless, suspicious):
    vertict = []
    if malicious > 0:
        vertict.append("malicious")
    elif suspicious >  0:
        vertict.append("suspicious")
    else:
        vertict.append("clean")

    return vertict

