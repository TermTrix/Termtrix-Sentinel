from typing import Dict
from pydantic import BaseModel

class WhoisLookupResponse(BaseModel):
    asn: str = ""
    organization: str = ""
    network: str = ""
    rir: str = ""
    country: str = ""
    abuse_contact: str = ""
    registration_date: str = ""
    last_updated: str = ""
    source: str =""
