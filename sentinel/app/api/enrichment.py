"""
Phase 1: Threat Intelligence Enrichment Endpoints
"""
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field
from typing import Optional
import json
# from langchain_core.messages import HumanMessage
from app.dependencies import get_mcp, get_graph
from app.logger import logger


import asyncio

router = APIRouter(prefix="/enrichment", tags=["Phase 1: Enrichment"])

class EnrichmentRequest(BaseModel):
    """Request model for enrichment"""
    indicator: str = Field(..., description="IP address, domain, hash, or URL to enrich")
    alert_id: Optional[str] = Field(None, description="Associated alert ID")
    context: Optional[dict] = Field(default_factory=dict, description="Additional context")

class EnrichmentResponse(BaseModel):
    """Response model for enrichment"""
    indicator: str
    whois_info: dict
    geoip_info: dict
    virustotal_info: dict
    alert_id: Optional[str] = None

@router.post("/enrich", response_model=EnrichmentResponse)
async def enrich_indicator(
    request: EnrichmentRequest,
    mcp_client = Depends(get_mcp)
):
    """
    Phase 1: Enrich a single indicator

    Gathers threat intelligence from multiple sources:
    - WHOIS lookup (ASN, organization, country)
    - GeoIP lookup (location, ISP)
    - VirusTotal reputation check

    Example:
        ```
        POST /enrichment/enrich
        {
            "indicator": "8.8.8.8",
            "alert_id": "EDR-12345"
        }
        ```
    """
    try:
        logger.info(f"Enriching indicator: {request.indicator}")

        result = {}

        # Call WHOIS tool
        logger.info("Calling WHOIS tool...")
        whois_result = await mcp_client.call_tool(
            "whois_info",
            arguments={"indicator":request.indicator}
        )
        result["whois_info"] = json.loads(
            whois_result.content[0].text if whois_result.content else "{}"
        )

        # Call GeoIP tool
        logger.info("Calling GeoIP tool...")
        geoip_result = await mcp_client.call_tool(
            "geoip_info",
            arguments={"indicator":request.indicator}
        )
        result["geoip_info"] = json.loads(
            geoip_result.content[0].text if geoip_result.content else "{}"
        )

        # Call VirusTotal tool
        logger.info("Calling VirusTotal tool...")
        vt_result = await mcp_client.call_tool(
            "virustotal_info",
            arguments={"indicator":request.indicator}
        )
        result["virustotal_info"] = json.loads(vt_result.content[0].text if vt_result.content else "{}"
        )

        # Add metadata
        result["indicator"] = request.indicator
        result["alert_id"] = request.alert_id

        logger.info(f"Enrichment complete for: {request.indicator}")
        return result

    except Exception as e:
        logger.error(f"Enrichment failed for {request.indicator}:{e}")
        raise HTTPException(
            status_code=500,
            detail=f"Enrichment failed: {str(e)}"
        )
        
@router.post("/call_graph")
async def call_graph_legacy(
    indicator:str,
    mcp_client = Depends(get_mcp)
):
    """
    Legacy endpoint for Phase 1 enrichment
    Maintains backward compatibility

    **Deprecated:** Use `/enrichment/enrich` instead

    Example:
        ```
        POST /call_graph
        {
            "indicator":"8.8.8.8"
        }
        ```
    """
    try:
        logger.info(f"call_graph (legacy) invoked for: {indicator}")

        # Use the new endpoint internally
        request = EnrichmentRequest(indicator=indicator)
        return await enrich_indicator(request, mcp_client)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"call_graph failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/bulk_enrich")
async def bulk_enrich(
    indicators:list[str],
    mcp_client = Depends(get_mcp)
):
    """
    Enrich multiple indicators in parallel
    
    Example:
        ```
        POST /enrichment/bulk_enrich
        {
            "indicators":["8.8.8.8", "1.1.1.1", "malicious.com"]
        }
        ```
    """

    try:
        logger.info(f"Bulk enriching {len(indicators)} indicators")

        # Enrich all indicators in parallel
        tasks = [
            enrich_indicator(
                EnrichmentRequest(indicator=indicator),
                mcp_client
            )
            for indicator in indicators
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Separate successes and failures
        enriched = []
        failed = []

        for i, result in enumerate(results):
            if isinstance(result, Exception):
                failed.append({
                    "indicator":indicators[i],
                    "error":str(result)
                })
            else:
                enriched.append(result)

        logger.info(f"Bulk enrichment complete: {len(enriched)} succeeded, {len(failed)} failed ")
        
        return{
            "total":len(indicators),
            "succeeded":len(enriched),
            "failed":len(failed),
            "results":enriched,
            "errors":failed
        }

    except Exception as e:
        logger.error(f"Bulk enrichment failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
        