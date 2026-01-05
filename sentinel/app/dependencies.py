"""
FastAPI dependencies
Provides shared resources to endpoints
"""

from fastapi import Depends, HTTPException
from app.core.mcp_client import get_mcp_client
from app.core.graph import get_enrichment_graph
from mcp import ClientSession


async def get_mcp() -> ClientSession:
    """
    Dependency: Get MCP client

    Returns:
        MCP client session

    Raises:
        HTTPException: If MCP client not available
    """

    try:
        return get_mcp_client()
    except RuntimeError as e:
        raise HTTPException(
            status_code=503,
            detail="MCP client not available"
        )

async def get_graph():
    """
    Dependency: Get enrichment graph

    Returns:
        LangGraph enrichment graph
    
    Raises:
    HTTPException: If graph not available
    """
    try:
        return get_enrichment_graph()
    except RuntimeError as e:
        raise HTTPException(
            status_code=503,
            detail="Enrichment graph not available"
        )