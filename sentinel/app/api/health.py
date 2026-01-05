"""
Health check endpoints
"""

from fastapi import APIRouter
from app.core.mcp_client import get_mcp_client
from app.core.graph import get_enrichment_graph
from app.core.redis import redis_client
from app.logger import logger

router = APIRouter(tags=["Health"])

@router.get("/")
async def root():
    """
    Basic health check
    """
    return {"message": "Health World", "status":"ok"}

@router.get("health")
async def health_check():
    """
    Detailed health check
    Checks status of all services
    """
    health_status = {
        "status": "healthy",
        "version": "1.0.0",
        "services":{}
    }

    # Check MCP client
    try:
        mcp_client = get_mcp_client()
        health_status["services"]["mcp"]="up"
    except:
        health_status["services"]["mcp"] = "down"
        health_status["status"]="degraded"

    # Check enrichment graph
    try:
        graph = get_enrichment_graph()
        health_status["services"]["graph"]="up"
    except:
        health_status["services"]["graph"]="down"
        health_status["status"]="degraded"

    # Check Redis
    try: 
        await redis_client.ping()
        health_status["services"]["redis"] = "up"
    except Exception as e:
        health_status["services"]["redis"] = "down"
        health_status["status"] = "degraded"
        logger.error(f"Redis health check failed: {e}")
    
    return health_status

@router.get("/ready")
async def readiness_check():
    """
    Kybernetes readiness probe
    Returns 200 if service is ready to accept traffic
    """
    try:
        # Check critical services
        mcp_client = get_mcp_client()
        graph = get_enrichment_graph()
        await redis_client.ping()

        return {"status":"ready"}
    except Exception as e:
        logger.error(f"Readiness check failed: {e}")
        return {"status": "not ready", "error": str(e)}, 503


@router.get("/live")
async def liveness_check():
    """
    Kubernetes liveness probe
    Returns 200 if service is alive (even if not fully ready)
    """
    return {"status":"alive"}