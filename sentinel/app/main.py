"""
Termtrix Sentinel - AI-Powered SOAR Platform
Main FastAPI application

A security operations automation platform that:
1. Enriches threat intelligence (Phase 1)
2. AI-powered triage (Phase 2)
3. Orchestrates response actions (Phase 3)
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Lifespan management
from app.lifespan import lifespan

# API routers
from app.api.health import router as health_router
from app.api.enrichment import router as enrichment_router
from app.api.route.triage import router as triage_router
from app.api.action import router as action_router
from app.api.internal_logs import logs as internal_logs_router

# Logging
from app.logger import logger

# =========================================
# FastAPI Application
# =========================================

app = FastAPI(
    title="Termtrix Sentinel",
    description="""
    AI-Powered Security Operations & Response (SOAR) Platform
    
    ## Features
    
    * **Phase 1: Threat Intelligence Enrichment** - Automatic indicator enrichment
    * **Phase 2: AI-Powered Triage** - LLM-based threat analysis
    * **Phase 3: Action Orchestration** - Automated response with human approval
    
    ## Architecture
    
    - **MCP (Model Context Protocol)** for deterministic tool execution
    - **LangGraph** for stateful workflows
    - **PostgreSQL** for checkpointing and persistence
    - **Redis** for log streaming and caching
    """,
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# =========================================
# Middleware
# =========================================

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # TODO: Configure for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

# =========================================
# Mount API Routers
# =========================================


# Health checks
app.include_router(health_router)

# Phase 1: Enrichment
app.include_router(enrichment_router)

# Phase 2: Triage
app.include_router(triage_router, prefix="/triage")

# Phase 3: Actions
app.include_router(action_router)

# Internal: Log ingestion
app.include_router(internal_logs_router, prefix="/internal")

# =========================================
# Legacy Compatibility
# =========================================

@app.post("/call_graph", tags=["Legacy"])
async def legacy_call_graph_root(indicator: str):
    """
    Legacy endpoint - redirects to /enrichment/call_graph

    **Deprecated:** Use `/enrichment/enrich` instead
    """
    from app.api.enrichment import call_graph_legacy
    from app.dependencies import get_mcp

    mcp_client = await get_mcp()
    return await call_graph_legacy(indicator, mcp_client)

# =========================================
# Startup Message
# =========================================

@app.on_event("startup")
async def startup_message():
    """Log startup message"""
    logger.info("=" * 60)
    logger.info("🛡️  Termtrix Sentinel v1.0.0")
    logger.info("=" * 60)
    logger.info("📖 API Documentation: http://localhost:8000/docs")
    logger.info("🏥 Health Check: http://localhost:8000/health")
    logger.info("=" * 60)


# =========================================
# Main Entry Point
# =========================================

if __name__ =="__main__":
    import uvicorn
    uvicorn.run(
        app, 
        host="0.0.0.0", 
        port=8000, 
        log_level="info"
    )

