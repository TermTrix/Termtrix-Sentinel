"""
Application lifespan management
Handles startup and shutdown events
"""

import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from app.core.redis import create_consumer_group
from app.core.mcp_client import initialize_mcp_client, cleanup_mcp_client
from app.core.graph import initialize_enrichment_graph
from app.logger import logger

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifespan context manager for FastAPI
    Runs on startup and shutdown
    """
    # ===============================================
    # STARTUP
    # ===============================================
    logger.info("Starting TermTrix Sentinel")

    try:
        # 1. Initialize Redis consumer group
        logger.info("📡 Initializing Redis...")
        await create_consumer_group()
        logger.info("✅ Redis consumer group initialized")
        
        # 2. Initialize MCP client (optional)
        disable_mcp = os.getenv("DISABLE_MCP", "").lower() in {"1", "true", "yes", "on"}
        if disable_mcp:
            logger.info("⏭️  Skipping MCP initialization (DISABLE_MCP is set)")
        else:
            logger.info("🔧 Initializing MCP client...")
            await initialize_mcp_client()
            logger.info("✅ MCP client initialized")
        
        # 3. Initialize LangGraph
        logger.info("🧠 Initializing enrichment graph...")
        await initialize_enrichment_graph()
        logger.info("✅ Enrichment graph initialized")
        
        logger.info("✅ Sentinel startup complete")
        
    except Exception as e:
        logger.error(f"❌ Startup failed: {e}")
        raise

    # Application is running
    yield

    # ===============================================
    # SHUTDOWN
    # ===============================================
    logger.info("Shutting down Sentinel...")

    # Cleanup resources
    disable_mcp = os.getenv("DISABLE_MCP", "").lower() in {"1", "true", "yes", "on"}
    if disable_mcp:
        logger.info("⏭️  Skipping MCP cleanup (DISABLE_MCP is set)")
    else:
        await cleanup_mcp_client()

    logger.info("Sentinel shutdown complete")