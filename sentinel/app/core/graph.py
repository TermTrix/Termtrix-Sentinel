"""
LangGraph enrichment graph singleton
"""

from typing import Optional
from langgraph.graph import StateGraph
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from app.config import settings
from app.logger import logger

# Global enrichment graph
_enrichment_graph = None
_checkpointer_cm = None
_checkpointer = None

async def initialize_enrichment_graph():
    """
    Initialize LangGraph enrichment graph with PostgreSQL checkpointing
    Should be called once during startup
    """
    global _enrichment_graph, _checkpointer

    if _enrichment_graph is not None:
        logger.warning("Enrichment graph already initialized")
        return _enrichment_graph

    try:
        # Create PostgreSQL checkpointer
        # from_conn_string returns an async context manager; enter and keep both
        global _checkpointer_cm
        _checkpointer_cm = AsyncPostgresSaver.from_conn_string(settings.DB_URI)
        _checkpointer = await _checkpointer_cm.__aenter__()
        await _checkpointer.setup()

        # Import and create graph
        from app.workflows.enrichment_graph import create_enrichment_graph
        _enrichment_graph = create_enrichment_graph(_checkpointer)

        logger.info("Enrichment graph created with PostgreSQL checkpointing")
        return _enrichment_graph
    
    except Exception as e:
        logger.error(f"Failed to initialize enrichment graph: {e}")
        raise

def get_enrichment_graph():
    """
    Get the global enrichment graph instance

    Returns:
        LangGraph enrichment graph
    
    Raises:
        RuntimeError: If graph not initialized
    """
    if _enrichment_graph is None:
        raise RuntimeError(
            "Enrichment graph not initialized."
            "Call initlize_enrichment_graph() during startup."
        )
    return _enrichment_graph

async def cleanup_enrichment_graph():
    """
    Cleanup enrichment graph resources
    Should be called during shutdown
    """
    global _enrichment_graph, _checkpointer_cm, _checkpointer

    if _checkpointer_cm:
        try:
            await _checkpointer_cm.__aexit__(None, None, None)
            logger.info("Enrichment graph checkpointer closed")
        except Exception as e:
            logger.error(f"Error cleaning up checkpointer: {e}")
        finally:
            _enrichment_graph = None
            _checkpointer = None
            _checkpointer_cm = None

       
    
    