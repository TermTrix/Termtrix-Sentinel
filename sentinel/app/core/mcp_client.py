"""
MCP Client singleton
Manages connection to MCP Server
"""

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from typing import Optional
from app.logger import logger

# Global MCP Client
_mcp_client: Optional[ClientSession] = None
_mcp_read = None
_mcp_write = None


async def initialize_mcp_client() -> ClientSession:
    """
    Initialize MCP Client connection
    Should be called once during startup
    """
    global _mcp_client, _mcp_read, _mcp_write

    if _mcp_client is not None:
        logger.warning("MCP client already initialized")
        return _mcp_client

    
    try:
        # Create MCP server parameters
        server_params = StdioServerParameters(
            command="uvicorn",
            args=[
                "mcp_server.threat_intel.server:mcp_app",
                "--host","0.0.0.0",
                "--port","8001"
            ],
            env=None
        )

        # Initialize MCP Client
        _mcp_read, _mcp_write = await stdio_client(server_params).__aenter__()
        _mcp_client = ClientSession(_mcp_read, _mcp_write)

        await _mcp_client.__aenter__()

        logger.info("MCP client connected")
        return _mcp_client
        
    except Exception as e:
        logger.error(f"Failed to initialize MCP client: {e}")
        raise

def get_mcp_client() -> ClientSession:
    """
    Get the global MCP client instance

    Returns:
        MCP client session
    
    Raises:
        RuntimeError: If client not initialized
    """
    if _mcp_client is None:
        raise RunTimeError(
            "MCP client not initialized."
            "Call initialize_mcp_client() during startup."
        )
    return _mcp_client

async def cleanup_mcp_client():
    """
    Cleanup MCP client connection
    Should be called during shutdown
    """
    global _mcp_client, _mcp_read, _mcp_write

    if _mcp_client:
        try:
            await _mcp_client.__aexit__(None, None, None)
            logger.info("MCP client disconnected")
        except Exception as e:
            logger.error(f"Error cleaning up MCP client: {e}")
        finally:
            _mcp_client = None
            _mcp_read = None
            _mcp_write = None