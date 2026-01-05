"""
MCP Server for Threat Intelligence Tools
Exposes WHOIS, GeoIP, and VirusTotal as MCP tools
"""
from fastmcp import FastMCP

# Create FastMCP app
mcp_app = FastMCP("Threat Intelligence Server")

# Import and register tools
from mcp_server.threat_intel. tools.whois import (
    whois_info,
    geoip_info,
    virustotal_info
)

# Register tools with MCP
mcp_app. add_tool(whois_info)
mcp_app.add_tool(geoip_info)
mcp_app.add_tool(virustotal_info)


if __name__ == "__main__": 
    import uvicorn
    
    # Run MCP server
    uvicorn.run(
        mcp_app,
        host="0.0.0.0",
        port=8001,
        log_level="info"
    )