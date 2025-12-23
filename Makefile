MCP_DIR = mcp_servers
MCP_APP = threat_intel.server:mcp_app
HOST = 0.0.0.0
MCP_PORT = 8001
FASTAPI_PORT = 8000

.PHONY: mcp_server

mcp_server:
	cd $(MCP_DIR) && uvicorn $(MCP_APP) --reload --host $(HOST) --port $(MCP_PORT)



# BACKEND

.PHONY:sentinel

server:
	cd sentinel && uvicorn app.main:app --reload --host $(HOST) --port $(FASTAPI_PORT)