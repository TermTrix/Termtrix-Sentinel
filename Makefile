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


make build:
	docker compose down
	docker system prune -f
	docker compose up


# curl -G https://api.abuseipdb.com/api/v2/check \
#   --data-urlencode "ipAddress=118.25.6.39" \
#   -d maxAgeInDays=90 \
#   -d verbose \
#   -H "Key: ab7ad4b933fd1db9026c067561948bc36030fd42db2a404179f387c5b7bed8023182fa7e11e87875" \
#   -H "Accept: application/json"



# docker run --rm \
#   -v $(pwd)/observability/vector.yaml:/etc/observability/vector.yaml:ro \
#   -v $(pwd)/app/logs/app.log:/var/log/sentinel/app/logs/app.log:ro \
#   timberio/vector:latest-alpine \
#   --config /etc/observability/vector.yaml

	