from fastapi import FastAPI
from app.api.internal.whois import whois
from mcp_server.threat_intel.server import mcp_app


app = FastAPI(
    title="Termtrix Sentinel",
    version="0.0.1",
    description="Termtrix Sentinel",
    lifespan=mcp_app.lifespan,
)
app.mount("/analytics", mcp_app)

app.include_router(whois)


@app.get("/")
def read_root():
    return {"Hello": "World"}


from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain.agents import create_agent
from langchain_mcp_adapters.tools import load_mcp_tools
from langgraph_sdk import get_client
from langchain_mcp_adapters.prompts import load_mcp_prompt
from langchain_google_genai import ChatGoogleGenerativeAI
from app.config import settings

MCP_SERVER = "http://localhost:8000/analytics/mcp"


GEMINI_API_KEY = settings.GEMINI_API_KEY

client = MultiServerMCPClient(
    {
        "sentinel": {
            "transport": "http",
            "url": "http://localhost:8000/analytics/mcp",
        }
    }
)


model = ChatGoogleGenerativeAI(
    model="gemini-2.0-flash", temperature=0, api_key=GEMINI_API_KEY
)


from pydantic import BaseModel, Field
from typing import Dict, List, Literal


class Result(BaseModel):
    risk_level: Literal["LOW", "MEDIUM", "HIGH"]
    summary: str = Field(description="Short summary of the analysis")
    evidence: List[str]
    recommendations: List[str]


from langchain.messages import ToolMessage

from workflows.state import EnrichmentState

state = {}


@app.get("/analyze")
async def analyze(ip: str):
    try:
        tools = await client.get_tools(server_name="sentinel")
        # prompt = await client.get_prompts()
        PROMPT = """
You are a SOC analyst assistant.

You are given ONE indicator.

You MUST:
- Call whois_info with {"indicator": "<value>"}
- Call geoip_info with {"indicator": "<value>"}
- Call virustotal_info with {"indicator": "<value>"}

Use ONLY tool outputs.
Do NOT invent facts.

Return:
- Risk level (LOW / MEDIUM / HIGH)
- Evidence (bullet points)
- Recommended next steps
"""

        agent = create_agent(model, tools, system_prompt=PROMPT, response_format=Result)

        result = await agent.ainvoke(
            {
                "messages": [
                    {
                        "role": "user",
                        "content": f"""
                        Analyze the following indicator.

                        Indicator type: IP
                        Indicator value: {ip}
                        """,
                    }
                ]
            }
        )

        for message in result["messages"]:
            if isinstance(message, ToolMessage) and message.artifact:
                structured_content = message.artifact["structured_content"]
                tool_name = message.name
                state[tool_name] = structured_content
                print(structured_content, "FROM TOOL")
        # print(state)

        structured_response = result.get("structured_response")

        state["structured_response"] = structured_response
        return state

    except Exception as e:
        print(e)
        return {"error": str(e)}
















from workflows.enrichment_graph import create_graph
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client


from langchain_core.messages import HumanMessage


@app.post("/call_graph")
async def call_graph(domain: str):
    try:
        config = {"configurable": {"thread_id": "001"}}

        async with client.session("sentinel") as session:
            graph = await create_graph(session)

            initial_state = {
                "messages": [HumanMessage(content=f"Analyze indicator {domain}")]
            }

            result = await graph.ainvoke(initial_state, config=config)
            return result

    except Exception as e:
        # IMPORTANT: expose the real error while debugging
        return {"error": repr(e)}
