from fastapi import FastAPI
from app.api.internal.whois import whois

app = FastAPI(title="Termtrix Sentinel", version="0.0.1", description="Termtrix Sentinel")
# app.include_router(whois)

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
from app.config import Settings

MCP_SERVER = "http://localhost:8001/mcp"



GEMINI_API_KEY = Settings.GEMINI_API_KEY

client = MultiServerMCPClient(
    {
        "sentinel": {
            "transport": "http",
            "url": "http://localhost:8001/mcp",
        }
    }
)



model = ChatGoogleGenerativeAI(
    model="gemini-2.0-flash", temperature=0, api_key=GEMINI_API_KEY
)


@app.get("/analyze")
async def analyze(ip: str):
    try:
        tools = await client.get_tools(server_name="sentinel")
        # prompt = await client.get_prompts()
        
        print(tools)
        # print(prompt)

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



        agent = create_agent(
            model,
            tools,
            system_prompt=PROMPT,
        )


        result =await agent.ainvoke({
            "messages": [
                {
                    "role": "user",
                    "content": f"""
Analyze the following indicator.

Indicator type: IP
Indicator value: {ip}
"""
                }
            ]
        })

        return result

    except Exception as e:
        print(e)
        return {"error": str(e)}