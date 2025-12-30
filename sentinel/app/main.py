from fastapi import FastAPI,Request
from app.api.internal.whois import whois
from mcp_server.threat_intel.server import phase1_app, phase3_app
from app.api.action import router

from app.config import settings
from contextlib import asynccontextmanager
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from langgraph.store.postgres.aio import AsyncPostgresStore  
from langgraph.store.base import BaseStore
from app.api.internal_logs import logs

DB_URI = settings.DB_URI

# @asynccontextmanager
# async def lifespan(app: FastAPI):
#     async with phase1_app.lifespan(app):
#         async with phase3_app.lifespan(app):
#             yield

from app.logger import logger

print(DB_URI,"DB_URI")


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with (
        AsyncPostgresStore.from_conn_string(DB_URI) as store,
        AsyncPostgresSaver.from_conn_string(DB_URI) as checkpointer,
    ):
        print("STORE TYPE:", type(store))
        print("CHECKPOINTER TYPE:", type(checkpointer))

        await store.setup()
        await checkpointer.setup()

        app.state.graph = await create_enrichment_graph(store, checkpointer)
        yield


app = FastAPI(
    title="Termtrix Sentinel",
    version="0.0.1",
    description="Termtrix Sentinel",
    lifespan=lifespan,
)

# 🔹 Phase 1 – Threat Intel
app.mount("/analytics", phase1_app)

# 🔹 Phase 3 – Action / Decision
app.mount("/actions", phase3_app)


app.include_router(whois)
app.include_router(router)
app.include_router(logs)


@app.get("/")
def read_root():
    logger.info("Hello World")
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
        },
        "sentinel_phase_3": {
            "transport": "http",
            "url": "http://localhost:8000/actions/mcp",
        },
    }
)


model = ChatGoogleGenerativeAI(
    model="gemini-2.0-flash", temperature=0, api_key=GEMINI_API_KEY
)


from pydantic import BaseModel, Field
from typing import Dict, List, Literal, Any


class Result(BaseModel):
    risk_level: Literal["LOW", "MEDIUM", "HIGH"]
    summary: str = Field(description="Short summary of the analysis")
    evidence: List[str]
    recommendations: List[str]


from langchain.messages import ToolMessage

from workflows.state import EnrichmentState

state = {
  "whois_info": {
    "asn": "24309",
    "organization": "CABLELITE-AS-AP Atria Convergence Technologies Pvt. Ltd. Broadband Internet Service Provider INDIA, IN",
    "network": "49.205.32.0/21",
    "rir": "apnic",
    "country": "IN",
    "registration_date": "2010-12-06"
  },
  "geoip_info": {
    "country": "India",
    "country_code": "IN",
    "region": "Karnataka",
    "region_code": "KA",
    "city": "Bengaluru",
    "latitude": 12.9753,
    "longitude": 77.591,
    "is_eu": False,
    "source": "geoip"
  },
  "virustotal_info": {
    "confidence": 0,
    "vertict": "clean",
    "stats": {
      "malicious": 0,
      "harmless": 0,
      "suspicious": 0
    },
    "reputation": 0
  },
  "structured_response": {
    "risk_level": "LOW",
    "summary": "IP address is likely safe.",
    "evidence": [
      "WHOIS: Located in India, owned by Atria Convergence Technologies.",
      "GEOIP: Located in India, Bengaluru.",
      "VirusTotal: Clean reputation, no detections."
    ],
    "recommendations": [
      "Monitor the IP for any suspicious activity.",
      "Keep intrusion detection system updated."
    ]
  }
}


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


# Alert Analyzer


class Alert(BaseModel):
    alert_id: str
    source: str
    alert_type: str
    severity: str
    host: str | None
    user: str | None
    indicators: list[Dict[str, Any]]


# Dummy paylaod

# {
#   "alert_id": "EDR-12345",
#   "source": "EDR",
#   "alert_type": "suspicious_outbound_connection",
#   "severity": "medium",
#   "host": "laptop-23",
#   "user": "alice",
#   "indicators": [
#     {
#       "type": "ip",
#       "value": "49.205.34.164"
#     }
#   ]
# }

TYPICAL_VERTICTS = ["benign", "suspicious" "malicious", "needs_investigation"]

from enum import Enum


class Verdict(str, Enum):
    BENIGN = "BENIGN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    NEEDS_INVESTIGATION = "NEEDS INVESTIGATION"


class RecommendedAction(str, Enum):
    CLOSE_ALERT = "close_alert"
    MONITOR = "monitor"
    ESCALATE_TO_TIER2 = "escalate_to_tier2"
    INVESTIGATE_FURTHER = "investigate_further"


class Triage(BaseModel):
    verdict: str = Verdict
    confidence: float = Field(
        ge=0.0, le=1.0, description="Confidence score between 0 and 1"
    )

    reason: str = Field(description="short, evidence-based explanation")


class TriageResult(BaseModel):
    triage: Dict[str, Triage]
    recommended_action: str = RecommendedAction
    requires_human_review: bool


from langchain_core.prompts import PromptTemplate
from langchain_core.output_parsers import JsonOutputParser

parser = JsonOutputParser(pydantic_object=TriageResult)

from app.prompts.triage import TRIAGE_PROMPT
import json


@app.post("/alert/analyze")
async def alert_analyze(req: Alert):
    try:

        print(state, "++++")

        enrich_data_str = json.dumps(state, indent=2)
        PROMPT = PromptTemplate.from_template(
            template=TRIAGE_PROMPT,
            partial_variables={"format_instructions": parser.get_format_instructions()},
        )

        chain = PROMPT | model | parser

        response = await chain.ainvoke({"ENRICH_DATA": enrich_data_str})    

        print(response)

        phase_two_res = {
            **response,
            "enriched_indicators": state.get("structured_response"),
        }

        return phase_two_res

    except Exception as error:
        print(error)


# PHASE 3


phase2_result = {
    "triage": {
        "verdict": "benign",
        "confidence": 0.8,
        "reason": "The IP address is associated with a known ISP in India and has no malicious detections on VirusTotal.",
    },
    "recommended_action": "close_alert",
    "requires_human_review": False,
    "enriched_indicators": [],
}


from app.services.action_planner import plan_actions

import asyncio


async def check_pahse3_plan():
    task = await plan_actions(phase2_result)
    print(task, "-->")


# print(asyncio.create_task(check_pahse3_plan()))


from workflows.action_graph import create_phase_three_graph

config = {"configurable": {"thread_id": "001"}}

from langchain.agents.middleware import HumanInTheLoopMiddleware
from langgraph.checkpoint.memory import InMemorySaver
from mcp.client.streamable_http import streamable_http_client


@app.post("/action-graph")
async def action_graph(action_id: str, message: str):
    try:
        # graph = await create_phase_three_graph()
        # result = await graph.ainvoke({"id": action_id}, config=config)

        # return result

        async with client.session("sentinel_phase_3") as session:
            tools = await load_mcp_tools(session)
            # prompt = await client.get_prompts()
            PROMPT = """
            You are a SOC analyst assistant.
            response properly

            """
            print(tools)

            agent = create_agent(
                model,
                tools,
                system_prompt=PROMPT,
                # middleware=[
                #     HumanInTheLoopMiddleware(
                #         interrupt_on={"find_is_action_needed": False},
                #         description_prefix="Tool execution pending approval",
                #     )
                # ],
                # checkpointer=InMemorySaver(),
            )

            response = await agent.ainvoke(
                {
                    "messages": [
                        {
                            "role": "user",
                            "content": f"""
                        Excute the tools based on user and tool responses
                        action_id: {action_id}
                        
                        user_message: {message}
                        
                        """,
                        }
                    ]
                }
            )

            return response

        # return result
    except Exception as error:
        return {"error": str(error)}


from workflows.state import Phase3State




from workflows.enrichment_graph import create_enrichment_graph
from mcp import ClientSession
from langgraph.types import Command
from langchain_core.messages import HumanMessage


@app.post("/call_graph")
async def call_graph(domain: str,req:Request):
    try:
        config = {"configurable": {"thread_id": domain,"user_id": "user_1"}}

        graph = req.app.state.graph

        result = await graph.ainvoke(
            {
                "messages": "Hello",
                "indicator": domain
            },
            config=config
        )

        print(result,"RESULR")
        # If interrupted, return approval request to frontend
        if "__interrupt__" in result:
            return {
                "status": "awaiting_approval",
                "question": result["__interrupt__"][0].value,
                "thread_id": domain
            }

        return result

    except Exception as e:
        # IMPORTANT: expose the real error while debugging
        return {"error": repr(e)}




@app.post("/call_graph/approve")
async def approve_graph(thread_id: str, approved: bool,req:Request):
    config = {"configurable": {"thread_id": thread_id}}

    graph = req.app.state.graph

    result = await graph.ainvoke(
            Command(resume=approved),
            config=config
        )

    return result













import time
import httpx



@app.post("/fetch_page_html")
async def fetch_page_html(url: str) -> dict:
    """
    Fetches the HTML of a given URL and measures load time.
    """

    start_time = time.time()

    try:
        async with httpx.AsyncClient(
            timeout=10,
            follow_redirects=True,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (compatible; TermtrixSEO/1.0; +https://termtrix.com)"
                )
            },
        ) as client:
            response = await client.get(url)

        load_time_ms = int((time.time() - start_time) * 1000)

        return {
            "url": url,
            "status_code": response.status_code,
            "load_time_ms": load_time_ms,
            "html": response.text,
        }

    except Exception as e:
        return {
            "url": url,
            "status_code": 0,
            "load_time_ms": None,
            "error": str(e),
            "html": "",
        }















# from bs4 import BeautifulSoup


# data = "<!DOCTYPE html><html lang=\"en\"><head><meta charSet=\"utf-8\"/><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"/><link rel=\"preload\" as=\"image\" imageSrcSet=\"/_next/image?url=%2Ftermtrix-logo.jpg&amp;w=640&amp;q=75 640w, /_next/image?url=%2Ftermtrix-logo.jpg&amp;w=750&amp;q=75 750w, /_next/image?url=%2Ftermtrix-logo.jpg&amp;w=828&amp;q=75 828w, /_next/image?url=%2Ftermtrix-logo.jpg&amp;w=1080&amp;q=75 1080w, /_next/image?url=%2Ftermtrix-logo.jpg&amp;w=1200&amp;q=75 1200w, /_next/image?url=%2Ftermtrix-logo.jpg&amp;w=1920&amp;q=75 1920w, /_next/image?url=%2Ftermtrix-logo.jpg&amp;w=2048&amp;q=75 2048w, /_next/image?url=%2Ftermtrix-logo.jpg&amp;w=3840&amp;q=75 3840w\" imageSizes=\"100vw\"/><link rel=\"stylesheet\" href=\"/_next/static/chunks/fff905c71cb6ab0c.css\" data-precedence=\"next\"/><link rel=\"stylesheet\" href=\"/_next/static/chunks/d9f7fc5c3062ede5.css\" data-precedence=\"next\"/><link rel=\"preload\" as=\"script\" fetchPriority=\"low\" href=\"/_next/static/chunks/c62b4372c26b460f.js\"/><script src=\"/_next/static/chunks/4663b8084bfc1226.js\" async=\"\"></script><script src=\"/_next/static/chunks/c262c49f15ce2f1f.js\" async=\"\"></script><script src=\"/_next/static/chunks/54afae82ba38f00b.js\" async=\"\"></script><script src=\"/_next/static/chunks/turbopack-a4cc1c15e1eec4cc.js\" async=\"\"></script><script src=\"/_next/static/chunks/25f0986ed87d220e.js\" async=\"\"></script><script src=\"/_next/static/chunks/e2b0ebdd7c9ec357.js\" async=\"\"></script><script src=\"/_next/static/chunks/3f682a3264f29773.js\" async=\"\"></script><script src=\"/_next/static/chunks/703ab740f268a9b9.js\" async=\"\"></script><script src=\"/_next/static/chunks/53c5ffaf39e0edf3.js\" async=\"\"></script><script src=\"/_next/static/chunks/ece0d313a4d1cc87.js\" async=\"\"></script><script src=\"/_next/static/chunks/483d179ffd78e2c9.js\" async=\"\"></script><script src=\"/_next/static/chunks/ff1a16fafef87110.js\" async=\"\"></script><script src=\"/_next/static/chunks/89460367c0865bec.js\" async=\"\"></script><meta name=\"next-size-adjust\" content=\"\"/><title>TERMTRIX — Learn, Collaborate &amp; Build Real Systems</title><meta name=\"description\" content=\"TERMTRIX is a developer community focused on learning, collaboration, and real-world problem solving. We explore modern technologies, share knowledge openly, and build meaningful systems together.\"/><link rel=\"author\" href=\"https://termtrix.vercel.app\"/><meta name=\"author\" content=\"Bala Ms\"/><link rel=\"manifest\" href=\"/manifest.json\"/><meta name=\"keywords\" content=\"Developer Community,Learn Software Engineering,Build Real World Systems,Collaborative Coding Community,System Design Learning,Backend Engineering Community,Modern Web Development,TERMTRIX Community,Engineering Knowledge Sharing\"/><meta name=\"creator\" content=\"TERMTRIX\"/><meta name=\"publisher\" content=\"TERMTRIX\"/><meta name=\"robots\" content=\"index, follow\"/><meta name=\"googlebot\" content=\"index, follow, max-image-preview:large, max-snippet:-1\"/><meta name=\"category\" content=\"technology\"/><link rel=\"canonical\" href=\"https://termtrix.vercel.app\"/><meta property=\"og:title\" content=\"TERMTRIX — Learn, Collaborate &amp; Build Real Systems\"/><meta property=\"og:description\" content=\"A developer community for learning modern technologies, collaborating openly, and building real-world systems together.\"/><meta property=\"og:url\" content=\"https://termtrix.vercel.app\"/><meta property=\"og:site_name\" content=\"TERMTRIX\"/><meta property=\"og:locale\" content=\"en_US\"/><meta property=\"og:image\" content=\"https://termtrix.vercel.app/og.png\"/><meta property=\"og:image:width\" content=\"1200\"/><meta property=\"og:image:height\" content=\"630\"/><meta property=\"og:image:alt\" content=\"TERMTRIX Developer Community\"/><meta property=\"og:type\" content=\"website\"/><meta name=\"twitter:card\" content=\"summary_large_image\"/><meta name=\"twitter:title\" content=\"TERMTRIX — Learn, Collaborate &amp; Build Real Systems\"/><meta name=\"twitter:description\" content=\"A developer community focused on learning, collaboration, and building meaningful real-world systems.\"/><meta name=\"twitter:image\" content=\"https://termtrix.vercel.app/og.png\"/><link rel=\"icon\" href=\"/favicon.ico?favicon.c301ae68.ico\" sizes=\"48x48\" type=\"image/x-icon\"/><link rel=\"icon\" href=\"/icon0.svg?icon0.e77d1506.svg\" sizes=\"any\" type=\"image/svg+xml\"/><link rel=\"icon\" href=\"/icon1.png?icon1.0f46e201.png\" sizes=\"96x96\" type=\"image/png\"/><link rel=\"apple-touch-icon\" href=\"/apple-icon.png?apple-icon.c63bc649.png\" sizes=\"180x180\" type=\"image/png\"/><script src=\"/_next/static/chunks/a6dad97d9634a72d.js\" noModule=\"\"></script></head><body class=\"geist_2ae47f08-module__h69qWW__variable geist_mono_eb58308d-module__w_p2Lq__variable antialiased\"><div hidden=\"\"><!--$--><!--/$--></div><script>((a,b,c,d,e,f,g,h)=>{let i=document.documentElement,j=[\"light\",\"dark\"];function k(b){var c;(Array.isArray(a)?a:[a]).forEach(a=>{let c=\"class\"===a,d=c&&f?e.map(a=>f[a]||a):e;c?(i.classList.remove(...d),i.classList.add(f&&f[b]?f[b]:b)):i.setAttribute(a,b)}),c=b,h&&j.includes(c)&&(i.style.colorScheme=c)}if(d)k(d);else try{let a=localStorage.getItem(b)||c,d=g&&\"system\"===a?window.matchMedia(\"(prefers-color-scheme: dark)\").matches?\"dark\":\"light\":a;k(d)}catch(a){}})(\"class\",\"theme\",\"system\",null,[\"light\",\"dark\"],null,true,true)</script><div class=\"z-50\"><nav class=\"fixed top-4 left-4 right-4 z-50 h-16 max-w-7xl mx-auto rounded-full border border-border/40 bg-background/60 backdrop-blur-md shadow-sm transition-all\"><div class=\"h-full flex items-center justify-between px-6\"><div class=\"flex items-center gap-2 hover:opacity-90 transition-opacity\"><div class=\"relative h-10 w-10 overflow-hidden rounded-lg border border-white/10 shadow-sm\"><img alt=\"TermTrix Logo\" decoding=\"async\" data-nimg=\"fill\" class=\"object-cover\" style=\"position:absolute;height:100%;width:100%;left:0;top:0;right:0;bottom:0;color:transparent\" sizes=\"100vw\" srcSet=\"/_next/image?url=%2Ftermtrix-logo.jpg&amp;w=640&amp;q=75 640w, /_next/image?url=%2Ftermtrix-logo.jpg&amp;w=750&amp;q=75 750w, /_next/image?url=%2Ftermtrix-logo.jpg&amp;w=828&amp;q=75 828w, /_next/image?url=%2Ftermtrix-logo.jpg&amp;w=1080&amp;q=75 1080w, /_next/image?url=%2Ftermtrix-logo.jpg&amp;w=1200&amp;q=75 1200w, /_next/image?url=%2Ftermtrix-logo.jpg&amp;w=1920&amp;q=75 1920w, /_next/image?url=%2Ftermtrix-logo.jpg&amp;w=2048&amp;q=75 2048w, /_next/image?url=%2Ftermtrix-logo.jpg&amp;w=3840&amp;q=75 3840w\" src=\"/_next/image?url=%2Ftermtrix-logo.jpg&amp;w=3840&amp;q=75\"/></div><span class=\"font-bold dark:text-white text-xl tracking-tight bg-gradient-to-r from-white to-white/70 bg-clip-text text-transparent\">TΞRMTRIX</span></div><nav aria-label=\"Main\" data-orientation=\"horizontal\" dir=\"ltr\" data-slot=\"navigation-menu\" data-viewport=\"true\" class=\"group/navigation-menu relative max-w-max flex-1 items-center justify-center hidden md:block\"><div style=\"position:relative\"><ul data-orientation=\"horizontal\" data-slot=\"navigation-menu-list\" class=\"group flex flex-1 list-none items-center justify-center gap-3 space-x-0 data-[orientation=vertical]:flex-col data-[orientation=vertical]:items-start data-[orientation=vertical]:justify-start\" dir=\"ltr\"><li data-slot=\"navigation-menu-item\" class=\"relative\"><a data-slot=\"navigation-menu-link\" class=\"data-[active=true]:focus:bg-accent data-[active=true]:hover:bg-accent data-[active=true]:bg-accent/50 data-[active=true]:text-accent-foreground hover:bg-accent hover:text-accent-foreground focus:bg-accent focus:text-accent-foreground focus-visible:ring-ring/50 [&amp;_svg:not([class*=&#x27;text-&#x27;])]:text-muted-foreground flex flex-col gap-1 rounded-sm p-2 text-sm transition-all outline-none focus-visible:ring-[3px] focus-visible:outline-1 [&amp;_svg:not([class*=&#x27;size-&#x27;])]:size-4\" data-radix-collection-item=\"\" href=\"/\">Home</a></li><li data-slot=\"navigation-menu-item\" class=\"relative\"><a data-slot=\"navigation-menu-link\" class=\"data-[active=true]:focus:bg-accent data-[active=true]:hover:bg-accent data-[active=true]:bg-accent/50 data-[active=true]:text-accent-foreground hover:bg-accent hover:text-accent-foreground focus:bg-accent focus:text-accent-foreground focus-visible:ring-ring/50 [&amp;_svg:not([class*=&#x27;text-&#x27;])]:text-muted-foreground flex flex-col gap-1 rounded-sm p-2 text-sm transition-all outline-none focus-visible:ring-[3px] focus-visible:outline-1 [&amp;_svg:not([class*=&#x27;size-&#x27;])]:size-4\" data-radix-collection-item=\"\" href=\"/blog\">Blog</a></li></ul></div><div class=\"absolute top-full left-0 isolate z-50 flex justify-center\"></div></nav><div class=\"flex items-center gap-3\"><button data-slot=\"button\" class=\"inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-md text-sm font-medium transition-all disabled:pointer-events-none disabled:opacity-50 [&amp;_svg]:pointer-events-none [&amp;_svg:not([class*=&#x27;size-&#x27;])]:size-4 shrink-0 [&amp;_svg]:shrink-0 outline-none focus-visible:border-ring focus-visible:ring-ring/50 focus-visible:ring-[3px] aria-invalid:ring-destructive/20 dark:aria-invalid:ring-destructive/40 aria-invalid:border-destructive hover:bg-accent hover:text-accent-foreground dark:hover:bg-accent/50 size-9\" type=\"button\" id=\"radix-_R_7db_\" aria-haspopup=\"menu\" aria-expanded=\"false\" data-state=\"closed\"><svg xmlns=\"http://www.w3.org/2000/svg\" width=\"24\" height=\"24\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" class=\"lucide lucide-sun h-[1.2rem] w-[1.2rem] rotate-0 scale-100 transition-all dark:-rotate-90 dark:scale-0\" aria-hidden=\"true\"><circle cx=\"12\" cy=\"12\" r=\"4\"></circle><path d=\"M12 2v2\"></path><path d=\"M12 20v2\"></path><path d=\"m4.93 4.93 1.41 1.41\"></path><path d=\"m17.66 17.66 1.41 1.41\"></path><path d=\"M2 12h2\"></path><path d=\"M20 12h2\"></path><path d=\"m6.34 17.66-1.41 1.41\"></path><path d=\"m19.07 4.93-1.41 1.41\"></path></svg><svg xmlns=\"http://www.w3.org/2000/svg\" width=\"24\" height=\"24\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" class=\"lucide lucide-moon absolute h-[1.2rem] w-[1.2rem] rotate-90 scale-0 transition-all dark:rotate-0 dark:scale-100\" aria-hidden=\"true\"><path d=\"M20.985 12.486a9 9 0 1 1-9.473-9.472c.405-.022.617.46.402.803a6 6 0 0 0 8.268 8.268c.344-.215.825-.004.803.401\"></path></svg><span class=\"sr-only\">Toggle theme</span></button><button data-slot=\"button\" class=\"inline-flex items-center justify-center gap-2 whitespace-nowrap text-sm font-medium disabled:pointer-events-none disabled:opacity-50 [&amp;_svg]:pointer-events-none [&amp;_svg:not([class*=&#x27;size-&#x27;])]:size-4 shrink-0 [&amp;_svg]:shrink-0 outline-none focus-visible:border-ring focus-visible:ring-ring/50 focus-visible:ring-[3px] aria-invalid:ring-destructive/20 dark:aria-invalid:ring-destructive/40 aria-invalid:border-destructive bg-primary text-primary-foreground hover:bg-primary/90 h-9 px-4 py-2 has-[&gt;svg]:px-3 rounded-full shadow-md hover:shadow-lg transition-shadow\">                                     <a href=\"https://discord.gg/dvbbPSHP\" target=\"_blank\" rel=\"noopener noreferrer\">Join Termtrix</a></button><div class=\"md:hidden\"><button data-slot=\"button\" class=\"inline-flex items-center justify-center gap-2 whitespace-nowrap text-sm font-medium transition-all disabled:pointer-events-none disabled:opacity-50 [&amp;_svg]:pointer-events-none [&amp;_svg:not([class*=&#x27;size-&#x27;])]:size-4 shrink-0 [&amp;_svg]:shrink-0 outline-none focus-visible:border-ring focus-visible:ring-ring/50 focus-visible:ring-[3px] aria-invalid:ring-destructive/20 dark:aria-invalid:ring-destructive/40 aria-invalid:border-destructive border bg-background shadow-xs hover:bg-accent hover:text-accent-foreground dark:bg-input/30 dark:border-input dark:hover:bg-input/50 size-9 rounded-full\" type=\"button\" aria-haspopup=\"dialog\" aria-expanded=\"false\" aria-controls=\"radix-_R_fdb_\" data-state=\"closed\"><svg xmlns=\"http://www.w3.org/2000/svg\" width=\"24\" height=\"24\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" class=\"lucide lucide-menu\" aria-hidden=\"true\"><path d=\"M4 5h16\"></path><path d=\"M4 12h16\"></path><path d=\"M4 19h16\"></path></svg></button></div></div></div></nav></div><main class=\"bg-background text-foreground overflow-x-hidden\"><section class=\"relative overflow-hidden bg-background py-24 sm:py-32 lg:pb-40\"><div class=\"absolute inset-0 z-0 overflow-hidden pointer-events-none\"><div class=\"absolute top-[-10%] left-[20%] h-[500px] w-[500px] rounded-full bg-primary/10 blur-[100px]\"></div><div class=\"absolute bottom-[-10%] right-[10%] h-[400px] w-[400px] rounded-full bg-accent/20 blur-[100px]\"></div></div><div class=\"container relative z-10 mx-auto px-4 text-center\"><div class=\"mx-auto flex max-w-4xl flex-col items-center\" style=\"opacity:0;transform:translateY(20px)\"><div class=\"mb-8 inline-flex items-center rounded-full border border-primary/20 bg-primary/5 px-3 py-1 text-sm font-medium text-primary backdrop-blur-sm\"><span class=\"flex h-2 w-2 rounded-full bg-primary mr-2 animate-pulse\"></span>Building Learning-Driven Tech Communities</div><h1 class=\"text-balance text-5xl font-bold tracking-tight text-foreground sm:text-7xl\">Learn <span class=\"text-primary bg-clip-text text-transparent bg-gradient-to-r from-primary to-accent\">Collaborate</span> &amp;<!-- --> <span class=\"relative\">Build<svg aria-hidden=\"true\" viewBox=\"0 0 418 42\" class=\"absolute left-0 top-2/3 h-[0.58em] w-full fill-primary/20 z-[-1]\" preserveAspectRatio=\"none\"><path d=\"M203.371.916c-26.013-2.078-76.686 1.963-124.73 9.946L67.3 12.749C46.169 16.243 4.198 21.956 2.57 23.363c-1.628 1.408-5.202 5.024-5.202 5.024l-3.37 2.623c-1.628 1.258-3.138 2.52-5.74 3.796-7.802 20.39-16.925 25.64-21.758 5.74 1.259 3.138 2.52 5.74 3.796 3.139 5.202 5.024 5.202 5.024 1.409 1.628 6.011 4.198 21.956 46.17 16.243l11.34-1.887c48.044-7.983 98.718-12.024 124.73-9.946 86.708 6.92 191.076 29.569 203.25 31.958 12.173 2.39 15.541-1.258 16.354-2.202.813-.943 1.259-3.138 2.52-5.74l3.139-5.202c1.259-1.628 4.198-6.011 16.243-46.17-11.34 1.888-48.044 7.984-98.718 12.025-50.674 4.04-124.73.916-203.25-31.958-12.173-2.39-4.378-5.202-5.74-2.52-1.362 2.682-.944 4.816-.944 4.816s11.531 37.14 85.08 62.72c36.772 12.788 84.815 16.829 124.73 9.946z\"></path></svg></span> <!-- -->Real Systems</h1><p class=\"mt-6 max-w-2xl text-lg text-muted-foreground sm:text-xl/8\"><strong>Termtrix</strong> is a developer community focused on learning, collaboration, and real-world problem solving. We explore modern technologies, share knowledge openly, and build meaningful systems together</p><div class=\"mt-10 flex flex-col gap-4 sm:flex-row sm:justify-center\"><a href=\"https://discord.gg/dvbbPSHP\" target=\"_blank\" rel=\"noopener noreferrer\" data-slot=\"button\" class=\"inline-flex items-center justify-center gap-2 whitespace-nowrap font-medium disabled:pointer-events-none disabled:opacity-50 [&amp;_svg]:pointer-events-none [&amp;_svg:not([class*=&#x27;size-&#x27;])]:size-4 shrink-0 [&amp;_svg]:shrink-0 outline-none focus-visible:border-ring focus-visible:ring-ring/50 focus-visible:ring-[3px] aria-invalid:ring-destructive/20 dark:aria-invalid:ring-destructive/40 aria-invalid:border-destructive bg-primary text-primary-foreground hover:bg-primary/90 has-[&gt;svg]:px-4 h-12 px-8 text-base rounded-full shadow-lg shadow-primary/20 hover:shadow-primary/30 transition-all\"><svg xmlns=\"http://www.w3.org/2000/svg\" width=\"24\" height=\"24\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" class=\"lucide lucide-users mr-2 h-5 w-5\" aria-hidden=\"true\"><path d=\"M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2\"></path><path d=\"M16 3.128a4 4 0 0 1 0 7.744\"></path><path d=\"M22 21v-2a4 4 0 0 0-3-3.87\"></path><circle cx=\"9\" cy=\"7\" r=\"4\"></circle></svg>Join Community</a><a href=\"https://github.com/TermTrix/\" target=\"_blank\" rel=\"noopener noreferrer\" data-slot=\"button\" class=\"inline-flex items-center justify-center gap-2 whitespace-nowrap font-medium disabled:pointer-events-none disabled:opacity-50 [&amp;_svg]:pointer-events-none [&amp;_svg:not([class*=&#x27;size-&#x27;])]:size-4 shrink-0 [&amp;_svg]:shrink-0 outline-none focus-visible:border-ring focus-visible:ring-ring/50 focus-visible:ring-[3px] aria-invalid:ring-destructive/20 dark:aria-invalid:ring-destructive/40 aria-invalid:border-destructive border bg-background shadow-xs hover:text-accent-foreground dark:bg-input/30 dark:border-input dark:hover:bg-input/50 has-[&gt;svg]:px-4 h-12 px-8 text-base rounded-full border-muted-foreground/20 hover:bg-muted/50 transition-all\">Explore Repositories<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"24\" height=\"24\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" class=\"lucide lucide-arrow-right ml-2 h-4 w-4\" aria-hidden=\"true\"><path d=\"M5 12h14\"></path><path d=\"m12 5 7 7-7 7\"></path></svg></a></div><div class=\"mt-16 flex items-center justify-center gap-8 opacity-70 grayscale transition-all hover:grayscale-0 hover:opacity-100\"><span class=\"text-sm font-semibold tracking-wider text-muted-foreground uppercase\">Powered by</span><div class=\"flex gap-6\"><span class=\"font-bold flex items-center\"><svg xmlns=\"http://www.w3.org/2000/svg\" width=\"24\" height=\"24\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" class=\"lucide lucide-rocket w-4 h-4 mr-1\" aria-hidden=\"true\"><path d=\"M4.5 16.5c-1.5 1.26-2 5-2 5s3.74-.5 5-2c.71-.84.7-2.13-.09-2.91a2.18 2.18 0 0 0-2.91-.09z\"></path><path d=\"m12 15-3-3a22 22 0 0 1 2-3.95A12.88 12.88 0 0 1 22 2c0 2.72-.78 7.5-6 11a22.35 22.35 0 0 1-4 2z\"></path><path d=\"M9 12H4s.55-3.03 2-4c1.62-1.08 5 0 5 0\"></path><path d=\"M12 15v5s3.03-.55 4-2c1.08-1.62 0-5 0-5\"></path></svg> Open Source</span><a href=\"https://github.com/TermTrix/\" target=\"_blank\" rel=\"noopener noreferrer\" class=\"font-bold flex items-center\"><svg xmlns=\"http://www.w3.org/2000/svg\" width=\"24\" height=\"24\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" class=\"lucide lucide-github w-4 h-4 mr-1\" aria-hidden=\"true\"><path d=\"M15 22v-4a4.8 4.8 0 0 0-1-3.5c3 0 6-2 6-5.5.08-1.25-.27-2.48-1-3.5.28-1.15.28-2.35 0-3.5 0 0-1 0-3 1.5-2.64-.5-5.36-.5-8 0C6 2 5 2 5 2c-.3 1.15-.3 2.35 0 3.5A5.403 5.403 0 0 0 4 9c0 3.5 3 5.5 6 5.5-.39.49-.68 1.05-.85 1.65-.17.6-.22 1.23-.15 1.85v4\"></path><path d=\"M9 18c-4.51 2-5-2-7-2\"></path></svg> Community-Driven</a></div></div></div></div></section><section class=\"container mx-auto px-4 mb-4\" id=\"community\"><div class=\"grid gap-12 lg:grid-cols-2 lg:gap-24\"><div class=\"flex flex-col space-y-8\"><div class=\"space-y-2\" style=\"opacity:0;transform:translateY(20px)\"><h2 class=\"text-3xl font-bold tracking-tight sm:text-4xl\">Latest Insights</h2><p class=\"text-muted-foreground text-lg\">What we’re learning while building real systems together...</p></div><div class=\"flex flex-col gap-6\"><article class=\"group relative flex flex-col items-start p-6 rounded-2xl border border-white/5 bg-white/5 hover:bg-white/10 hover:border-white/10 transition-all cursor-pointer\" style=\"opacity:0;transform:translateX(-20px)\"><a href=\"/blog/using-an-mcp-server-with-langgraph-a-practical-guide-to-mcp-adapters\" class=\"absolute inset-0 z-10\" aria-label=\"Read Using an MCP Server with LangGraph: A Practical Guide to MCP Adapters\"></a><div class=\"flex items-center gap-3 text-xs text-muted-foreground mb-3\"><span class=\"flex items-center gap-1\"><svg xmlns=\"http://www.w3.org/2000/svg\" width=\"24\" height=\"24\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" class=\"lucide lucide-calendar h-3 w-3\" aria-hidden=\"true\"><path d=\"M8 2v4\"></path><path d=\"M16 2v4\"></path><rect width=\"18\" height=\"18\" x=\"3\" y=\"4\" rx=\"2\"></rect><path d=\"M3 10h18\"></path></svg> <!-- -->Dec 22, 2025</span><span>•</span><span class=\"flex items-center gap-1\"><svg xmlns=\"http://www.w3.org/2000/svg\" width=\"24\" height=\"24\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" class=\"lucide lucide-book-open h-3 w-3\" aria-hidden=\"true\"><path d=\"M12 7v14\"></path><path d=\"M3 18a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h5a4 4 0 0 1 4 4 4 4 0 0 1 4-4h5a1 1 0 0 1 1 1v13a1 1 0 0 1-1 1h-6a3 3 0 0 0-3 3 3 3 0 0 0-3-3z\"></path></svg> <!-- -->5min read</span></div><h3 class=\"text-xl font-semibold mb-2 group-hover:text-primary transition-colors\">Using an MCP Server with LangGraph: A Practical Guide to MCP Adapters</h3><p class=\"text-muted-foreground text-sm line-clamp-2 mb-4\">Learn how to integrate an MCP server with LangGraph using MCP adapters to build deterministic, schema-validated AI agents. This practical guide explains why prompt-only tool calling fails and how MCP enables reliable, production-grade agent workflows.</p><span class=\"text-sm font-medium text-primary flex items-center gap-1 mt-auto\">Read Article <svg xmlns=\"http://www.w3.org/2000/svg\" width=\"24\" height=\"24\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" class=\"lucide lucide-arrow-right h-4 w-4 transition-transform group-hover:translate-x-1\" aria-hidden=\"true\"><path d=\"M5 12h14\"></path><path d=\"m12 5 7 7-7 7\"></path></svg></span></article><article class=\"group relative flex flex-col items-start p-6 rounded-2xl border border-white/5 bg-white/5 hover:bg-white/10 hover:border-white/10 transition-all cursor-pointer\" style=\"opacity:0;transform:translateX(-20px)\"><a href=\"/blog/turbopack-in-nextjs-does-turbopackfilesystemcachefordev-make-your-app-lightning-fast\" class=\"absolute inset-0 z-10\" aria-label=\"Read 🚀 Turbopack in Next.js: Does turbopackFileSystemCacheForDev Make Your App Lightning Fast?\"></a><div class=\"flex items-center gap-3 text-xs text-muted-foreground mb-3\"><span class=\"flex items-center gap-1\"><svg xmlns=\"http://www.w3.org/2000/svg\" width=\"24\" height=\"24\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" class=\"lucide lucide-calendar h-3 w-3\" aria-hidden=\"true\"><path d=\"M8 2v4\"></path><path d=\"M16 2v4\"></path><rect width=\"18\" height=\"18\" x=\"3\" y=\"4\" rx=\"2\"></rect><path d=\"M3 10h18\"></path></svg> <!-- -->Dec 20, 2025</span><span>•</span><span class=\"flex items-center gap-1\"><svg xmlns=\"http://www.w3.org/2000/svg\" width=\"24\" height=\"24\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" class=\"lucide lucide-book-open h-3 w-3\" aria-hidden=\"true\"><path d=\"M12 7v14\"></path><path d=\"M3 18a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h5a4 4 0 0 1 4 4 4 4 0 0 1 4-4h5a1 1 0 0 1 1 1v13a1 1 0 0 1-1 1h-6a3 3 0 0 0-3 3 3 3 0 0 0-3-3z\"></path></svg> <!-- -->2min read</span></div><h3 class=\"text-xl font-semibold mb-2 group-hover:text-primary transition-colors\">🚀 Turbopack in Next.js: Does turbopackFileSystemCacheForDev Make Your App Lightning Fast?</h3><p class=\"text-muted-foreground text-sm line-clamp-2 mb-4\">No description available.</p><span class=\"text-sm font-medium text-primary flex items-center gap-1 mt-auto\">Read Article <svg xmlns=\"http://www.w3.org/2000/svg\" width=\"24\" height=\"24\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" class=\"lucide lucide-arrow-right h-4 w-4 transition-transform group-hover:translate-x-1\" aria-hidden=\"true\"><path d=\"M5 12h14\"></path><path d=\"m12 5 7 7-7 7\"></path></svg></span></article><article class=\"group relative flex flex-col items-start p-6 rounded-2xl border border-white/5 bg-white/5 hover:bg-white/10 hover:border-white/10 transition-all cursor-pointer\" style=\"opacity:0;transform:translateX(-20px)\"><a href=\"/blog/perfect-aws-security-group-best-practices\" class=\"absolute inset-0 z-10\" aria-label=\"Read How to Create a Perfect AWS Security Group (Production-Ready &amp; Secure)\"></a><div class=\"flex items-center gap-3 text-xs text-muted-foreground mb-3\"><span class=\"flex items-center gap-1\"><svg xmlns=\"http://www.w3.org/2000/svg\" width=\"24\" height=\"24\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" class=\"lucide lucide-calendar h-3 w-3\" aria-hidden=\"true\"><path d=\"M8 2v4\"></path><path d=\"M16 2v4\"></path><rect width=\"18\" height=\"18\" x=\"3\" y=\"4\" rx=\"2\"></rect><path d=\"M3 10h18\"></path></svg> <!-- -->Dec 20, 2025</span><span>•</span><span class=\"flex items-center gap-1\"><svg xmlns=\"http://www.w3.org/2000/svg\" width=\"24\" height=\"24\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" class=\"lucide lucide-book-open h-3 w-3\" aria-hidden=\"true\"><path d=\"M12 7v14\"></path><path d=\"M3 18a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h5a4 4 0 0 1 4 4 4 4 0 0 1 4-4h5a1 1 0 0 1 1 1v13a1 1 0 0 1-1 1h-6a3 3 0 0 0-3 3 3 3 0 0 0-3-3z\"></path></svg> <!-- -->4min read</span></div><h3 class=\"text-xl font-semibold mb-2 group-hover:text-primary transition-colors\">How to Create a Perfect AWS Security Group (Production-Ready &amp; Secure)</h3><p class=\"text-muted-foreground text-sm line-clamp-2 mb-4\">Learn how to design a production-ready AWS Security Group using least-privilege principles for EC2, RDS, and Redis—without breaking your app.\n\nAWS Security Group best practices\n\nSecure EC2 Security Group\n\nRDS Security Group configuration\n\nRedis Security Group AWS\n\nAWS least privilege networking\n\nCloud security for backend apps</p><span class=\"text-sm font-medium text-primary flex items-center gap-1 mt-auto\">Read Article <svg xmlns=\"http://www.w3.org/2000/svg\" width=\"24\" height=\"24\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" class=\"lucide lucide-arrow-right h-4 w-4 transition-transform group-hover:translate-x-1\" aria-hidden=\"true\"><path d=\"M5 12h14\"></path><path d=\"m12 5 7 7-7 7\"></path></svg></span></article></div></div><div class=\"flex flex-col justify-center\"><div class=\"relative overflow-hidden rounded-3xl border border-primary/20 bg-gradient-to-br from-primary/10 via-primary/5 to-transparent p-8 md:p-12\" style=\"opacity:0;transform:scale(0.95)\"><div class=\"absolute top-0 right-0 -mr-16 -mt-16 h-64 w-64 rounded-full bg-primary/20 blur-[80px]\"></div><div class=\"absolute bottom-0 left-0 -ml-16 -mb-16 h-64 w-64 rounded-full bg-blue-500/10 blur-[80px]\"></div><div class=\"relative z-10 space-y-8 text-center\"><div class=\"mx-auto flex h-20 w-20 items-center justify-center rounded-2xl bg-gradient-to-br from-primary to-blue-600 shadow-xl shadow-primary/20\"><svg xmlns=\"http://www.w3.org/2000/svg\" width=\"24\" height=\"24\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" class=\"lucide lucide-users h-10 w-10 text-white\" aria-hidden=\"true\"><path d=\"M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2\"></path><path d=\"M16 3.128a4 4 0 0 1 0 7.744\"></path><path d=\"M22 21v-2a4 4 0 0 0-3-3.87\"></path><circle cx=\"9\" cy=\"7\" r=\"4\"></circle></svg></div><div class=\"space-y-4\"><h3 class=\"text-3xl font-bold\">Learn. Collaborate. Build — Together.</h3><p class=\"text-muted-foreground\">Join Termtrix, a community of developers focused on learning through collaboration and building real systems.</p></div><div class=\"flex flex-col gap-3 sm:flex-row sm:justify-center\"><a href=\"https://discord.gg/dvbbPSHP\" target=\"_blank\" rel=\"noopener noreferrer\" data-slot=\"button\" class=\"inline-flex items-center justify-center gap-2 whitespace-nowrap font-medium transition-all disabled:pointer-events-none disabled:opacity-50 [&amp;_svg]:pointer-events-none [&amp;_svg:not([class*=&#x27;size-&#x27;])]:size-4 shrink-0 [&amp;_svg]:shrink-0 outline-none focus-visible:border-ring focus-visible:ring-ring/50 focus-visible:ring-[3px] aria-invalid:ring-destructive/20 dark:aria-invalid:ring-destructive/40 aria-invalid:border-destructive bg-primary text-primary-foreground hover:bg-primary/90 has-[&gt;svg]:px-4 rounded-full h-12 px-8 text-base shadow-lg shadow-primary/25\"><svg xmlns=\"http://www.w3.org/2000/svg\" width=\"24\" height=\"24\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" class=\"lucide lucide-message-square mr-2 h-5 w-5\" aria-hidden=\"true\"><path d=\"M22 17a2 2 0 0 1-2 2H6.828a2 2 0 0 0-1.414.586l-2.202 2.202A.71.71 0 0 1 2 21.286V5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2z\"></path></svg>Join Termtrix</a><button data-slot=\"button\" class=\"inline-flex items-center justify-center gap-2 whitespace-nowrap font-medium transition-all disabled:pointer-events-none disabled:opacity-50 [&amp;_svg]:pointer-events-none [&amp;_svg:not([class*=&#x27;size-&#x27;])]:size-4 shrink-0 [&amp;_svg]:shrink-0 outline-none focus-visible:border-ring focus-visible:ring-ring/50 focus-visible:ring-[3px] aria-invalid:ring-destructive/20 dark:aria-invalid:ring-destructive/40 aria-invalid:border-destructive border shadow-xs hover:text-accent-foreground dark:bg-input/30 dark:border-input dark:hover:bg-input/50 has-[&gt;svg]:px-4 rounded-full h-12 px-8 text-base bg-transparent border-white/10 hover:bg-white/5 cursor-pointer\">Join Discussions</button></div><div class=\"pt-4 flex items-center justify-center -space-x-3\"><div class=\"h-10 w-10 rounded-full border-2 border-background bg-zinc-800 flex items-center justify-center text-xs font-bold text-zinc-500\">TM<!-- -->1</div><div class=\"h-10 w-10 rounded-full border-2 border-background bg-zinc-800 flex items-center justify-center text-xs font-bold text-zinc-500\">TM<!-- -->2</div><div class=\"h-10 w-10 rounded-full border-2 border-background bg-zinc-800 flex items-center justify-center text-xs font-bold text-zinc-500\">TM<!-- -->3</div><div class=\"h-10 w-10 rounded-full border-2 border-background bg-zinc-800 flex items-center justify-center text-xs font-bold text-zinc-500\">TM<!-- -->4</div><div class=\"h-10 w-10 rounded-full border-2 border-background bg-primary/20 flex items-center justify-center text-xs font-bold text-primary\">TΞ</div></div></div></div></div></div></section><footer class=\"relative border-t border-white/10 bg-black pt-24 pb-12 overflow-hidden\"><div class=\"absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-primary/50 to-transparent opacity-50\"></div><div class=\"absolute top-0 left-1/2 -translate-x-1/2 h-[500px] w-[800px] bg-primary/5 rounded-full blur-[120px] pointer-events-none\"></div><div class=\"container mx-auto px-4 space-y-16 relative z-10\"><h2 class=\"text-5xl   max-w-7xl font-bold tracking-tighter sm:text-7xl bg-clip-text text-transparent bg-gradient-to-b from-white to-white/50\" style=\"opacity:0;transform:translateY(20px)\">Let&#x27;s build something <!-- --> <!-- -->  <br/><span class=\"text-primary bg-gradient-to-r from-primary to-blue-500 bg-clip-text text-transparent\">meaningful — together..</span></h2><div class=\"grid grid-cols-1 lg:grid-cols-2 gap-16 lg:gap-24 mb-20\"><div class=\"space-y-8\"><p class=\"text-muted-foreground text-lg max-w-md\">Building real systems through learning and collaboration. Join the Termtrix community and grow together.</p><div class=\"flex flex-wrap gap-4\"><a href=\"mailto:termtrix.community@gmail.com\" data-slot=\"button\" class=\"inline-flex items-center justify-center whitespace-nowrap font-medium transition-all disabled:pointer-events-none disabled:opacity-50 [&amp;_svg]:pointer-events-none [&amp;_svg:not([class*=&#x27;size-&#x27;])]:size-4 shrink-0 [&amp;_svg]:shrink-0 outline-none focus-visible:border-ring focus-visible:ring-ring/50 focus-visible:ring-[3px] aria-invalid:ring-destructive/20 dark:aria-invalid:ring-destructive/40 aria-invalid:border-destructive bg-primary text-primary-foreground hover:bg-primary/90 has-[&gt;svg]:px-4 h-14 px-8 rounded-full text-lg gap-2 shadow-lg shadow-primary/20\"><svg xmlns=\"http://www.w3.org/2000/svg\" width=\"24\" height=\"24\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" class=\"lucide lucide-mail h-5 w-5\" aria-hidden=\"true\"><path d=\"m22 7-8.991 5.727a2 2 0 0 1-2.009 0L2 7\"></path><rect x=\"2\" y=\"4\" width=\"20\" height=\"16\" rx=\"2\"></rect></svg>termtrix.community@gmail.com</a><button data-slot=\"button\" class=\"inline-flex items-center justify-center whitespace-nowrap font-medium transition-all disabled:pointer-events-none disabled:opacity-50 [&amp;_svg]:pointer-events-none [&amp;_svg:not([class*=&#x27;size-&#x27;])]:size-4 shrink-0 [&amp;_svg]:shrink-0 outline-none focus-visible:border-ring focus-visible:ring-ring/50 focus-visible:ring-[3px] aria-invalid:ring-destructive/20 dark:aria-invalid:ring-destructive/40 aria-invalid:border-destructive border shadow-xs hover:text-accent-foreground dark:bg-input/30 dark:border-input dark:hover:bg-input/50 has-[&gt;svg]:px-4 h-14 px-8 rounded-full text-lg gap-2 border-white/10 bg-transparent hover:bg-white/5 cursor-pointer\"><svg xmlns=\"http://www.w3.org/2000/svg\" width=\"24\" height=\"24\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" class=\"lucide lucide-arrow-up-right h-5 w-5\" aria-hidden=\"true\"><path d=\"M7 7h10v10\"></path><path d=\"M7 17 17 7\"></path></svg>Subscribe</button></div></div><div class=\"flex flex-col justify-end lg:items-end space-y-12\"><div class=\"grid grid-cols-2 gap-12 sm:gap-24\"><div class=\"space-y-4\"><h4 class=\"font-bold text-lg\">Navigation</h4><ul class=\"space-y-2 text-muted-foreground\"><li><a href=\"#\" class=\"hover:text-primary transition-colors\">Home</a></li><li><a href=\"#projects\" class=\"hover:text-primary transition-colors\">Work</a></li><li><a href=\"#community\" class=\"hover:text-primary transition-colors\">Community</a></li><li><a href=\"#about\" class=\"hover:text-primary transition-colors\">About</a></li></ul></div><div class=\"space-y-4\"><h4 class=\"font-bold text-lg\">Socials</h4><ul class=\"space-y-2 text-muted-foreground\"><li><a href=\"https://x.com/TermTrix\" target=\"_blank\" class=\"hover:text-primary transition-colors\">Twitter / X</a></li><li><a href=\"https://github.com/TermTrix\" target=\"_blank\" class=\"hover:text-primary transition-colors\">GitHub</a></li><li><a href=\"https://www.linkedin.com/in/bala-s-1395a621a/\" target=\"_blank\" class=\"hover:text-primary transition-colors\">LinkedIn</a></li><li><a href=\"https://discord.gg/dvbbPSHP\" target=\"_blank\" class=\"hover:text-primary transition-colors\">Discord</a></li></ul></div></div></div></div><div class=\"border-t border-white/5 pt-8 flex flex-col md:flex-row justify-between items-center gap-4 text-sm text-muted-foreground\"><p>© <!-- -->2025<!-- --> Grigore Budac. All rights reserved.</p><div class=\"flex items-center gap-8\"><a href=\"#\" class=\"hover:text-foreground transition-colors\">Privacy Policy</a><a href=\"#\" class=\"hover:text-foreground transition-colors\">Terms of Service</a></div></div></div></footer></main><!--$--><!--/$--><script src=\"/_next/static/chunks/c62b4372c26b460f.js\" id=\"_R_\" async=\"\"></script><script>(self.__next_f=self.__next_f||[]).push([0])</script><script>self.__next_f.push([1,\"1:\\\"$Sreact.fragment\\\"\\n2:I[84931,[\\\"/_next/static/chunks/25f0986ed87d220e.js\\\",\\\"/_next/static/chunks/e2b0ebdd7c9ec357.js\\\",\\\"/_next/static/chunks/3f682a3264f29773.js\\\",\\\"/_next/static/chunks/703ab740f268a9b9.js\\\"],\\\"ThemeProvider\\\"]\\n3:I[85437,[\\\"/_next/static/chunks/25f0986ed87d220e.js\\\",\\\"/_next/static/chunks/e2b0ebdd7c9ec357.js\\\",\\\"/_next/static/chunks/3f682a3264f29773.js\\\",\\\"/_next/static/chunks/703ab740f268a9b9.js\\\",\\\"/_next/static/chunks/53c5ffaf39e0edf3.js\\\",\\\"/_next/static/chunks/ece0d313a4d1cc87.js\\\",\\\"/_next/static/chunks/483d179ffd78e2c9.js\\\"],\\\"Image\\\"]\\n4:I[76958,[\\\"/_next/static/chunks/25f0986ed87d220e.js\\\",\\\"/_next/static/chunks/e2b0ebdd7c9ec357.js\\\",\\\"/_next/static/chunks/3f682a3264f29773.js\\\",\\\"/_next/static/chunks/703ab740f268a9b9.js\\\"],\\\"Root\\\"]\\n5:I[76958,[\\\"/_next/static/chunks/25f0986ed87d220e.js\\\",\\\"/_next/static/chunks/e2b0ebdd7c9ec357.js\\\",\\\"/_next/static/chunks/3f682a3264f29773.js\\\",\\\"/_next/static/chunks/703ab740f268a9b9.js\\\"],\\\"List\\\"]\\n6:I[76958,[\\\"/_next/static/chunks/25f0986ed87d220e.js\\\",\\\"/_next/static/chunks/e2b0ebdd7c9ec357.js\\\",\\\"/_next/static/chunks/3f682a3264f29773.js\\\",\\\"/_next/static/chunks/703ab740f268a9b9.js\\\"],\\\"Item\\\"]\\n7:I[76958,[\\\"/_next/static/chunks/25f0986ed87d220e.js\\\",\\\"/_next/static/chunks/e2b0ebdd7c9ec357.js\\\",\\\"/_next/static/chunks/3f682a3264f29773.js\\\",\\\"/_next/static/chunks/703ab740f268a9b9.js\\\"],\\\"Link\\\"]\\n8:I[22016,[\\\"/_next/static/chunks/25f0986ed87d220e.js\\\",\\\"/_next/static/chunks/e2b0ebdd7c9ec357.js\\\",\\\"/_next/static/chunks/3f682a3264f29773.js\\\",\\\"/_next/static/chunks/703ab740f268a9b9.js\\\",\\\"/_next/static/chunks/53c5ffaf39e0edf3.js\\\",\\\"/_next/static/chunks/ece0d313a4d1cc87.js\\\",\\\"/_next/static/chunks/483d179ffd78e2c9.js\\\"],\\\"default\\\"]\\n9:I[76958,[\\\"/_next/static/chunks/25f0986ed87d220e.js\\\",\\\"/_next/static/chunks/e2b0ebdd7c9ec357.js\\\",\\\"/_next/static/chunks/3f682a3264f29773.js\\\",\\\"/_next/static/chunks/703ab740f268a9b9.js\\\"],\\\"Viewport\\\"]\\ne:I[68027,[\\\"/_next/static/chunks/25f0986ed87d220e.js\\\",\\\"/_next/static/chunks/e2b0ebdd7c9ec357.js\\\",\\\"/_next/static/chunks/3f682a3264f29773.js\\\",\\\"/_next/static/chunks/703ab740f268a9b9.js\\\"],\\\"default\\\"]\\n11:I[38370,[\\\"/_next/s\"])</script><script>self.__next_f.push([1,\"tatic/chunks/25f0986ed87d220e.js\\\",\\\"/_next/static/chunks/e2b0ebdd7c9ec357.js\\\",\\\"/_next/static/chunks/3f682a3264f29773.js\\\",\\\"/_next/static/chunks/703ab740f268a9b9.js\\\"],\\\"ModeToggle\\\"]\\n12:I[32866,[\\\"/_next/static/chunks/25f0986ed87d220e.js\\\",\\\"/_next/static/chunks/e2b0ebdd7c9ec357.js\\\",\\\"/_next/static/chunks/3f682a3264f29773.js\\\",\\\"/_next/static/chunks/703ab740f268a9b9.js\\\"],\\\"Sheet\\\"]\\n13:I[32866,[\\\"/_next/static/chunks/25f0986ed87d220e.js\\\",\\\"/_next/static/chunks/e2b0ebdd7c9ec357.js\\\",\\\"/_next/static/chunks/3f682a3264f29773.js\\\",\\\"/_next/static/chunks/703ab740f268a9b9.js\\\"],\\\"SheetTrigger\\\"]\\n14:I[32866,[\\\"/_next/static/chunks/25f0986ed87d220e.js\\\",\\\"/_next/static/chunks/e2b0ebdd7c9ec357.js\\\",\\\"/_next/static/chunks/3f682a3264f29773.js\\\",\\\"/_next/static/chunks/703ab740f268a9b9.js\\\"],\\\"SheetContent\\\"]\\n17:I[39756,[\\\"/_next/static/chunks/ff1a16fafef87110.js\\\",\\\"/_next/static/chunks/89460367c0865bec.js\\\"],\\\"default\\\"]\\n18:I[37457,[\\\"/_next/static/chunks/ff1a16fafef87110.js\\\",\\\"/_next/static/chunks/89460367c0865bec.js\\\"],\\\"default\\\"]\\n1a:I[97367,[\\\"/_next/static/chunks/ff1a16fafef87110.js\\\",\\\"/_next/static/chunks/89460367c0865bec.js\\\"],\\\"OutletBoundary\\\"]\\n1c:I[14706,[\\\"/_next/static/chunks/ff1a16fafef87110.js\\\",\\\"/_next/static/chunks/89460367c0865bec.js\\\"],\\\"AsyncMetadataOutlet\\\"]\\n1e:I[97367,[\\\"/_next/static/chunks/ff1a16fafef87110.js\\\",\\\"/_next/static/chunks/89460367c0865bec.js\\\"],\\\"ViewportBoundary\\\"]\\n20:I[97367,[\\\"/_next/static/chunks/ff1a16fafef87110.js\\\",\\\"/_next/static/chunks/89460367c0865bec.js\\\"],\\\"MetadataBoundary\\\"]\\n21:\\\"$Sreact.suspense\\\"\\n23:I[27201,[\\\"/_next/static/chunks/ff1a16fafef87110.js\\\",\\\"/_next/static/chunks/89460367c0865bec.js\\\"],\\\"IconMark\\\"]\\n:HL[\\\"/_next/static/chunks/fff905c71cb6ab0c.css\\\",\\\"style\\\"]\\n:HL[\\\"/_next/static/chunks/d9f7fc5c3062ede5.css\\\",\\\"style\\\"]\\n:HL[\\\"/_next/static/media/797e433ab948586e-s.p.dbea232f.woff2\\\",\\\"font\\\",{\\\"crossOrigin\\\":\\\"\\\",\\\"type\\\":\\\"font/woff2\\\"}]\\n:HL[\\\"/_next/static/media/caa3a2e1cccd8315-s.p.853070df.woff2\\\",\\\"font\\\",{\\\"crossOrigin\\\":\\\"\\\",\\\"type\\\":\\\"font/woff2\\\"}]\\n\"])</script><script>self.__next_f.push([1,\"0:{\\\"P\\\":null,\\\"b\\\":\\\"CGCGyTKAoz8io5gvM5DOv\\\",\\\"p\\\":\\\"\\\",\\\"c\\\":[\\\"\\\",\\\"\\\"],\\\"i\\\":false,\\\"f\\\":[[[\\\"\\\",{\\\"children\\\":[\\\"__PAGE__\\\",{}]},\\\"$undefined\\\",\\\"$undefined\\\",true],[\\\"\\\",[\\\"$\\\",\\\"$1\\\",\\\"c\\\",{\\\"children\\\":[[[\\\"$\\\",\\\"link\\\",\\\"0\\\",{\\\"rel\\\":\\\"stylesheet\\\",\\\"href\\\":\\\"/_next/static/chunks/fff905c71cb6ab0c.css\\\",\\\"precedence\\\":\\\"next\\\",\\\"crossOrigin\\\":\\\"$undefined\\\",\\\"nonce\\\":\\\"$undefined\\\"}],[\\\"$\\\",\\\"link\\\",\\\"1\\\",{\\\"rel\\\":\\\"stylesheet\\\",\\\"href\\\":\\\"/_next/static/chunks/d9f7fc5c3062ede5.css\\\",\\\"precedence\\\":\\\"next\\\",\\\"crossOrigin\\\":\\\"$undefined\\\",\\\"nonce\\\":\\\"$undefined\\\"}],[\\\"$\\\",\\\"script\\\",\\\"script-0\\\",{\\\"src\\\":\\\"/_next/static/chunks/25f0986ed87d220e.js\\\",\\\"async\\\":true,\\\"nonce\\\":\\\"$undefined\\\"}],[\\\"$\\\",\\\"script\\\",\\\"script-1\\\",{\\\"src\\\":\\\"/_next/static/chunks/e2b0ebdd7c9ec357.js\\\",\\\"async\\\":true,\\\"nonce\\\":\\\"$undefined\\\"}],[\\\"$\\\",\\\"script\\\",\\\"script-2\\\",{\\\"src\\\":\\\"/_next/static/chunks/3f682a3264f29773.js\\\",\\\"async\\\":true,\\\"nonce\\\":\\\"$undefined\\\"}],[\\\"$\\\",\\\"script\\\",\\\"script-3\\\",{\\\"src\\\":\\\"/_next/static/chunks/703ab740f268a9b9.js\\\",\\\"async\\\":true,\\\"nonce\\\":\\\"$undefined\\\"}]],[\\\"$\\\",\\\"html\\\",null,{\\\"lang\\\":\\\"en\\\",\\\"suppressHydrationWarning\\\":true,\\\"children\\\":[\\\"$\\\",\\\"body\\\",null,{\\\"className\\\":\\\"geist_2ae47f08-module__h69qWW__variable geist_mono_eb58308d-module__w_p2Lq__variable antialiased\\\",\\\"children\\\":[\\\"$\\\",\\\"$L2\\\",null,{\\\"attribute\\\":\\\"class\\\",\\\"defaultTheme\\\":\\\"system\\\",\\\"enableSystem\\\":true,\\\"disableTransitionOnChange\\\":true,\\\"children\\\":[[\\\"$\\\",\\\"div\\\",null,{\\\"className\\\":\\\"z-50\\\",\\\"children\\\":[\\\"$\\\",\\\"nav\\\",null,{\\\"className\\\":\\\"fixed top-4 left-4 right-4 z-50 h-16 max-w-7xl mx-auto rounded-full border border-border/40 bg-background/60 backdrop-blur-md shadow-sm transition-all\\\",\\\"children\\\":[\\\"$\\\",\\\"div\\\",null,{\\\"className\\\":\\\"h-full flex items-center justify-between px-6\\\",\\\"children\\\":[[\\\"$\\\",\\\"div\\\",null,{\\\"className\\\":\\\"flex items-center gap-2 hover:opacity-90 transition-opacity\\\",\\\"children\\\":[[\\\"$\\\",\\\"div\\\",null,{\\\"className\\\":\\\"relative h-10 w-10 overflow-hidden rounded-lg border border-white/10 shadow-sm\\\",\\\"children\\\":[\\\"$\\\",\\\"$L3\\\",null,{\\\"src\\\":\\\"/termtrix-logo.jpg\\\",\\\"alt\\\":\\\"TermTrix Logo\\\",\\\"fill\\\":true,\\\"className\\\":\\\"object-cover\\\",\\\"priority\\\":true}]}],[\\\"$\\\",\\\"span\\\",null,{\\\"className\\\":\\\"font-bold dark:text-white text-xl tracking-tight bg-gradient-to-r from-white to-white/70 bg-clip-text text-transparent\\\",\\\"children\\\":\\\"TΞRMTRIX\\\"}]]}],[\\\"$\\\",\\\"$L4\\\",null,{\\\"data-slot\\\":\\\"navigation-menu\\\",\\\"data-viewport\\\":true,\\\"className\\\":\\\"group/navigation-menu relative max-w-max flex-1 items-center justify-center hidden md:block\\\",\\\"children\\\":[[\\\"$\\\",\\\"$L5\\\",null,{\\\"data-slot\\\":\\\"navigation-menu-list\\\",\\\"className\\\":\\\"group flex flex-1 list-none items-center justify-center gap-3 space-x-0 data-[orientation=vertical]:flex-col data-[orientation=vertical]:items-start data-[orientation=vertical]:justify-start\\\",\\\"children\\\":[[\\\"$\\\",\\\"$L6\\\",null,{\\\"data-slot\\\":\\\"navigation-menu-item\\\",\\\"className\\\":\\\"relative\\\",\\\"children\\\":[\\\"$\\\",\\\"$L7\\\",null,{\\\"data-slot\\\":\\\"navigation-menu-link\\\",\\\"className\\\":\\\"data-[active=true]:focus:bg-accent data-[active=true]:hover:bg-accent data-[active=true]:bg-accent/50 data-[active=true]:text-accent-foreground hover:bg-accent hover:text-accent-foreground focus:bg-accent focus:text-accent-foreground focus-visible:ring-ring/50 [\\u0026_svg:not([class*='text-'])]:text-muted-foreground flex flex-col gap-1 rounded-sm p-2 text-sm transition-all outline-none focus-visible:ring-[3px] focus-visible:outline-1 [\\u0026_svg:not([class*='size-'])]:size-4\\\",\\\"asChild\\\":true,\\\"children\\\":[\\\"$\\\",\\\"$L8\\\",null,{\\\"href\\\":\\\"/\\\",\\\"children\\\":\\\"Home\\\"}]}]}],[\\\"$\\\",\\\"$L6\\\",null,{\\\"data-slot\\\":\\\"navigation-menu-item\\\",\\\"className\\\":\\\"relative\\\",\\\"children\\\":[\\\"$\\\",\\\"$L7\\\",null,{\\\"data-slot\\\":\\\"navigation-menu-link\\\",\\\"className\\\":\\\"data-[active=true]:focus:bg-accent data-[active=true]:hover:bg-accent data-[active=true]:bg-accent/50 data-[active=true]:text-accent-foreground hover:bg-accent hover:text-accent-foreground focus:bg-accent focus:text-accent-foreground focus-visible:ring-ring/50 [\\u0026_svg:not([class*='text-'])]:text-muted-foreground flex flex-col gap-1 rounded-sm p-2 text-sm transition-all outline-none focus-visible:ring-[3px] focus-visible:outline-1 [\\u0026_svg:not([class*='size-'])]:size-4\\\",\\\"asChild\\\":true,\\\"children\\\":[\\\"$\\\",\\\"$L8\\\",null,{\\\"href\\\":\\\"/blog\\\",\\\"children\\\":\\\"Blog\\\"}]}]}]]}],[\\\"$\\\",\\\"div\\\",null,{\\\"className\\\":\\\"absolute top-full left-0 isolate z-50 flex justify-center\\\",\\\"children\\\":[\\\"$\\\",\\\"$L9\\\",null,{\\\"data-slot\\\":\\\"navigation-menu-viewport\\\",\\\"className\\\":\\\"origin-top-center bg-popover text-popover-foreground data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-90 relative mt-1.5 h-[var(--radix-navigation-menu-viewport-height)] w-full overflow-hidden rounded-md border shadow md:w-[var(--radix-navigation-menu-viewport-width)]\\\"}]}]]}],\\\"$La\\\"]}]}]}],\\\"$Lb\\\"]}]}]}]]}],{\\\"children\\\":[\\\"__PAGE__\\\",\\\"$Lc\\\",{},null,false]},null,false],\\\"$Ld\\\",false]],\\\"m\\\":\\\"$undefined\\\",\\\"G\\\":[\\\"$e\\\",[\\\"$Lf\\\",\\\"$L10\\\"]],\\\"s\\\":false,\\\"S\\\":false}\\n\"])</script><script>self.__next_f.push([1,\"a:[\\\"$\\\",\\\"div\\\",null,{\\\"className\\\":\\\"flex items-center gap-3\\\",\\\"children\\\":[[\\\"$\\\",\\\"$L11\\\",null,{}],[\\\"$\\\",\\\"button\\\",null,{\\\"data-slot\\\":\\\"button\\\",\\\"className\\\":\\\"inline-flex items-center justify-center gap-2 whitespace-nowrap text-sm font-medium disabled:pointer-events-none disabled:opacity-50 [\\u0026_svg]:pointer-events-none [\\u0026_svg:not([class*='size-'])]:size-4 shrink-0 [\\u0026_svg]:shrink-0 outline-none focus-visible:border-ring focus-visible:ring-ring/50 focus-visible:ring-[3px] aria-invalid:ring-destructive/20 dark:aria-invalid:ring-destructive/40 aria-invalid:border-destructive bg-primary text-primary-foreground hover:bg-primary/90 h-9 px-4 py-2 has-[\\u003esvg]:px-3 rounded-full shadow-md hover:shadow-lg transition-shadow\\\",\\\"children\\\":[\\\"                                     \\\",[\\\"$\\\",\\\"a\\\",null,{\\\"href\\\":\\\"https://discord.gg/dvbbPSHP\\\",\\\"target\\\":\\\"_blank\\\",\\\"rel\\\":\\\"noopener noreferrer\\\",\\\"children\\\":\\\"Join Termtrix\\\"}]]}],[\\\"$\\\",\\\"div\\\",null,{\\\"className\\\":\\\"md:hidden\\\",\\\"children\\\":[\\\"$\\\",\\\"$L12\\\",null,{\\\"children\\\":[[\\\"$\\\",\\\"$L13\\\",null,{\\\"asChild\\\":true,\\\"children\\\":[\\\"$\\\",\\\"button\\\",null,{\\\"data-slot\\\":\\\"button\\\",\\\"className\\\":\\\"inline-flex items-center justify-center gap-2 whitespace-nowrap text-sm font-medium transition-all disabled:pointer-events-none disabled:opacity-50 [\\u0026_svg]:pointer-events-none [\\u0026_svg:not([class*='size-'])]:size-4 shrink-0 [\\u0026_svg]:shrink-0 outline-none focus-visible:border-ring focus-visible:ring-ring/50 focus-visible:ring-[3px] aria-invalid:ring-destructive/20 dark:aria-invalid:ring-destructive/40 aria-invalid:border-destructive border bg-background shadow-xs hover:bg-accent hover:text-accent-foreground dark:bg-input/30 dark:border-input dark:hover:bg-input/50 size-9 rounded-full\\\",\\\"children\\\":[\\\"$\\\",\\\"svg\\\",null,{\\\"ref\\\":\\\"$undefined\\\",\\\"xmlns\\\":\\\"http://www.w3.org/2000/svg\\\",\\\"width\\\":24,\\\"height\\\":24,\\\"viewBox\\\":\\\"0 0 24 24\\\",\\\"fill\\\":\\\"none\\\",\\\"stroke\\\":\\\"currentColor\\\",\\\"strokeWidth\\\":2,\\\"strokeLinecap\\\":\\\"round\\\",\\\"strokeLinejoin\\\":\\\"round\\\",\\\"className\\\":\\\"lucide lucide-menu\\\",\\\"aria-hidden\\\":\\\"true\\\",\\\"children\\\":[[\\\"$\\\",\\\"path\\\",\\\"1tepv9\\\",{\\\"d\\\":\\\"M4 5h16\\\"}],[\\\"$\\\",\\\"path\\\",\\\"1lakjw\\\",{\\\"d\\\":\\\"M4 12h16\\\"}],[\\\"$\\\",\\\"path\\\",\\\"1djgab\\\",{\\\"d\\\":\\\"M4 19h16\\\"}],\\\"$undefined\\\"]}]}]}],[\\\"$\\\",\\\"$L14\\\",null,{\\\"className\\\":\\\"px-6 py-3\\\",\\\"children\\\":[[\\\"$\\\",\\\"div\\\",null,{\\\"className\\\":\\\"flex items-center gap-2 hover:opacity-90 transition-opacity\\\",\\\"children\\\":[[\\\"$\\\",\\\"div\\\",null,{\\\"className\\\":\\\"relative h-10 w-10 overflow-hidden rounded-lg border border-white/10 shadow-sm\\\",\\\"children\\\":[\\\"$\\\",\\\"$L3\\\",null,{\\\"src\\\":\\\"/termtrix-logo.jpg\\\",\\\"alt\\\":\\\"TermTrix Logo\\\",\\\"fill\\\":true,\\\"className\\\":\\\"object-cover\\\",\\\"priority\\\":true}]}],[\\\"$\\\",\\\"span\\\",null,{\\\"className\\\":\\\"font-bold dark:text-white text-xl tracking-tight bg-gradient-to-r from-white to-white/70 bg-clip-text text-transparent\\\",\\\"children\\\":\\\"TΞRMTRIX\\\"}]]}],[\\\"$\\\",\\\"$L4\\\",null,{\\\"data-slot\\\":\\\"navigation-menu\\\",\\\"data-viewport\\\":true,\\\"className\\\":\\\"group/navigation-menu relative flex max-w-max flex-1 items-center justify-center mt-6 [\\u0026\\u003ediv]:h-full\\\",\\\"orientation\\\":\\\"vertical\\\",\\\"children\\\":[[\\\"$\\\",\\\"$L5\\\",null,{\\\"data-slot\\\":\\\"navigation-menu-list\\\",\\\"className\\\":\\\"group flex flex-1 list-none items-center justify-center gap-3 space-x-0 data-[orientation=vertical]:flex-col data-[orientation=vertical]:items-start data-[orientation=vertical]:justify-start\\\",\\\"children\\\":[[\\\"$\\\",\\\"$L6\\\",null,{\\\"data-slot\\\":\\\"navigation-menu-item\\\",\\\"className\\\":\\\"relative\\\",\\\"children\\\":[\\\"$\\\",\\\"$L7\\\",null,{\\\"data-slot\\\":\\\"navigation-menu-link\\\",\\\"className\\\":\\\"data-[active=true]:focus:bg-accent data-[active=true]:hover:bg-accent data-[active=true]:bg-accent/50 data-[active=true]:text-accent-foreground hover:bg-accent hover:text-accent-foreground focus:bg-accent focus:text-accent-foreground focus-visible:ring-ring/50 [\\u0026_svg:not([class*='text-'])]:text-muted-foreground flex flex-col gap-1 rounded-sm p-2 text-sm transition-all outline-none focus-visible:ring-[3px] focus-visible:outline-1 [\\u0026_svg:not([class*='size-'])]:size-4\\\",\\\"asChild\\\":true,\\\"children\\\":[\\\"$\\\",\\\"$L8\\\",null,{\\\"href\\\":\\\"/\\\",\\\"children\\\":\\\"Home\\\"}]}]}],\\\"$L15\\\"]}],\\\"$L16\\\"]}]]}]]}]}]]}]\\n\"])</script><script>self.__next_f.push([1,\"b:[\\\"$\\\",\\\"$L17\\\",null,{\\\"parallelRouterKey\\\":\\\"children\\\",\\\"error\\\":\\\"$undefined\\\",\\\"errorStyles\\\":\\\"$undefined\\\",\\\"errorScripts\\\":\\\"$undefined\\\",\\\"template\\\":[\\\"$\\\",\\\"$L18\\\",null,{}],\\\"templateStyles\\\":\\\"$undefined\\\",\\\"templateScripts\\\":\\\"$undefined\\\",\\\"notFound\\\":[[[\\\"$\\\",\\\"title\\\",null,{\\\"children\\\":\\\"404: This page could not be found.\\\"}],[\\\"$\\\",\\\"div\\\",null,{\\\"style\\\":{\\\"fontFamily\\\":\\\"system-ui,\\\\\\\"Segoe UI\\\\\\\",Roboto,Helvetica,Arial,sans-serif,\\\\\\\"Apple Color Emoji\\\\\\\",\\\\\\\"Segoe UI Emoji\\\\\\\"\\\",\\\"height\\\":\\\"100vh\\\",\\\"textAlign\\\":\\\"center\\\",\\\"display\\\":\\\"flex\\\",\\\"flexDirection\\\":\\\"column\\\",\\\"alignItems\\\":\\\"center\\\",\\\"justifyContent\\\":\\\"center\\\"},\\\"children\\\":[\\\"$\\\",\\\"div\\\",null,{\\\"children\\\":[[\\\"$\\\",\\\"style\\\",null,{\\\"dangerouslySetInnerHTML\\\":{\\\"__html\\\":\\\"body{color:#000;background:#fff;margin:0}.next-error-h1{border-right:1px solid rgba(0,0,0,.3)}@media (prefers-color-scheme:dark){body{color:#fff;background:#000}.next-error-h1{border-right:1px solid rgba(255,255,255,.3)}}\\\"}}],[\\\"$\\\",\\\"h1\\\",null,{\\\"className\\\":\\\"next-error-h1\\\",\\\"style\\\":{\\\"display\\\":\\\"inline-block\\\",\\\"margin\\\":\\\"0 20px 0 0\\\",\\\"padding\\\":\\\"0 23px 0 0\\\",\\\"fontSize\\\":24,\\\"fontWeight\\\":500,\\\"verticalAlign\\\":\\\"top\\\",\\\"lineHeight\\\":\\\"49px\\\"},\\\"children\\\":404}],[\\\"$\\\",\\\"div\\\",null,{\\\"style\\\":{\\\"display\\\":\\\"inline-block\\\"},\\\"children\\\":[\\\"$\\\",\\\"h2\\\",null,{\\\"style\\\":{\\\"fontSize\\\":14,\\\"fontWeight\\\":400,\\\"lineHeight\\\":\\\"49px\\\",\\\"margin\\\":0},\\\"children\\\":\\\"This page could not be found.\\\"}]}]]}]}]],[]],\\\"forbidden\\\":\\\"$undefined\\\",\\\"unauthorized\\\":\\\"$undefined\\\"}]\\n\"])</script><script>self.__next_f.push([1,\"c:[\\\"$\\\",\\\"$1\\\",\\\"c\\\",{\\\"children\\\":[\\\"$L19\\\",[[\\\"$\\\",\\\"script\\\",\\\"script-0\\\",{\\\"src\\\":\\\"/_next/static/chunks/53c5ffaf39e0edf3.js\\\",\\\"async\\\":true,\\\"nonce\\\":\\\"$undefined\\\"}],[\\\"$\\\",\\\"script\\\",\\\"script-1\\\",{\\\"src\\\":\\\"/_next/static/chunks/ece0d313a4d1cc87.js\\\",\\\"async\\\":true,\\\"nonce\\\":\\\"$undefined\\\"}],[\\\"$\\\",\\\"script\\\",\\\"script-2\\\",{\\\"src\\\":\\\"/_next/static/chunks/483d179ffd78e2c9.js\\\",\\\"async\\\":true,\\\"nonce\\\":\\\"$undefined\\\"}]],[\\\"$\\\",\\\"$L1a\\\",null,{\\\"children\\\":[\\\"$L1b\\\",[\\\"$\\\",\\\"$L1c\\\",null,{\\\"promise\\\":\\\"$@1d\\\"}]]}]]}]\\nd:[\\\"$\\\",\\\"$1\\\",\\\"h\\\",{\\\"children\\\":[null,[[\\\"$\\\",\\\"$L1e\\\",null,{\\\"children\\\":\\\"$L1f\\\"}],[\\\"$\\\",\\\"meta\\\",null,{\\\"name\\\":\\\"next-size-adjust\\\",\\\"content\\\":\\\"\\\"}]],[\\\"$\\\",\\\"$L20\\\",null,{\\\"children\\\":[\\\"$\\\",\\\"div\\\",null,{\\\"hidden\\\":true,\\\"children\\\":[\\\"$\\\",\\\"$21\\\",null,{\\\"fallback\\\":null,\\\"children\\\":\\\"$L22\\\"}]}]}]]}]\\nf:[\\\"$\\\",\\\"link\\\",\\\"0\\\",{\\\"rel\\\":\\\"stylesheet\\\",\\\"href\\\":\\\"/_next/static/chunks/fff905c71cb6ab0c.css\\\",\\\"precedence\\\":\\\"next\\\",\\\"crossOrigin\\\":\\\"$undefined\\\",\\\"nonce\\\":\\\"$undefined\\\"}]\\n10:[\\\"$\\\",\\\"link\\\",\\\"1\\\",{\\\"rel\\\":\\\"stylesheet\\\",\\\"href\\\":\\\"/_next/static/chunks/d9f7fc5c3062ede5.css\\\",\\\"precedence\\\":\\\"next\\\",\\\"crossOrigin\\\":\\\"$undefined\\\",\\\"nonce\\\":\\\"$undefined\\\"}]\\n\"])</script><script>self.__next_f.push([1,\"15:[\\\"$\\\",\\\"$L6\\\",null,{\\\"data-slot\\\":\\\"navigation-menu-item\\\",\\\"className\\\":\\\"relative\\\",\\\"children\\\":[\\\"$\\\",\\\"$L7\\\",null,{\\\"data-slot\\\":\\\"navigation-menu-link\\\",\\\"className\\\":\\\"data-[active=true]:focus:bg-accent data-[active=true]:hover:bg-accent data-[active=true]:bg-accent/50 data-[active=true]:text-accent-foreground hover:bg-accent hover:text-accent-foreground focus:bg-accent focus:text-accent-foreground focus-visible:ring-ring/50 [\\u0026_svg:not([class*='text-'])]:text-muted-foreground flex flex-col gap-1 rounded-sm p-2 text-sm transition-all outline-none focus-visible:ring-[3px] focus-visible:outline-1 [\\u0026_svg:not([class*='size-'])]:size-4\\\",\\\"asChild\\\":true,\\\"children\\\":[\\\"$\\\",\\\"$L8\\\",null,{\\\"href\\\":\\\"/blog\\\",\\\"children\\\":\\\"Blog\\\"}]}]}]\\n\"])</script><script>self.__next_f.push([1,\"16:[\\\"$\\\",\\\"div\\\",null,{\\\"className\\\":\\\"absolute top-full left-0 isolate z-50 flex justify-center\\\",\\\"children\\\":[\\\"$\\\",\\\"$L9\\\",null,{\\\"data-slot\\\":\\\"navigation-menu-viewport\\\",\\\"className\\\":\\\"origin-top-center bg-popover text-popover-foreground data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-90 relative mt-1.5 h-[var(--radix-navigation-menu-viewport-height)] w-full overflow-hidden rounded-md border shadow md:w-[var(--radix-navigation-menu-viewport-width)]\\\"}]}]\\n1f:[[\\\"$\\\",\\\"meta\\\",\\\"0\\\",{\\\"charSet\\\":\\\"utf-8\\\"}],[\\\"$\\\",\\\"meta\\\",\\\"1\\\",{\\\"name\\\":\\\"viewport\\\",\\\"content\\\":\\\"width=device-width, initial-scale=1\\\"}]]\\n1b:null\\n\"])</script><script>self.__next_f.push([1,\"1d:{\\\"metadata\\\":[[\\\"$\\\",\\\"title\\\",\\\"0\\\",{\\\"children\\\":\\\"TERMTRIX — Learn, Collaborate \\u0026 Build Real Systems\\\"}],[\\\"$\\\",\\\"meta\\\",\\\"1\\\",{\\\"name\\\":\\\"description\\\",\\\"content\\\":\\\"TERMTRIX is a developer community focused on learning, collaboration, and real-world problem solving. We explore modern technologies, share knowledge openly, and build meaningful systems together.\\\"}],[\\\"$\\\",\\\"link\\\",\\\"2\\\",{\\\"rel\\\":\\\"author\\\",\\\"href\\\":\\\"https://termtrix.vercel.app\\\"}],[\\\"$\\\",\\\"meta\\\",\\\"3\\\",{\\\"name\\\":\\\"author\\\",\\\"content\\\":\\\"Bala Ms\\\"}],[\\\"$\\\",\\\"link\\\",\\\"4\\\",{\\\"rel\\\":\\\"manifest\\\",\\\"href\\\":\\\"/manifest.json\\\",\\\"crossOrigin\\\":\\\"$undefined\\\"}],[\\\"$\\\",\\\"meta\\\",\\\"5\\\",{\\\"name\\\":\\\"keywords\\\",\\\"content\\\":\\\"Developer Community,Learn Software Engineering,Build Real World Systems,Collaborative Coding Community,System Design Learning,Backend Engineering Community,Modern Web Development,TERMTRIX Community,Engineering Knowledge Sharing\\\"}],[\\\"$\\\",\\\"meta\\\",\\\"6\\\",{\\\"name\\\":\\\"creator\\\",\\\"content\\\":\\\"TERMTRIX\\\"}],[\\\"$\\\",\\\"meta\\\",\\\"7\\\",{\\\"name\\\":\\\"publisher\\\",\\\"content\\\":\\\"TERMTRIX\\\"}],[\\\"$\\\",\\\"meta\\\",\\\"8\\\",{\\\"name\\\":\\\"robots\\\",\\\"content\\\":\\\"index, follow\\\"}],[\\\"$\\\",\\\"meta\\\",\\\"9\\\",{\\\"name\\\":\\\"googlebot\\\",\\\"content\\\":\\\"index, follow, max-image-preview:large, max-snippet:-1\\\"}],[\\\"$\\\",\\\"meta\\\",\\\"10\\\",{\\\"name\\\":\\\"category\\\",\\\"content\\\":\\\"technology\\\"}],[\\\"$\\\",\\\"link\\\",\\\"11\\\",{\\\"rel\\\":\\\"canonical\\\",\\\"href\\\":\\\"https://termtrix.vercel.app\\\"}],[\\\"$\\\",\\\"meta\\\",\\\"12\\\",{\\\"property\\\":\\\"og:title\\\",\\\"content\\\":\\\"TERMTRIX — Learn, Collaborate \\u0026 Build Real Systems\\\"}],[\\\"$\\\",\\\"meta\\\",\\\"13\\\",{\\\"property\\\":\\\"og:description\\\",\\\"content\\\":\\\"A developer community for learning modern technologies, collaborating openly, and building real-world systems together.\\\"}],[\\\"$\\\",\\\"meta\\\",\\\"14\\\",{\\\"property\\\":\\\"og:url\\\",\\\"content\\\":\\\"https://termtrix.vercel.app\\\"}],[\\\"$\\\",\\\"meta\\\",\\\"15\\\",{\\\"property\\\":\\\"og:site_name\\\",\\\"content\\\":\\\"TERMTRIX\\\"}],[\\\"$\\\",\\\"meta\\\",\\\"16\\\",{\\\"property\\\":\\\"og:locale\\\",\\\"content\\\":\\\"en_US\\\"}],[\\\"$\\\",\\\"meta\\\",\\\"17\\\",{\\\"property\\\":\\\"og:image\\\",\\\"content\\\":\\\"https://termtrix.vercel.app/og.png\\\"}],[\\\"$\\\",\\\"meta\\\",\\\"18\\\",{\\\"property\\\":\\\"og:image:width\\\",\\\"content\\\":\\\"1200\\\"}],[\\\"$\\\",\\\"meta\\\",\\\"19\\\",{\\\"property\\\":\\\"og:image:height\\\",\\\"content\\\":\\\"630\\\"}],[\\\"$\\\",\\\"meta\\\",\\\"20\\\",{\\\"property\\\":\\\"og:image:alt\\\",\\\"content\\\":\\\"TERMTRIX Developer Community\\\"}],[\\\"$\\\",\\\"meta\\\",\\\"21\\\",{\\\"property\\\":\\\"og:type\\\",\\\"content\\\":\\\"website\\\"}],[\\\"$\\\",\\\"meta\\\",\\\"22\\\",{\\\"name\\\":\\\"twitter:card\\\",\\\"content\\\":\\\"summary_large_image\\\"}],[\\\"$\\\",\\\"meta\\\",\\\"23\\\",{\\\"name\\\":\\\"twitter:title\\\",\\\"content\\\":\\\"TERMTRIX — Learn, Collaborate \\u0026 Build Real Systems\\\"}],[\\\"$\\\",\\\"meta\\\",\\\"24\\\",{\\\"name\\\":\\\"twitter:description\\\",\\\"content\\\":\\\"A developer community focused on learning, collaboration, and building meaningful real-world systems.\\\"}],[\\\"$\\\",\\\"meta\\\",\\\"25\\\",{\\\"name\\\":\\\"twitter:image\\\",\\\"content\\\":\\\"https://termtrix.vercel.app/og.png\\\"}],[\\\"$\\\",\\\"link\\\",\\\"26\\\",{\\\"rel\\\":\\\"icon\\\",\\\"href\\\":\\\"/favicon.ico?favicon.c301ae68.ico\\\",\\\"sizes\\\":\\\"48x48\\\",\\\"type\\\":\\\"image/x-icon\\\"}],[\\\"$\\\",\\\"link\\\",\\\"27\\\",{\\\"rel\\\":\\\"icon\\\",\\\"href\\\":\\\"/icon0.svg?icon0.e77d1506.svg\\\",\\\"sizes\\\":\\\"any\\\",\\\"type\\\":\\\"image/svg+xml\\\"}],[\\\"$\\\",\\\"link\\\",\\\"28\\\",{\\\"rel\\\":\\\"icon\\\",\\\"href\\\":\\\"/icon1.png?icon1.0f46e201.png\\\",\\\"sizes\\\":\\\"96x96\\\",\\\"type\\\":\\\"image/png\\\"}],[\\\"$\\\",\\\"link\\\",\\\"29\\\",{\\\"rel\\\":\\\"apple-touch-icon\\\",\\\"href\\\":\\\"/apple-icon.png?apple-icon.c63bc649.png\\\",\\\"sizes\\\":\\\"180x180\\\",\\\"type\\\":\\\"image/png\\\"}],[\\\"$\\\",\\\"$L23\\\",\\\"30\\\",{}]],\\\"error\\\":null,\\\"digest\\\":\\\"$undefined\\\"}\\n\"])</script><script>self.__next_f.push([1,\"22:\\\"$1d:metadata\\\"\\n\"])</script><script>self.__next_f.push([1,\"24:I[87154,[\\\"/_next/static/chunks/25f0986ed87d220e.js\\\",\\\"/_next/static/chunks/e2b0ebdd7c9ec357.js\\\",\\\"/_next/static/chunks/3f682a3264f29773.js\\\",\\\"/_next/static/chunks/703ab740f268a9b9.js\\\",\\\"/_next/static/chunks/53c5ffaf39e0edf3.js\\\",\\\"/_next/static/chunks/ece0d313a4d1cc87.js\\\",\\\"/_next/static/chunks/483d179ffd78e2c9.js\\\"],\\\"Hero\\\"]\\n25:I[13034,[\\\"/_next/static/chunks/25f0986ed87d220e.js\\\",\\\"/_next/static/chunks/e2b0ebdd7c9ec357.js\\\",\\\"/_next/static/chunks/3f682a3264f29773.js\\\",\\\"/_next/static/chunks/703ab740f268a9b9.js\\\",\\\"/_next/static/chunks/53c5ffaf39e0edf3.js\\\",\\\"/_next/static/chunks/ece0d313a4d1cc87.js\\\",\\\"/_next/static/chunks/483d179ffd78e2c9.js\\\"],\\\"CommunityInsights\\\"]\\n26:T1644,\"])</script><script>self.__next_f.push([1,\"# Using an MCP Server with LangGraph: A Practical Guide to MCP Adapters\\n\\n## Introduction\\n\\nAs LLM agents grow more complex, prompt-only tool calling starts to break down.\\n\\nHallucinated tools, inconsistent outputs, and fragile prompt logic make production agents hard to trust. This becomes especially painful once agents move beyond single-step reasoning into stateful, multi-node workflows.\\n\\nThat’s where MCP (Model Context Protocol) comes in.\\n\\nIn this article, I’ll walk through how to use an MCP server with LangGraph using MCP adapters, why this approach produces cleaner and more deterministic agents, and what actually worked in a real implementation.\\n\\nThis is not a theoretical overview. It’s a practical guide based on hands-on integration.\\n\\n---\\n\\n## The Problem with Traditional Tool Calling\\n\\nBefore MCP, most LangGraph agents relied on a mix of:\\n\\n* Prompt instructions like “You MUST call this tool”\\n* Manual tool routing logic\\n* Post-processing messy outputs\\n* Hoping the model doesn’t invent tools\\n\\nIn practice, this leads to:\\n\\n* Inconsistent tool usage\\n* Agents ignoring required tools\\n* Difficult debugging\\n* Tight coupling between prompts and execution logic\\n\\nAs agent graphs become stateful and multi-step, this approach does not scale. Prompt-driven enforcement is fundamentally unreliable.\\n\\n---\\n\\n## What Is an MCP Server (In Practice)?\\n\\nAn MCP server acts as a formal contract layer between your agent and its tools.\\n\\nInstead of embedding tool definitions inside prompts:\\n\\n* Tools are declared and hosted by the MCP server\\n* The agent discovers tools dynamically\\n* Inputs and outputs are schema-validated\\n* The model cannot guess tool behavior\\n\\nA useful mental model is:\\n\\nMCP is like OpenAPI for AI agents, designed specifically for multi-tool, multi-step reasoning.\\n\\nThis shifts tool usage from “best effort” to “protocol-enforced”.\\n\\n---\\n\\n## Why MCP Adapters Matter in LangGraph\\n\\nLangGraph is excellent at:\\n\\n* Stateful agent flows\\n* Deterministic graph execution\\n* Multi-node reasoning\\n\\nHowever, it intentionally does not dictate how tools should be exposed or enforced.\\n\\nMCP adapters fill this gap.\\n\\nWith MCP adapters:\\n\\n* LangGraph does not care how tools are implemented\\n* The agent only interacts with validated MCP tools\\n* Tool calls become protocol-driven, not prompt-driven\\n\\nThe result is cleaner graphs and far more predictable behavior.\\n\\n---\\n\\n## High-Level Architecture\\n\\nThis mental model worked best in practice:\\n\\n```\\nLLM Agent (LangGraph)\\n        ↓\\n   MCP Adapter Layer\\n        ↓\\n     MCP Server\\n        ↓\\n  External Tools / Services\\n```\\n\\nClear separation of concerns:\\n\\n* LangGraph handles reasoning and state\\n* MCP defines tool contracts\\n* Tools handle real execution\\n\\nEach layer has a single responsibility, which dramatically reduces complexity.\\n\\n---\\n\\n## Step 1: Running an MCP Server\\n\\nYour MCP server exposes tools using strict schemas.\\n\\nExample tools:\\n\\n* whois_info\\n* geoip_info\\n* virustotal_info\\n\\nEach tool:\\n\\n* Has defined input arguments\\n* Returns structured output\\n* Is discoverable at runtime\\n\\nThis immediately eliminates:\\n\\n* Tool hallucination\\n* Argument mismatch\\n* Output inconsistency\\n\\nThe MCP server becomes the authoritative source of truth for all available capabilities.\\n\\n---\\n\\n## Step 2: Connecting MCP to LangGraph via Adapters\\n\\nUsing MCP adapters, LangGraph loads tools directly from the MCP server.\\n\\nConceptually, this looks like:\\n\\n```\\ntools = await client.get_tools(server_name=\\\"sentinel\\\")\\n\\nagent = create_agent(\\n    model=model,\\n    tools=tools,\\n    system_prompt=SYSTEM_PROMPT,\\n)\\n```\\n\\nImportant details:\\n\\n* LangGraph does not hardcode tools\\n* The MCP server defines what the agent can do\\n* Tool schemas are enforced automatically\\n\\nThis removes an entire class of runtime failures caused by mismatched prompts and tool definitions.\\n\\n---\\n\\n## Step 3: Writing a Tool-Enforced System Prompt\\n\\nWith MCP in place, the system prompt becomes protocol-aware instead of defensive.\\n\\nExample:\\n\\n```\\nYou are a SOC analyst assistant.\\n\\nYou MUST:\\n- Call whois_info\\n- Call geoip_info\\n- Call virustotal_info\\n\\nUse ONLY tool outputs.\\nDo NOT invent facts.\\n```\\n\\nBecause the tools are MCP-backed:\\n\\n* The agent cannot bypass them\\n* Outputs are always structured\\n* Downstream parsing becomes trivial\\n\\nThe prompt is no longer fighting the model. It is reinforcing a protocol the model already understands.\\n\\n---\\n\\n## What Improved Immediately\\n\\nAfter switching to MCP adapters, the improvements were obvious.\\n\\n### Deterministic Tool Usage\\n\\nThe agent always calls required tools. No retries, no prompt hacks, no brittle guardrails.\\n\\n### Clean Outputs\\n\\nNo mixed natural language and tool artifacts. Everything is structured and predictable.\\n\\n### Easier Debugging\\n\\nFailures occur at the protocol level, not as vague “LLM behavior” issues.\\n\\n### Scalable Agent Design\\n\\nAdding new tools does not require rewriting prompts or graph logic. The MCP server handles discovery and validation.\\n\\n---\\n\\n## When You Should Use MCP with LangGraph\\n\\nThis setup is ideal if you are building:\\n\\n* SOC or SecOps agents\\n* RFQ or procurement agents\\n* Interview or assessment agents\\n* Multi-step enterprise workflows\\n* Any agent where incorrect tool usage has real consequences\\n\\nIf your agent must be correct, explainable, and auditable, MCP is not optional.\\n\\n---\\n\\n## Final Thoughts\\n\\nLangGraph gives you control over agent flow.\\n\\nMCP gives you control over agent capabilities.\\n\\nTogether, they solve the two hardest problems in agent engineering:\\n\\n* What should the agent do next?\\n* What is the agent allowed to do?\\n\\nIf you are serious about production-grade AI agents, MCP servers combined with LangGraph adapters are one of the cleanest and most robust patterns available today.\\n\"])</script><script>self.__next_f.push([1,\"27:Tf90,\"])</script><script>self.__next_f.push([1,\"# Turbopack in Next.js: Does turbopackFileSystemCacheForDev Make Your App Lightning Fast?\\n\\nIf you’re working with Next.js 14 or newer, you’ve likely seen growing discussion around Turbopack — the Rust-based bundler designed to eventually replace Webpack.\\n\\nOne experimental flag in particular has drawn attention:\\n\\nturbopackFileSystemCacheForDev\\n\\nThis post breaks down what this flag actually does, the performance impact you can realistically expect, and when it makes sense to enable it in a real-world codebase.\\n\\n---\\n\\n## Enabling turbopackFileSystemCacheForDev\\n\\nThe flag is enabled in next.config.ts:\\n\\n```\\nconst nextConfig = {\\n    experimental: {\\n        turbopackFileSystemCacheForDev: true,\\n    },\\n};\\n\\nexport default nextConfig;\\n```\\n\\nThis setting only applies to development mode. It has no effect on production builds.\\n\\n---\\n\\n## What This Setting Actually Does\\n\\nturbopackFileSystemCacheForDev enables persistent file-system caching during development.\\n\\nIn practical terms:\\n\\n* The first build behaves like a normal cold start\\n* Build outputs are written to disk\\n* On subsequent restarts, Turbopack reuses cached results\\n* Only files that actually change are recompiled\\n* Dev server restarts and HMR updates become significantly faster\\n\\nYou can think of this as moving from an in-memory-only dev workflow to one where the bundler remembers previous work across restarts.\\n\\n---\\n\\n## Expected Performance Improvements\\n\\n### Before Enabling the Cache\\n\\nIn medium-to-large projects, especially with TypeScript:\\n\\n* Dev server boot time increases as the codebase grows\\n* Hot reloads introduce noticeable delays\\n* Route refreshes can trigger multi-second rebuilds\\n* Monorepos amplify all of the above\\n\\n### After Enabling the Cache\\n\\nOnce the initial build is complete:\\n\\n* Dev server restarts are noticeably faster\\n* Hot reloads are often near-instant\\n* TypeScript-heavy components see a major improvement\\n* Large monorepos benefit the most\\n\\nImportant detail: cold start performance does not change. The gains show up after the first successful build.\\n\\n---\\n\\n## Does This Make Your App “Lightning Fast”?\\n\\nShort answer:\\n\\n* Development: Yes, especially after the first run\\n* Production: No impact at all\\n\\nThis flag strictly improves the developer experience. It does not change production bundle output, size, or runtime performance.\\n\\n---\\n\\n## Experimental Caveats\\n\\nDespite being usable day-to-day, this is still an experimental feature. A few practical concerns to keep in mind:\\n\\n* Cache invalidation can occasionally break\\n* Deleting the .next directory may be required if things get out of sync\\n* Stability varies with dependency graphs and project size\\n* Some tooling ecosystems (Storybook, Jest, custom dev tooling) may not fully align with Turbopack yet\\n* Source maps may be less predictable than Webpack in certain setups\\n\\nFor most teams, these issues are manageable, but they are real.\\n\\n---\\n\\n## When You Should Enable It\\n\\nThis flag is a good fit if you:\\n\\n* Work on a large Next.js codebase\\n* Regularly restart the dev server\\n* Rely heavily on TypeScript\\n* Care about fast HMR feedback loops\\n* Use a monorepo setup (especially with Turborepo)\\n\\nIn these cases, the productivity gains are noticeable.\\n\\n---\\n\\n## When You Should Avoid It\\n\\nYou may want to hold off if:\\n\\n* Your project depends on custom Webpack loaders\\n* You use tooling that does not support Turbopack yet\\n* You rely on highly stable and predictable source maps for debugging\\n* Your setup already has tight coupling to Webpack internals\\n\\n---\\n\\n## Final Takeaway\\n\\nturbopackFileSystemCacheForDev does not magically optimize your application, but it significantly improves development iteration speed once the cache is warm.\\n\\nFor large, TypeScript-heavy projects, especially in monorepos, enabling it can remove a lot of day-to-day friction. Just be prepared to occasionally clear caches and accept some experimental rough edges.\\n\\nIf your priority is faster feedback during development, this flag is absolutely worth trying.\\n\"])</script><script>self.__next_f.push([1,\"28:Tfd7,\"])</script><script>self.__next_f.push([1,\"# 🔐 How to Create a Perfect AWS Security Group (Without Breaking Your App)\\n\\n**TΞRMTRIX**  \\n\\n\\n---\\n\\nWhen people say **“my EC2 is secure”**, most of the time it isn’t.\\n\\nOpen ports, default security groups, public databases — these are some of the most common **(and dangerous)** AWS mistakes.\\n\\nIn this article, I’ll walk you through how to design a **perfect AWS Security Group (SG)** using **least-privilege principles**, **without downtime**, and **without guesswork**.\\n\\nThis approach works for:\\n\\n- EC2\\n- RDS (PostgreSQL / MySQL)\\n- ElastiCache (Redis)\\n- Docker-based backends\\n- Production \\u0026 staging environments\\n\\n---\\n\\n## 🔍 What Is a Security Group (Really)?\\n\\nAn **AWS Security Group** is a **stateful virtual firewall** that controls:\\n\\n- **Inbound traffic** — who can connect to your resource\\n- **Outbound traffic** — where your resource can connect\\n\\n### Key rule\\n\\n\\u003e If a port is not explicitly allowed, it is blocked.\\n\\nSecurity Groups work at the **network interface level**, not inside your OS.\\n\\n---\\n\\n## ❌ The Biggest Mistake People Make\\n\\nUsing **one security group for everything** — usually the **default SG** — and opening ports like:\\n\\n0.0.0.0/0 → 22\\n0.0.0.0/0 → 5432\\n0.0.0.0/0 → 6379\\n\\n\\nThis makes your infrastructure:\\n\\n- Easy to hack\\n- Hard to audit\\n- Impossible to scale securely\\n\\n---\\n\\n## ✅ The “Perfect SG” Design (Production-Ready)\\n\\nInstead of one SG, we use **multiple purpose-based security groups**.\\n\\n### Target Architecture\\n\\nInternet\\n↓\\nBackend EC2 (backend-sg)\\n↓\\nRDS PostgreSQL (rds-sg)\\n↓\\nElastiCache Redis (redis-sg)\\n\\n\\nEach layer **trusts only the layer above it**.\\n\\n---\\n\\n## 🧱 Step 1: Create a Backend Security Group (`backend-sg`)\\n\\nAttach this SG to your **EC2 backend**  \\n(FastAPI, Node.js, Django, etc.)\\n\\n### Inbound Rules\\n\\nHTTP (80) → 0.0.0.0/0\\nHTTPS (443) → 0.0.0.0/0\\nSSH (22) → Your IP only (x.x.x.x/32)\\n\\n\\n### Why this is correct\\n\\n- Web traffic is public\\n- SSH is restricted\\n- No database or cache ports are exposed\\n\\n### ❌ Do NOT add\\n\\n- PostgreSQL (5432)\\n- Redis (6379)\\n- Custom internal ports\\n\\n---\\n\\n## 🗄️ Step 2: Create a Database Security Group (`rds-sg`)\\n\\nAttach this SG **only** to your RDS instance.\\n\\n### Inbound Rules\\n\\nPostgreSQL (5432) → Source: backend-sg\\n\\n\\n✔ Yes — the source is **another security group**, not an IP.\\n\\n### Why this is powerful\\n\\n- Only EC2s using `backend-sg` can connect\\n- No public access\\n- No IP allowlists to maintain\\n\\n### ❌ Never use\\n\\n0.0.0.0/0\\n\\n\\n---\\n\\n## 🧠 Step 3: Create a Redis Security Group (`redis-sg`)\\n\\nAttach this SG **only** to ElastiCache Redis.\\n\\n### Inbound Rules\\n\\nCustom TCP (6379) → Source: backend-sg\\n\\n\\n### Why this matters\\n\\n- Redis is one of the most attacked services\\n- Public Redis = instant compromise\\n- SG-to-SG access is the safest option\\n\\n---\\n\\n## 🚫 Step 4: Stop Using the Default Security Group\\n\\nYour **default SG should have NO inbound rules**.\\n\\n### Best practice\\n\\n- Do not attach it to EC2\\n- Do not attach it to RDS\\n- Do not attach it to Redis\\n\\nThink of it as a **parking lot**, not a firewall.\\n\\n---\\n\\n## 🔄 Step 5: Attach the Right SGs (Order Matters)\\n\\nAlways do this **without downtime**:\\n\\n1. Attach the new SG first\\n2. Verify the app works\\n3. Then remove the old SG\\n\\n### Example (EC2)\\n\\n**Before**\\n\\ndefault\\n\\n**After**\\n\\nbackend-sg\\n\\n\\n⚠️ Never delete rules before attaching the correct SG.\\n\\n---\\n\\n## 🚨 Common Red Flags (Fix Immediately)\\n\\n- `5432 → 0.0.0.0/0`\\n- `6379 → 0.0.0.0/0`\\n- SSH open to the world\\n- Databases using the default SG\\n- One SG attached to everything\\n\\n---\\n\\n## ✅ Final Checklist for a “Perfect” Security Group Setup\\n\\n- ✅ Separate SG per service\\n- ✅ SG-to-SG rules instead of IPs\\n- ✅ No public DB or Redis ports\\n- ✅ Default SG unused\\n- ✅ SSH restricted or replaced with SSM\\n\\n---\\n\\n## 🏁 Final Thought\\n\\nA perfect Security Group is **not about opening fewer ports** —  \\nit’s about opening ports **only to the right source**.\\n\\nOnce you adopt this pattern, your AWS infrastructure becomes:\\n\\n- Safer\\n- Easier to reason about\\n- Ready for production scale\\n\\n---\\n \\n\\n\\n\\n\\n\"])</script><script>self.__next_f.push([1,\"19:[\\\"$\\\",\\\"main\\\",null,{\\\"className\\\":\\\"bg-background text-foreground overflow-x-hidden\\\",\\\"children\\\":[[\\\"$\\\",\\\"$L24\\\",null,{}],[\\\"$\\\",\\\"$L25\\\",null,{\\\"posts\\\":[{\\\"id\\\":\\\"using-an-mcp-server-with-langgraph-a-practical-guide-to-mcp-adapters\\\",\\\"description\\\":\\\"Learn how to integrate an MCP server with LangGraph using MCP adapters to build deterministic, schema-validated AI agents. This practical guide explains why prompt-only tool calling fails and how MCP enables reliable, production-grade agent workflows.\\\",\\\"subtitle\\\":\\\"Building deterministic, production-ready LangGraph agents using MCP servers and protocol-driven tool enforcement\\\",\\\"tags\\\":[\\\"LangGraph\\\",\\\"MCP Server\\\",\\\"Model Context Protocol\\\",\\\"AI Agents\\\",\\\"LLM Tooling\\\",\\\"Agent Architecture\\\",\\\"FastAPI\\\"],\\\"title\\\":\\\"Using an MCP Server with LangGraph: A Practical Guide to MCP Adapters\\\",\\\"slug\\\":\\\"using-an-mcp-server-with-langgraph-a-practical-guide-to-mcp-adapters\\\",\\\"updatedAt\\\":\\\"2025-12-22T16:12:03.550Z\\\",\\\"category\\\":\\\"AI Agent\\\",\\\"author\\\":{\\\"role\\\":\\\"Writer\\\",\\\"image\\\":\\\"/termtrix-logo.jpg\\\",\\\"name\\\":\\\"TermTrix\\\"},\\\"readTime\\\":\\\"5min read\\\",\\\"content\\\":\\\"$26\\\",\\\"createdAt\\\":\\\"2025-12-22T16:12:03.550Z\\\",\\\"publishedAt\\\":\\\"Dec 22, 2025\\\",\\\"image\\\":\\\"https://raw.githubusercontent.com/msbala007/images/refs/heads/main/mcp_server.jpeg\\\",\\\"likes\\\":2},{\\\"id\\\":\\\"turbopack-in-nextjs-does-turbopackfilesystemcachefordev-make-your-app-lightning-fast\\\",\\\"slug\\\":\\\"turbopack-in-nextjs-does-turbopackfilesystemcachefordev-make-your-app-lightning-fast\\\",\\\"readTime\\\":\\\"2min read\\\",\\\"createdAt\\\":\\\"2025-12-20T15:50:29.012Z\\\",\\\"publishedAt\\\":\\\"Dec 20, 2025\\\",\\\"subtitle\\\":\\\"🚀 Turbopack in Next.js: Does turbopackFileSystemCacheForDev Make Your App Lightning Fast?\\\",\\\"tags\\\":[\\\"Next js\\\",\\\"TypeScript\\\",\\\"JavaScript\\\",\\\"React\\\"],\\\"title\\\":\\\"🚀 Turbopack in Next.js: Does turbopackFileSystemCacheForDev Make Your App Lightning Fast?\\\",\\\"category\\\":\\\"Next js\\\",\\\"updatedAt\\\":\\\"2025-12-20T15:50:29.012Z\\\",\\\"description\\\":\\\"\\\",\\\"author\\\":{\\\"role\\\":\\\"Writer\\\",\\\"name\\\":\\\"TermTrix\\\",\\\"image\\\":\\\"/termtrix-logo.jpg\\\"},\\\"content\\\":\\\"$27\\\",\\\"image\\\":\\\"https://raw.githubusercontent.com/msbala007/images/refs/heads/main/cache.jpeg\\\"},{\\\"id\\\":\\\"perfect-aws-security-group-best-practices\\\",\\\"title\\\":\\\"How to Create a Perfect AWS Security Group (Production-Ready \\u0026 Secure)\\\",\\\"slug\\\":\\\"perfect-aws-security-group-best-practices\\\",\\\"subtitle\\\":\\\"Design secure, production-ready AWS Security Groups using least-privilege—without downtime or guesswork\\\",\\\"category\\\":\\\"Cloud Security\\\",\\\"description\\\":\\\"Learn how to design a production-ready AWS Security Group using least-privilege principles for EC2, RDS, and Redis—without breaking your app.\\\\n\\\\nAWS Security Group best practices\\\\n\\\\nSecure EC2 Security Group\\\\n\\\\nRDS Security Group configuration\\\\n\\\\nRedis Security Group AWS\\\\n\\\\nAWS least privilege networking\\\\n\\\\nCloud security for backend apps\\\",\\\"tags\\\":[\\\"AWS\\\",\\\"AWS EC2\\\",\\\"Cloud Security\\\"],\\\"readTime\\\":\\\"4min read\\\",\\\"publishedAt\\\":\\\"Dec 20, 2025\\\",\\\"createdAt\\\":\\\"2025-12-20T11:03:42.951Z\\\",\\\"updatedAt\\\":\\\"2025-12-20T11:03:42.951Z\\\",\\\"image\\\":\\\"https://raw.githubusercontent.com/msbala007/images/refs/heads/main/aws-security.jpeg\\\",\\\"author\\\":{\\\"name\\\":\\\"TermTrix\\\",\\\"role\\\":\\\"Writer\\\",\\\"image\\\":\\\"/termtrix-logo.jpg\\\"},\\\"content\\\":\\\"$28\\\"}]}],\\\"$L29\\\"]}]\\n\"])</script><script>self.__next_f.push([1,\"2a:I[45766,[\\\"/_next/static/chunks/25f0986ed87d220e.js\\\",\\\"/_next/static/chunks/e2b0ebdd7c9ec357.js\\\",\\\"/_next/static/chunks/3f682a3264f29773.js\\\",\\\"/_next/static/chunks/703ab740f268a9b9.js\\\",\\\"/_next/static/chunks/53c5ffaf39e0edf3.js\\\",\\\"/_next/static/chunks/ece0d313a4d1cc87.js\\\",\\\"/_next/static/chunks/483d179ffd78e2c9.js\\\"],\\\"SiteFooter\\\"]\\n29:[\\\"$\\\",\\\"$L2a\\\",null,{}]\\n\"])</script></body></html>"


# @app.post("/extract_on_page_elements")
# def extract_on_page_elements(data: str) -> dict:
#     """
#     Parses HTML and extracts on-page SEO-relevant elements.
#     """

#     html = data
#     soup = BeautifulSoup(data, "html.parser")

#     seo = {
#         "title": soup.title.text if soup.title else None,
#         "description": soup.find("meta", {"name": "description"})["content"],
#         "og_image": soup.find("meta", {"property": "og:image"})["content"],
#         "canonical": soup.find("link", {"rel": "canonical"})["href"],
#     }
    
#     return seo



logger.info("Logging with structlog")
logger.debug("Database connection established")

