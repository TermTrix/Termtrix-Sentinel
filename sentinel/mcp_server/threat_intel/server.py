
from sentinel.mcp_server.threat_intel.tools.whois import register_intel_tools
from sentinel.mcp_server.threat_intel.tools.action_tools import register_action_tools
from fastmcp.server.event_store import EventStore
from key_value.aio.stores.redis import RedisStore

redis_store = RedisStore(url="redis://localhost:6379")
event_store = EventStore(
    storage=redis_store,
    max_events_per_stream=100,  # Keep last 100 events per stream
    ttl=3600,  # Events expire after 1 hour
)

import asyncio


from fastmcp import FastMCP

# def create_app():

#     tool = register_intel_tools(mcp)


#     # async def run():
#     #     print(await mcp.get_tools())
        
#     # asyncio.create_task(run())

#     return mcp.http_app(event_store=event_store,path="/mcp")


# mcp_app = create_app() 


# def create_action_app():
#     tool =  register_action_tools(mcp_app)
#     return action_mcp.http_app(event_store=event_store,path="/mcp")
  


def create_phase1_mcp():
    mcp = FastMCP(name="sentinel-phase-1")
    register_intel_tools(mcp)   # whois, geoip, virustotal
    return mcp

def create_phase3_mcp():
    mcp = FastMCP(name="sentinel-phase-3")
    register_action_tools(mcp)  # find_action_needed only
    return mcp



mcp_phase1 = create_phase1_mcp()
mcp_phase3 = create_phase3_mcp()

phase1_app = mcp_phase1.http_app(
    event_store=event_store,
    path="/mcp",
)
    
    
phase3_app = mcp_phase3.http_app(
    event_store=event_store,
    path="/mcp",
)