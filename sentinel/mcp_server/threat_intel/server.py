from mcp_server.threat_intel.mcp_instance import mcp
from mcp_server.threat_intel.tools.whois import register_intel_tools
from fastmcp.server.event_store import EventStore
from key_value.aio.stores.redis import RedisStore

redis_store = RedisStore(url="redis://localhost:6379")
event_store = EventStore(
    storage=redis_store,
    max_events_per_stream=100,  # Keep last 100 events per stream
    ttl=3600,  # Events expire after 1 hour
)

import asyncio

def create_app():

    tool = register_intel_tools(mcp)

    # async def run():
    #     print(await mcp.get_tools())
        
    # asyncio.create_task(run())

    return mcp.http_app(event_store=event_store,path="/mcp")


mcp_app = create_app() 
  