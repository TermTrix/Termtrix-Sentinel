from fastapi import APIRouter,Request
from app.core.redis import redis_client


logs = APIRouter()

@logs.post("/internal/logs")
async def ingest_logs(request: Request):
    events = await request.json()
    # DO NOT process here
    # Just enqueue or dump for now
    print("Received logs:", len(events))

    for event in events:
        print(event)
        # await redis_client.xadd("logs", event)

    return {"status": "ok"}