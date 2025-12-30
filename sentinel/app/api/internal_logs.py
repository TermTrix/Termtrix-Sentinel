from fastapi import APIRouter,Request



logs = APIRouter()

@logs.post("/internal/logs")
async def ingest_logs(request: Request):
    events = await request.json()
    # DO NOT process here
    # Just enqueue or dump for now
    print("Received logs:", len(events))
    return {"status": "ok"}