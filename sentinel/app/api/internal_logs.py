from fastapi import APIRouter,Request
from app.core.redis import redis_client
from app.logger import logger

import json

logs = APIRouter()

@logs.post("/internal/logs")
async def ingest_logs(request: Request):
    try:
        events = await request.json()
  
        print("Received logs:", len(events))

        for event in events:
            # print(event)
            # event_ = json.dumps(event)
            await redis_client.xadd("sentinel:logs", {"payload": json.dumps(event)})
            # fp = make_fingerprint(event)
            # print(fp)


        return {"status": "ok"}
    except Exception as e:
        logger.error(f"Error processing logs: {e}")
        return {"status": "error"}


import hashlib

def make_fingerprint(event):
    log = event.get("event", None)
    if log is None:
        return None
    sentinel = log.get("sentinel", None)
    print(sentinel)
    if sentinel == "application":
        return None
    parts = [
        log.get("remote_addr", ""),
        log.get("http_user_agent", ""),
        # log.get("http_accept_language", ""),
        # log.get("ssl_protocol", ""),
        # log.get("ssl_cipher", "")
    ]

    fp_source = "|".join(parts)
    return hashlib.sha256(fp_source.encode()).hexdigest()
