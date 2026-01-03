
from sentinel.app.core.redis import redis_client
import asyncio
import redis.asyncio as redis
import signal
import json

from worker.normailzer import SentinelNormlizer
from worker.storage import connection
from worker.serializer import EventSerializer



STREAM = "sentinel:logs"
GROUP = "sentinel-consumers"
CONSUMER = "worker-1"



running = True
normailzer = SentinelNormlizer()

def shutdown():
    global running
    running = False

signal.signal(signal.SIGTERM, lambda *_: shutdown())
signal.signal(signal.SIGINT, lambda *_: shutdown())


async def process_log(log: dict):
    """
    DO NOT BLOCK HERE
    Offload heavy work to background tasks if needed
    """
    # print("Processing:", log)

    raw_event = json.loads(log["payload"]) 
    # store / analyze / enrich
    # sentinel = raw_event.get("sentinel")

    # print("sentinel ==>",raw_event)

    normalized_event = await normailzer.normalize(raw_event)
    # print("normalized_event ==>",normalized_event)

    if normalized_event is None:
        return

    payload = EventSerializer.to_redis(normalized_event)

    await redis_client.xadd("sentinel:logs:normalized", {"payload": payload})

  

    


async def consume():
    while running:
        try:
            messages = await redis_client.xreadgroup(
                groupname=GROUP,
                consumername=CONSUMER,
                streams={STREAM: ">"},
                count=100,          # batch size
                block=5000          # wait 5s
            )

            if not messages:
                continue

            for _, entries in messages:
                for msg_id, data in entries:
                    try:
                        await process_log(data)
                        await redis_client.xack(STREAM, GROUP, msg_id)
                    except Exception as e:
                        # DO NOT ACK on failure
                        print("Error processing", msg_id, e)

        except Exception as e:
            print("Consumer error:", e)
            await asyncio.sleep(1)



if __name__ == "__main__":  
    print("CONSUMER STARTED")
    asyncio.run(consume())












# 6️⃣ Handle stuck messages (advanced but important)

# If a worker crashes, messages get stuck in PEL.

# Use XPENDING + XCLAIM (periodically):

# pending = await redis_client.xpending_range(
#     STREAM, GROUP, min="-", max="+", count=10
# )

# for msg in pending:
#     msg_id = msg["message_id"]
#     await redis_client.xclaim(
#         STREAM,
#         GROUP,
#         CONSUMER,
#         min_idle_time=60000,  # 60s
#         message_ids=[msg_id]
#     )