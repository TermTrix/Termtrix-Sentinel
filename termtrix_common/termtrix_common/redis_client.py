from redis.asyncio import Redis
# from app.logger import logger


redis_client = Redis(
    host="redis-server",
    port=6379,
    db=0,
    decode_responses=True,
)

# create consumer group

STREAM = "sentinel:logs"
GROUP = "sentinel-consumers"

# FOR DETECTION ENGINE

NORMALIZED_EVENT = "normalized:events"
EVENT_GROUP = "detection-engine"
EVENT_CONSUMER = "dectector-1"

async def create_consumer_group():
    try:
        await redis_client.xgroup_create(STREAM, GROUP, mkstream=True)
        await redis_client.xgroup_create(NORMALIZED_EVENT,EVENT_GROUP,mkstream=True)
    except Exception as e:
        print("Consumer group already exists")