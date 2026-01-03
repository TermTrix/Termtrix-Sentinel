from redis.asyncio import Redis
# from app.logger import logger


redis_client = Redis(
    host="127.0.0.1",
    port=6379,
    db=0,
    decode_responses=True,
)


# logger.info("Redis connection established")


# create consumer group

STREAM = "sentinel:logs"
GROUP = "sentinel-consumers"

async def create_consumer_group():
    try:
        await redis_client.xgroup_create(STREAM, GROUP, mkstream=True)
    except Exception as e:
        print("Consumer group already exists")