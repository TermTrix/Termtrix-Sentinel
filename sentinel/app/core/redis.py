
# =====================================
# NEW CODE IMPLEMENTATION (05-01-2026)
# =====================================



import redis.asyncio as redis
from app.config import settings

# Redis connection
redis_client = redis.Redis(
    host=settings.REDIS_HOST if hasattr(settings, 'REDIS_HOST') else 'redis',
    port=settings.REDIS_PORT if hasattr(settings, 'REDIS_PORT') else 6379,
    db=settings.REDIS_DB if hasattr(settings, 'REDIS_DB') else 0,
    decode_responses=True
)

# Stream and group names
STREAM = "sentinel:logs"
GROUP = "sentinel-consumers"

async def create_consumer_group():
    """
    Create Redis Stream consumer group
    Idempotent - safe to call multiple times
    """
    try:
        await redis_client.xgroup_create(
            name=STREAM,
            groupname=GROUP,
            id="0",
            mkstream=True
        )
        print(f"Created consumer group: {GROUP}")
    except redis.ResponseError as e:
        if "BUSYGROUP" in str(e):
            # Group already exists - this is fine
            print(f"Consumer group already exists: {GROUP}")
        else:
            raise




# =====================================
# OLD CODE IMPLEMENTATION
# Problems:
# - Redis connection hardcoded to 127.0.0.1
# - Doesn't work in Docker (needs 'redis' hostname)
# =====================================

# from redis.asyncio import Redis

# # from app.logger import logger


# redis_client = Redis(
#     host="127.0.0.1",
#     port=6379,
#     db=0,
#     decode_responses=True,
# )


# # logger.info("Redis connection established")


# # create consumer group

# STREAM = "sentinel:logs"
# GROUP = "sentinel-consumers"

# async def create_consumer_group():
#     try:
#         await redis_client.xgroup_create(STREAM, GROUP, mkstream=True)
#     except Exception as e:
#         print("Consumer group already exists")