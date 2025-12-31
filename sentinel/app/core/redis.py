from redis.asyncio import Redis
from app.logger import logger


redis_client = Redis(
    host="localhost",
    port=6379,
    db=0,
    decode_responses=True,
)


logger.info("Redis connection established")

