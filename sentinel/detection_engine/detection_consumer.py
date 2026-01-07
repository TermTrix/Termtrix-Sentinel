
import asyncio
import json

from sentinel.app.core.redis import redis_client
from sentinel.detection_engine.termtrix_detection_engine import TermtrixDetectionEngine


class TermtrixConumerEngine():
    def __init__(self):
        self.NORMALIZED_EVENT = "normalized:events"
        self.GROUP = "detection-engine"
        self.CONSUMER = "dectector-1"
        self.BATCH_SIZE = 100
        self.BLOCK_MS = 3000
        self.engine = TermtrixDetectionEngine()

    async def consume_and_detect(self):
        while True:
            events = await redis_client.xreadgroup(
                groupname=self.GROUP,
                consumername=self.CONSUMER,
                streams={self.NORMALIZED_EVENT:">"},
                count=self.BATCH_SIZE,
                block=self.BLOCK_MS

            )

            if not events:
                continue

            for _,entires in events:
                for msg_id,fields in entires:
                    print(msg_id,"===>")
                    event = json.loads(fields["payload"])
                    # print("event ==>",event)
                    await self.engine.log_distributor(event=event)







if __name__ == __name__:
    print("ENGINE STARTED")
    asyncio.run(TermtrixConumerEngine().consume_and_detect())
