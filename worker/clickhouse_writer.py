import asyncio
import json
from uuid import UUID
from dateutil.parser import isoparse

import redis.asyncio as redis

from worker.storage import connection
from termtrix_common.termtrix_common.redis_client import redis_client


# ---------------- CONFIG ----------------

REDIS_STREAM = "sentinel:logs:normalized"
REDIS_GROUP = "clickhouse-writers"
CONSUMER_NAME = "writer-1"

BATCH_SIZE = 500
BLOCK_MS = 5000

CLICKHOUSE_DB = "default"
CLICKHOUSE_TABLE = "sentinel_logs"


def to_row(event: dict) -> tuple:
    """
    Convert normalized event dict → ClickHouse row tuple
    Order MUST match table schema
    """


    row = (
    event["event_id"],
    event["ts"],
    event["log_origin"],
    event["source"],
    event["level"],
    event["service"],
    event["message"],

    event.get("src_ip"),
    event.get("event_type"),
    # event.get("dest_ip"),
    # event.get("http_status"),
    # event.get("user_agent"),
    # event.get("src_port"),
    # event.get("dest_port"),
    # event.get("protocol"),

  
    # event.get("flow_id"),
    # event.get("flow_state"),
    # event.get("flow_reason"),
    # event.get("flow_age"),
    # event.get("bytes_toserver"),
    # event.get("bytes_toclient"),
    # event.get("pkts_toserver"),
    # event.get("pkts_toclient"),
    event.get("alerted"),

    # event["raw_json"],
)

    return row






class ClickHouseWriter:
    def __init__(self):
        self.client = connection.client
        self.buffer = []
        self.ack_ids = []
    

    async def consume_and_insert(self):
        while True:
            messages = await redis_client.xreadgroup(
            groupname=REDIS_GROUP,
            consumername=CONSUMER_NAME,
            streams={REDIS_STREAM: ">"},
            count=BATCH_SIZE,
            block=BLOCK_MS,
        )

            if not messages:
                continue

            for _, entries in messages:
                for msg_id, fields in entries:
                    try:
                        event = json.loads(fields["payload"])
                        # print("event ==>",event)
                        self.buffer.append(to_row(event))
                        self.ack_ids.append(msg_id)
                    except Exception as e:

                        print("Bad event skipped:", e)

            assert all(isinstance(e, tuple) for e in self.buffer)

            if self.buffer:
                try:
                    self.client.insert(
                        table=CLICKHOUSE_TABLE,
                        data=self.buffer,
                        column_names=[
                            "event_id",
                            "ts",
                            "log_origin",
                            "source",
                            "level",
                            "service",
                            "message",

                            "src_ip",
                            "event_type",
                            # "dest_ip",
                            # "http_status",
                            # "user_agent",

                            # "raw_json",

                            # "src_port",
                            # "dest_port",
                            # "protocol",


                            "alerted",
                        ]
                    )


                    # ACK only after successful insert
                    await redis_client.xack(
                        REDIS_STREAM, REDIS_GROUP, *self.ack_ids
                    )

                    self.buffer.clear()
                    self.ack_ids.clear()

                except Exception as e:
                    print("ClickHouse insert failed:", e)
                    print("FAILED EVENT:", event)
                    print("FAILED ROW:", to_row(event))
                    raise

                    await asyncio.sleep(1)  # backoff



# ---------------- BOOTSTRAP ----------------

async def main():
    try:
        await redis_client.xgroup_create(
            name=REDIS_STREAM,
            groupname=REDIS_GROUP,
            id="$",
            mkstream=True,
        )
    except Exception:
        pass  # group already exists

    await ClickHouseWriter().consume_and_insert()

if __name__ == "__main__":
    print("ClickHouse writer started")
    asyncio.run(main())
