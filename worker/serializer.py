import json
from uuid import UUID
from datetime import datetime
from dateutil.parser import isoparse


class EventSerializer:
    @staticmethod
    def to_redis(event: dict) -> str:
        """
        Python objects → JSON string (Redis-safe)
        """
        def convert(value):
            if isinstance(value, UUID):
                return str(value)
            if isinstance(value, datetime):
                return value.isoformat()
            return value

        safe = {k: convert(v) for k, v in event.items()}
        return json.dumps(safe)

    @staticmethod
    def from_redis(payload: str) -> dict:
        """
        JSON string → Python objects
        """
        event = json.loads(payload)

        if "event_id" in event:
            event["event_id"] = UUID(event["event_id"])

        if "ts" in event:
            event["ts"] = isoparse(event["ts"])

        return event
