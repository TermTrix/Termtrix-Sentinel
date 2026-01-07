from uuid import uuid4
import json
from dateutil.parser import parse



class SentinelNormlizer:
    
    async def normalize(self, e):
        sentinel = e.get("sentinel")
        print("EVENT",sentinel)
        if sentinel == "application":
            return await self._normalize_internal(e)
        elif sentinel == "nginx":
            return await self._normalize_nginx(e)
        elif sentinel == "suricata":
            return await self._normalize_suricata(e)
        else:
            return await self._normalize_internal(e)


    async def _normalize_internal(self, e):
        # print("internal ==>",e)
        event = e.get("event", {})
        return {
            "event_id": uuid4(),
            "ts": parse(event.get("timestamp")),
            "log_origin": "application",
            "source": "sentinel",
            "level": event.get("level", "INFO").upper(),
            "service": "sentinel-api",
            "message": event.get("event"),
            "src_ip": None,
            "dest_ip": None,
            "http_status": None,
            "user_agent": None,
            "event_type": "application",
            "raw_json": json.dumps(e),
        }

    async def _normalize_nginx(self, e):
        # print(e,"EVENTTTTTTTT")
        http = e.get("event")
        # message = http.get("event")
        # json.loads()
        # print(http,"HTTP",type(http))
        # print(http.get("remote_addr"),"+++++++++++++")
        return {
            "event_id": uuid4(),
            "ts":parse(e.get("timestamp")),
            "log_origin": "network",
            "source": "nginx",
            "level": "INFO",
            "service": "nginx",
            "message": http.get("request"),
            "src_ip": http.get("remote_addr"),
            "dest_ip": None,
            "event_type": "http",
            "http_status": int(http.get("status", 0)),
            "user_agent": http.get("http_user_agent"),
            "raw_json": json.dumps(http),
        }

    async def _normalize_suricata(self, e):
        flow = e.get("event", {}).get("flow", {})   
        evt = e.get("event", {})

        if evt.get("event_type") == "stats":
            print("stats ==>")
            return None

        return {
            "event_id": uuid4(),
            "ts": parse(evt["timestamp"]),
            "log_origin": "security",
            "source": "suricata",
            "level": "INFO",
            "service": "suricata",
            "message": "network_flow",

            "event_type": "flow",
            "flow_id": evt.get("flow_id",None),

            "src_ip": evt.get("src_ip",None),
            "src_port": evt.get("src_port",None),
            "dest_ip": evt.get("dest_ip",None),
            "dest_port": evt.get("dest_port",None),
            "protocol": evt.get("proto",None),

            "bytes_toserver": flow.get("bytes_toserver",None),
            "bytes_toclient": flow.get("bytes_toclient",None),
            "pkts_toserver": flow.get("pkts_toserver",None),
            "pkts_toclient": flow.get("pkts_toclient",None),
            "flow_state": flow.get("state",None),
            "flow_reason": flow.get("reason",None),
            "flow_age": flow.get("age",None),
            "alerted": flow.get("alerted",False),

            "raw_json": json.dumps(e),
        }
    





# {
#   "event_id": "...",
#   "ts": "...",
#   "log_origin": "network",
#   "source": "nginx",
#   "level": "INFO",
#   "service": "sentinel-api",
#   "message": "GET /",
#   "src_ip": "192.168.1.62",
#   "http_status": 200,
#   "user_agent": "...",
#   "raw_json": "{...}"
# }
