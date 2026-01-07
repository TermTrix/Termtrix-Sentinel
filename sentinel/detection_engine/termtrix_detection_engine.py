import json

class TermtrixDetectionEngine:
    NGINX_RULES = None
    def __init__(self):
        if TermtrixDetectionEngine.NGINX_RULES is None:
            TermtrixDetectionEngine.NGINX_RULES = self.load_rules()



    def load_rules(self):
        with open("./sentinel/detection_engine/NGINX_RULES.json", "r") as f:
            print("loading rules")
            RULES = json.load(f)
            # print(RULES)
            NGINX_RULES = [r for r in RULES if r["source"] == "nginx"]
            # print(NGINX_RULES)
            return NGINX_RULES
    


    async def log_distributor(self,event:dict):
         try:
            event_type = event.get('event_type')
            if event_type == "http":
                await self.nginx_vialotion_detector(event)
            elif event_type == "application":
                print("APPLICATION")
            elif event_type == "flow":
                print("FLOW")
         except Exception as error:
            pass
        
    
    # EVALUATE NGINX RULES

    async def evealuate_rules(self,event:dict):
        try:
            alert = []
            for rule in TermtrixDetectionEngine.NGINX_RULES:
                # print(rule)
                # if not self.match_basic(rule,event):
                #     continue

                print(self.match_basic(rule,event), "ALERT!!!! -->>>> ",rule)
            return False
        except Exception as error:
            print(error)
            return []



    # MATCH BASIC THINGS

    def match_basic(self,rule:dict,event:dict) -> bool:
        match = rule.get("match", {})
        # print(match,"===>MATCH",event)
        if "event_type" in match:
            if event.get("event_type") != match["event_type"]:
                print("EVENT_TYPE")
                return False

        # if "http_path" in match:
        #     if match["http_path"] not in (event.get("message") or ""):
        #         return False

        if "http_status" in match:
            if event.get("http_status") not in match["http_status"]:
                print("STATUS")
                return False
        print("TRUEEEEEEEEEE")
        return True

    async def nginx_vialotion_detector(self,event:dict):
        try:
            if event.get('event_type') != "http":
                return None

            # http_status = TermtrixDetectionEngine.RULE.get('NGINX',{}).get('match')
            # print(http_status,"http_status")
            # if event.get("http_status") not in http_status.get("http_status"):
            #     return None

            await self.evealuate_rules(event)

            src_ip = event.get("src_ip")

            print(src_ip)
            
        except Exception as e:
            print("Error in detect_based_on_rule", e)


# if __name__ == "__main__":
#     t = TermtrixDetectionEngine()
  
