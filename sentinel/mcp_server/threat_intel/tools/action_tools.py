from fastmcp import FastMCP
import httpx
from workflows.state import Phase3State
# from workflows.nodes import (
#     check_verdict_node,
#     checking_action_node,
#     plan_actions_node,
#     approval_gate_node,
# )
from app.storage.tool_storage import action_info


def register_action_tools(mcp: FastMCP):

    @mcp.tool(
        name="check_verdict_tool",
        description="First you need to check whether the verdict is vailable or not, if it's available we can proceed next otherwise we you need to stop",
    )
    async def check_verdict(action_id: str):
        try:
            # response = await action_info.find_verdict(action_id=action_id)
            # return response
            pass
        except Exception:
            return "ERROR"

    @mcp.tool(
        name="plan_actions_tool", description="Your task is need to verify the plan"
    )
    async def plan_actions_tool(action_id: str):
        # response = await action_info.create_plan(action_id=action_id)
        # return response
        pass

    # @mcp.tool(
    #     name="find_is_action_needed",
    #     description="Your task is need to find any action needed based on required approval",
    # )
    # async def find_action_is_needed():
    #     state = Phase3State
    #     plan = state.get("plan", {}).get("actions")
    #     action = next(plan, None)
    #     print(action, "ACTION")
    #     if not action:
    #         return None

    #     if action.requires_approval:
    #         state["isActionNeeded"] = True
    #         return True

    # async def action_approval_tool():
    #     pass
