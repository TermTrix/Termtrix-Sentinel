from typing import Dict, Optional
import json
from app.models.approval import Approval
from app.core.redis import redis_client

class ApprovalStore:
    """Redis-based approval storage with automatic expiry"""

    def __init__(self):
        self.prefix = "approval:"
        self.ttl = 3600 # 1 hour expiry

    async def save(self, approval: Approval) -> None:
        """Save approval to Redis with TTL"""
        key = f"{self.prefix}{approval.approval_id}"
        value = approval.model_dump_json()
        await redis_client.setex(key, self.ttl, value)

    async def get(self, approval_id:str) -> Optional[Approval]:
        """Retrieve approval from Redis"""
        key = f"{self.prefix}{approval_id}"
        value = await redis_client.get(key)
        if not value:
            return None
        return Approval.model_validate_json(value)
    
    async def update(self, approval: Approval) -> None:
        """Update existing approval"""
        await self.save(approval)

    async def delete(self, approval_id: str) -> None:
        """Delete approval from Redis"""
        key = f"{self.prefix}{approval_id}"
        await redis_client.delete(key)

    async def list_pending(self) -> list[Approval]:
        """Get all pending approvals"""
        keys = await redis_client.keys(f"{self.prefix}*")
        approvals = []

        for key in keys:
            value = await redis_client.get(key)
            if value:
                approval = Approval.model_validate_json(value)
                if approval.status == "pending":
                    approvals.append(approval)
        return approvals

# Global singleton
approval_store = ApprovalStore()