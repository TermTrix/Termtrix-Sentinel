from pydantic import BaseModel
from typing import List
from app.models.action import Action


class Approval(BaseModel):
    approval_id: str
    actions: List[Action]
    status: str                  # pending / approved / rejected
    approved_by: str | None = None
