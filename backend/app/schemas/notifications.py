from typing import Literal
from pydantic import BaseModel, Field

class NotificationCreate(BaseModel):
    title: str = Field(default="Notification", max_length=200)
    message: str = Field(default="", max_length=4000)
    type: Literal["success", "error", "info"] = "info"
    read: bool = False
