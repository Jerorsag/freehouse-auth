from typing import Optional
from sqlmodel import SQLModel, Field
from datetime import datetime


class RefreshToken(SQLModel, table=True):
    __tablename__ = "refresh_tokens"

    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="users.id", index=True)
    jti: str = Field(max_length=255, unique=True, index=True)  # JWT ID único
    expires_at: datetime
    revoked: bool = Field(default=False)
    created_at: datetime = Field(default_factory=datetime.utcnow)