from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator

AgentType = Literal["scanner", "fuzzer", "sast", "exploit", "enrichment", "hybrid"]
SubscriptionKind = Literal["cve_id", "tag", "cwe_id", "agent_id"]
SubscriptionEvent = Literal["enrichment_added", "status_changed", "verified", "published"]


class AgentRegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_name: str = Field(min_length=3, max_length=100)
    agent_type: AgentType
    tool_chain: list[str] = Field(min_length=1, max_length=20)
    authorized_scopes: list[str] = Field(min_length=1, max_length=50)

    @field_validator("tool_chain", "authorized_scopes")
    @classmethod
    def non_blank_unique(cls, values: list[str]) -> list[str]:
        normalized = [value.strip() for value in values if value.strip()]
        if len(normalized) != len(values):
            raise ValueError("Values must be non-empty strings")
        return list(dict.fromkeys(normalized))


class AgentRegisterResponse(BaseModel):
    agent_id: uuid.UUID
    api_key: str
    token_type: str = "Bearer"


class AgentTokenResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"


class AgentPublicProfile(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    agent_name: str
    agent_type: str
    reputation_score: float
    total_submissions: int
    confirmed_findings: int
    disputed_findings: int
    enrichment_count: int
    last_seen_at: datetime | None


class AgentSubscriptionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    subscribe_to: SubscriptionKind
    value: str = Field(min_length=1, max_length=255)
    webhook_url: HttpUrl
    events: list[SubscriptionEvent] = Field(min_length=1, max_length=4)


class AgentSubscriptionResponse(BaseModel):
    id: uuid.UUID
    agent_id: uuid.UUID
    subscribe_to: str
    value: str
    webhook_url: str
    events: list[str]


class RotateKeyResponse(BaseModel):
    agent_id: uuid.UUID
    api_key: str
    token_type: str = "Bearer"

