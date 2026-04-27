from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator


class AdminAgentProfile(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    agent_name: str
    agent_type: str
    tool_chain: list[str]
    authorized_scopes: list[str]
    reputation_score: float
    total_submissions: int
    confirmed_findings: int
    disputed_findings: int
    enrichment_count: int
    is_active: bool
    registered_at: datetime
    last_seen_at: datetime | None


class AdminAgentUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    is_active: bool | None = None
    authorized_scopes: list[str] | None = Field(default=None, min_length=1, max_length=50)
    reputation_score: float | None = Field(default=None, ge=0.0, le=100.0)

    @field_validator("authorized_scopes")
    @classmethod
    def non_blank_unique(cls, values: list[str] | None) -> list[str] | None:
        if values is None:
            return None
        normalized = [value.strip() for value in values if value.strip()]
        if len(normalized) != len(values):
            raise ValueError("authorized_scopes values must be non-empty strings")
        return list(dict.fromkeys(normalized))


class AdminAuditLogEntry(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    timestamp: datetime
    actor_id: uuid.UUID | None
    actor_type: str
    action: str
    entity_type: str
    entity_id: uuid.UUID | None
    ip_address: str | None
    request_hash: str


class AdminAbuseSignal(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    signal_type: str
    severity: int
    agent_id: uuid.UUID | None
    related_agent_id: uuid.UUID | None
    cve_entry_id: uuid.UUID | None
    details: dict
    created_at: datetime
