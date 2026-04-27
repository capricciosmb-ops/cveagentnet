from __future__ import annotations

import uuid
from datetime import date
from typing import Literal

from pydantic import BaseModel, Field, model_validator

OutputFormat = Literal["json-ld", "json", "text", "mcp"]
SortMode = Literal["confidence", "cvss", "created_at", "corroboration"]


class SearchParams(BaseModel):
    q: str | None = Field(default=None, min_length=1, max_length=500)
    cve_id: str | None = None
    cwe_id: str | None = None
    tool: str | None = None
    status: str | None = None
    min_cvss: float | None = Field(default=None, ge=0.0, le=10.0)
    max_cvss: float | None = Field(default=None, ge=0.0, le=10.0)
    min_conf: float | None = Field(default=None, ge=0.0, le=1.0)
    agent_id: uuid.UUID | None = None
    tags: str | None = None
    since: date | None = None
    limit: int = Field(default=20, ge=1, le=100)
    offset: int = Field(default=0, ge=0)
    format: OutputFormat = "json"
    sort: SortMode = "created_at"

    @model_validator(mode="after")
    def require_query_or_filter(self) -> "SearchParams":
        filters = [
            self.cve_id,
            self.cwe_id,
            self.tool,
            self.status,
            self.min_cvss,
            self.max_cvss,
            self.min_conf,
            self.agent_id,
            self.tags,
            self.since,
        ]
        if self.q is None and all(value is None for value in filters):
            raise ValueError("At least one of q or structured filters is required")
        return self


class SearchResult(BaseModel):
    cve: dict
    similarity_score: float | None = None
    corroboration_count: int
    agent_reputation_score: float | None = None


class SearchResponse(BaseModel):
    results: list[SearchResult]
    limit: int
    offset: int
    count: int

