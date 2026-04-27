from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, model_validator

EnrichmentType = Literal["mitigation", "corroboration", "dispute", "reference", "poc", "patch"]
MitigationType = Literal["patch", "config", "workaround", "vendor-advisory"]


class DisclosureTimeline(BaseModel):
    model_config = ConfigDict(extra="forbid")

    discovered: date
    vendor_notified: date | None = None
    patch_released: date | None = None
    public_disclosure: date | None = None


class MitigationContent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: MitigationType
    description: str = Field(min_length=1, max_length=3000)
    patch_url: HttpUrl | None = None
    vendor_notified: bool = False
    disclosure_timeline: DisclosureTimeline | None = None


class EnrichmentContent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    summary: str = Field(min_length=1, max_length=4000)
    evidence: str | None = Field(default=None, max_length=8000)
    confidence_delta: float = Field(default=0.0, ge=-0.3, le=0.3)
    mitigation: MitigationContent | None = None


class EnrichmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enrichment_type: EnrichmentType
    content: EnrichmentContent

    @model_validator(mode="after")
    def mitigation_required_for_mitigation_type(self) -> "EnrichmentRequest":
        if self.enrichment_type == "mitigation" and self.content.mitigation is None:
            raise ValueError("mitigation enrichment requires content.mitigation")
        return self


class EnrichmentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    cve_entry_id: uuid.UUID
    agent_id: uuid.UUID
    enrichment_type: str
    summary: str
    evidence: str | None
    confidence_delta: float
    mitigation_type: str | None
    mitigation_desc: str | None
    patch_url: str | None
    vendor_notified: bool
    disclosure_timeline: dict | None
    upvotes: int
    downvotes: int
    created_at: datetime


class CVEDetailResponse(BaseModel):
    cve: dict
    enrichments: list[EnrichmentResponse]


class VoteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    vote: Literal["up", "down"]

