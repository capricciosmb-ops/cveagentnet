from __future__ import annotations

import re
import uuid
from datetime import date, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator, model_validator

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
CWE_RE = re.compile(r"^CWE-\d{1,5}$")


class AffectedProduct(BaseModel):
    model_config = ConfigDict(extra="forbid")

    vendor: str = Field(min_length=1, max_length=120)
    product: str = Field(min_length=1, max_length=160)
    version_range: str = Field(min_length=1, max_length=200)


class ExploitStep(BaseModel):
    model_config = ConfigDict(extra="forbid")

    step: int = Field(ge=1, le=100)
    action: str = Field(min_length=1, max_length=1000)
    evidence: str = Field(min_length=1, max_length=8000)


class CVEFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=10, max_length=200)
    description: str = Field(min_length=50, max_length=10000)
    cve_id: str | None = None
    cwe_id: str | None = None
    cvss_v3_vector: str | None = Field(default=None, max_length=100)
    cvss_v3_score: float | None = Field(default=None, ge=0.0, le=10.0)
    epss_score: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Optional agent hint. Authoritative EPSS is refreshed from FIRST for published CVE IDs.",
    )
    affected_products: list[AffectedProduct] = Field(default_factory=list, max_length=100)
    exploit_chain: list[ExploitStep] = Field(default_factory=list, max_length=100)
    reproduction_steps: str = Field(min_length=1, max_length=5000)
    confidence_score: float = Field(ge=0.0, le=1.0)
    payload_sample: str | None = Field(default=None, max_length=5000)
    references: list[HttpUrl] = Field(default_factory=list, max_length=50)
    tags: list[str] = Field(default_factory=list, max_length=40)

    @field_validator("cve_id")
    @classmethod
    def validate_cve_id(cls, value: str | None) -> str | None:
        if value and not CVE_RE.match(value):
            raise ValueError("cve_id must match CVE-YYYY-NNNN")
        return value

    @field_validator("cwe_id")
    @classmethod
    def validate_cwe_id(cls, value: str | None) -> str | None:
        if value and not CWE_RE.match(value):
            raise ValueError("cwe_id must match CWE-NNN")
        return value

    @field_validator("tags")
    @classmethod
    def normalize_tags(cls, values: list[str]) -> list[str]:
        normalized = []
        for value in values:
            tag = value.strip().lower()
            if not tag or len(tag) > 40:
                raise ValueError("tags must be non-empty strings up to 40 characters")
            normalized.append(tag)
        return list(dict.fromkeys(normalized))

    @model_validator(mode="after")
    def require_evidence_for_high_confidence(self) -> "CVEFinding":
        if self.confidence_score > 0.9 and not self.exploit_chain:
            raise ValueError("confidence_score > 0.9 requires at least one exploit_chain entry")
        return self


class CVESubmission(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_scope: str = Field(min_length=1, max_length=255)
    finding: CVEFinding


class CVEEntryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    cve_id: str | None
    provisional_hash: str
    title: str
    description: str
    cwe_id: str | None
    cvss_v3_vector: str | None
    cvss_v3_score: float | None
    epss_score: float | None
    epss_percentile: float | None
    epss_date: date | None
    epss_last_checked_at: datetime | None
    epss_source: str | None
    affected_products: list[dict[str, Any]]
    exploit_chain: list[dict[str, Any]]
    reproduction_steps: str
    payload_sample: str | None
    confidence_score: float
    tags: list[str]
    references: list[str]
    status: str
    submitting_agent_id: uuid.UUID
    target_scope: str
    tool_chain: list[str]
    corroboration_count: int
    trusted_corroboration_count: int
    dispute_count: int
    created_at: datetime
    updated_at: datetime
    published_at: datetime | None


class CVEConflictResponse(BaseModel):
    detail: str
    existing_cve_entry_id: uuid.UUID
    existing_cve_id: str | None
    match_type: str
    similarity_score: float | None = None
    suggestion: str = "Add an enrichment to the existing CVE entry instead of creating a duplicate."
