from __future__ import annotations

import uuid
from datetime import date, datetime

from sqlalchemy import Date, DateTime, ForeignKey, Integer, Numeric, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from api.models.base import Base, Embedding, GUID, JsonDict, StringArray, TimestampMixin, utcnow


class CVEEntry(TimestampMixin, Base):
    __tablename__ = "cve_entries"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    cve_id: Mapped[str | None] = mapped_column(String(30), unique=True, index=True, nullable=True)
    provisional_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    cwe_id: Mapped[str | None] = mapped_column(String(20), index=True, nullable=True)
    cvss_v3_vector: Mapped[str | None] = mapped_column(String(100), nullable=True)
    cvss_v3_score: Mapped[float | None] = mapped_column(Numeric(3, 1), nullable=True)
    epss_score: Mapped[float | None] = mapped_column(Numeric(7, 6), nullable=True)
    epss_percentile: Mapped[float | None] = mapped_column(Numeric(7, 6), nullable=True)
    epss_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    epss_last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    epss_source: Mapped[str | None] = mapped_column(String(40), nullable=True)
    affected_products: Mapped[list[dict]] = mapped_column(JsonDict, default=list, nullable=False)
    exploit_chain: Mapped[list[dict]] = mapped_column(JsonDict, default=list, nullable=False)
    reproduction_steps: Mapped[str] = mapped_column(Text, nullable=False)
    payload_sample: Mapped[str | None] = mapped_column(Text, nullable=True)
    confidence_score: Mapped[float] = mapped_column(Numeric(3, 2), nullable=False)
    tags: Mapped[list[str]] = mapped_column(StringArray, default=list, nullable=False)
    references: Mapped[list[str]] = mapped_column(StringArray, default=list, nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="discovered", index=True, nullable=False)
    submitting_agent_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("agents.id"), nullable=False)
    target_scope: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    tool_chain: Mapped[list[str]] = mapped_column(StringArray, nullable=False)
    corroboration_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    trusted_corroboration_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    dispute_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    embedding: Mapped[list[float] | None] = mapped_column(Embedding, nullable=True)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    submitting_agent = relationship("Agent", back_populates="submissions")
    enrichments = relationship("Enrichment", back_populates="cve_entry", cascade="all, delete-orphan")
    lifecycle_events = relationship("LifecycleEvent", back_populates="cve_entry", cascade="all, delete-orphan")


class EnrichmentVote(Base):
    __tablename__ = "enrichment_votes"
    __table_args__ = (UniqueConstraint("agent_id", "enrichment_id", name="uq_enrichment_vote_agent"),)

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    enrichment_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("enrichments.id", ondelete="CASCADE"), nullable=False)
    agent_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("agents.id"), nullable=False)
    vote: Mapped[str] = mapped_column(String(10), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


class LifecycleEvent(Base):
    __tablename__ = "lifecycle_events"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    cve_entry_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("cve_entries.id", ondelete="CASCADE"), nullable=False)
    from_status: Mapped[str | None] = mapped_column(String(20), nullable=True)
    to_status: Mapped[str] = mapped_column(String(20), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    cve_entry = relationship("CVEEntry", back_populates="lifecycle_events")
