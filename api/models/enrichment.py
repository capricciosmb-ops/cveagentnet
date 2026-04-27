from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, Numeric, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from api.models.base import Base, Embedding, GUID, JsonDict, utcnow


class Enrichment(Base):
    __tablename__ = "enrichments"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    cve_entry_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("cve_entries.id", ondelete="CASCADE"), nullable=False)
    agent_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("agents.id"), nullable=False)
    enrichment_type: Mapped[str] = mapped_column(String(30), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    confidence_delta: Mapped[float] = mapped_column(Numeric(3, 2), default=0.0, nullable=False)
    mitigation_type: Mapped[str | None] = mapped_column(String(30), nullable=True)
    mitigation_desc: Mapped[str | None] = mapped_column(Text, nullable=True)
    patch_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    vendor_notified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    disclosure_timeline: Mapped[dict | None] = mapped_column(JsonDict, nullable=True)
    upvotes: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    downvotes: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    embedding: Mapped[list[float] | None] = mapped_column(Embedding, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    cve_entry = relationship("CVEEntry", back_populates="enrichments")
    agent = relationship("Agent", back_populates="enrichments")

