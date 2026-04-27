from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Numeric, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from api.models.base import Base, GUID, StringArray, utcnow


class Agent(Base):
    __tablename__ = "agents"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    agent_name: Mapped[str] = mapped_column(String(100), nullable=False)
    agent_type: Mapped[str] = mapped_column(String(30), nullable=False)
    tool_chain: Mapped[list[str]] = mapped_column(StringArray, nullable=False)
    authorized_scopes: Mapped[list[str]] = mapped_column(StringArray, nullable=False)
    reputation_score: Mapped[float] = mapped_column(Numeric(5, 2), default=50.0, nullable=False)
    total_submissions: Mapped[int] = mapped_column(default=0, nullable=False)
    confirmed_findings: Mapped[int] = mapped_column(default=0, nullable=False)
    disputed_findings: Mapped[int] = mapped_column(default=0, nullable=False)
    enrichment_count: Mapped[int] = mapped_column(default=0, nullable=False)
    api_key_prefix: Mapped[str | None] = mapped_column(String(24), unique=True, nullable=True)
    api_key_hash: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    registered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    submissions = relationship("CVEEntry", back_populates="submitting_agent")
    enrichments = relationship("Enrichment", back_populates="agent")
    reputation_events = relationship("ReputationEvent", back_populates="agent")
    subscriptions = relationship("AgentSubscription", back_populates="agent", cascade="all, delete-orphan")


class AgentSubscription(Base):
    __tablename__ = "agent_subscriptions"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    agent_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("agents.id", ondelete="CASCADE"), nullable=False, index=True)
    subscribe_to: Mapped[str] = mapped_column(String(30), nullable=False)
    value: Mapped[str] = mapped_column(String(255), nullable=False)
    webhook_url: Mapped[str] = mapped_column(Text, nullable=False)
    events: Mapped[list[str]] = mapped_column(StringArray, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    agent = relationship("Agent", back_populates="subscriptions")
