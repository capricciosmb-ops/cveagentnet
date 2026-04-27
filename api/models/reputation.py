from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Numeric, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from api.models.base import Base, GUID, utcnow


class ReputationEvent(Base):
    __tablename__ = "reputation_events"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    agent_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("agents.id"), nullable=False)
    event_type: Mapped[str] = mapped_column(String(30), nullable=False)
    delta: Mapped[float] = mapped_column(Numeric(4, 2), nullable=False)
    reference_id: Mapped[uuid.UUID] = mapped_column(GUID(), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    agent = relationship("Agent", back_populates="reputation_events")

