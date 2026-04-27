from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from api.models.base import Base, GUID, JsonDict, utcnow


class AbuseSignal(Base):
    __tablename__ = "abuse_signals"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    signal_type: Mapped[str] = mapped_column(String(60), nullable=False, index=True)
    severity: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    agent_id: Mapped[uuid.UUID | None] = mapped_column(GUID(), ForeignKey("agents.id"), nullable=True, index=True)
    related_agent_id: Mapped[uuid.UUID | None] = mapped_column(GUID(), ForeignKey("agents.id"), nullable=True)
    cve_entry_id: Mapped[uuid.UUID | None] = mapped_column(GUID(), ForeignKey("cve_entries.id", ondelete="CASCADE"), nullable=True, index=True)
    details: Mapped[dict] = mapped_column(JsonDict, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
