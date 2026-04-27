from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from api.models.audit import AuditLog


def request_hash(payload: Any) -> str:
    encoded = json.dumps(payload, default=str, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


async def write_audit_log(
    db: AsyncSession,
    *,
    actor_id: uuid.UUID | None,
    actor_type: str,
    action: str,
    entity_type: str,
    entity_id: uuid.UUID | None,
    ip_address: str | None,
    payload: Any,
) -> None:
    db.add(
        AuditLog(
            actor_id=actor_id,
            actor_type=actor_type,
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            ip_address=ip_address,
            request_hash=request_hash(payload),
        )
    )
    await db.flush()

