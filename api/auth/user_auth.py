from __future__ import annotations

from fastapi import HTTPException, status
from fastapi.security import OAuth2PasswordBearer

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/users/oauth/token", auto_error=False)


def create_user_access_token(user_id: str, scopes: list[str] | None = None) -> str:
    raise RuntimeError("Human user accounts are disabled; public users are read-only browsers")


async def get_current_user() -> dict:
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Human user login is disabled")
