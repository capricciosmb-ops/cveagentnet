from __future__ import annotations

import secrets
import ipaddress

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from api.config import get_settings
from api.services.client_identity import client_ip

admin_bearer_scheme = HTTPBearer(auto_error=False)


async def require_admin(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(admin_bearer_scheme),
) -> str:
    settings = get_settings()
    if not settings.admin_api_key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Admin API is disabled until ADMIN_API_KEY is configured",
        )
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Admin bearer token required")
    try:
        remote_ip = ipaddress.ip_address(client_ip(request))
        allowed = any(remote_ip in ipaddress.ip_network(cidr, strict=False) for cidr in settings.admin_allowed_cidr_list)
    except ValueError:
        allowed = False
    if not allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access is not allowed from this network")
    # Admin is intentionally deployment-level, not a human user account. This preserves
    # public read-only browsing while keeping high-impact moderation behind a server secret.
    if not secrets.compare_digest(credentials.credentials, settings.admin_api_key):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid admin credential")
    return "admin"
