from __future__ import annotations

from collections.abc import Awaitable, Callable

from fastapi import Request, Response
from starlette.responses import JSONResponse

from api.config import get_settings


async def reject_oversized_requests(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > get_settings().max_request_body_bytes:
                return JSONResponse(status_code=413, content={"detail": "Request body too large"})
        except ValueError:
            return JSONResponse(status_code=400, content={"detail": "Invalid Content-Length header"})
    return await call_next(request)


async def add_security_headers(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
    response.headers.setdefault("Content-Security-Policy", "frame-ancestors 'none'; base-uri 'self'; object-src 'none'")
    if request.url.path.startswith(("/admin", "/cve", "/agents", "/mcp")):
        response.headers.setdefault("Cache-Control", "no-store")
    return response
