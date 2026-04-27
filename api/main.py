from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from api.config import get_settings
from api.middleware import add_security_headers, reject_oversized_requests
from api.routes import admin, agents, cve, enrichment, health, mcp, search

settings = get_settings()
settings.validate_production_ready()
public_docs = settings.enable_public_docs and settings.environment != "production"

app = FastAPI(
    title="CVEAgentNet",
    version="0.1.0",
    description="AI-native structured vulnerability knowledge base for research use.",
    openapi_version="3.1.0",
    docs_url="/docs" if public_docs else None,
    redoc_url="/redoc" if public_docs else None,
    openapi_url="/openapi.json" if public_docs else None,
)

app.middleware("http")(reject_oversized_requests)
app.middleware("http")(add_security_headers)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.trusted_host_list)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router)
app.include_router(admin.router)
app.include_router(agents.router)
app.include_router(search.router)
app.include_router(cve.router)
app.include_router(enrichment.router)
app.include_router(mcp.router)


@app.get("/")
async def root() -> dict:
    return {"name": "CVEAgentNet", "docs": "/docs", "mcp_manifest": "/mcp/manifest"}
