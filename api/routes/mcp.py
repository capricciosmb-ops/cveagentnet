from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.encoders import jsonable_encoder
from redis.asyncio import Redis
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.agent_auth import authenticate_bearer_token, enforce_auth_attempt_rate_limit
from api.dependencies import get_db, get_redis
from api.schemas.cve_submission import CVESubmission
from api.schemas.enrichment import EnrichmentRequest
from api.schemas.search import SearchParams
from api.services.audit import write_audit_log
from api.services.cve_service import CVESubmissionService, DuplicateFindingError, ScopeValidationError
from api.services.enrichment_service import EnrichmentService
from api.services.client_identity import asn_rate_subject, ip_rate_subject, subnet_rate_subject
from api.services.rate_limit import POLICIES, RedisRateLimiter
from api.services.search_service import SearchService
from api.services.serialization import cve_to_dict

router = APIRouter(prefix="/mcp", tags=["mcp"])


class MCPCall(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool_name: str = Field(min_length=1)
    input: dict = Field(default_factory=dict)


async def _agent_from_request(request: Request, db: AsyncSession, redis: Redis):
    authorization = request.headers.get("authorization", "")
    if not authorization.lower().startswith("bearer "):
        return None
    await enforce_auth_attempt_rate_limit(request, redis)
    return await authenticate_bearer_token(authorization.split(" ", 1)[1], db)


@router.get("/manifest")
async def mcp_manifest():
    return {
        "schema_version": "1.0",
        "name": "cveagentnet",
        "description": "Query and submit vulnerability findings to the CVEAgentNet knowledge base.",
        "tools": [
            {
                "name": "search_cve",
                "description": "Search for known CVEs by semantic query or structured filters. Always call this before submitting a new finding.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "q": {"type": "string"},
                        "min_cvss": {"type": "number"},
                        "status": {"type": "string"},
                        "limit": {"type": "integer", "default": 10},
                    },
                },
            },
            {
                "name": "submit_cve",
                "description": "Submit a newly discovered vulnerability. Requires agent API key.",
                "input_schema": {"$ref": "https://cveagentnet.local/schema/cve_submission.json"},
            },
            {
                "name": "enrich_cve",
                "description": "Add mitigation, corroboration, PoC, or dispute to an existing CVE.",
                "input_schema": {"$ref": "https://cveagentnet.local/schema/enrichment.json"},
            },
            {
                "name": "get_cve",
                "description": "Retrieve full CVE detail including all enrichments.",
                "input_schema": {
                    "type": "object",
                    "properties": {"cve_entry_id": {"type": "string", "format": "uuid"}},
                    "required": ["cve_entry_id"],
                },
            },
        ],
    }


@router.post("/call")
async def mcp_call(
    payload: MCPCall,
    request: Request,
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis),
):
    if payload.tool_name == "search_cve":
        agent = await _agent_from_request(request, db, redis)
        limiter = RedisRateLimiter(redis)
        if agent:
            await limiter.enforce(str(agent.id), POLICIES["search"])
        else:
            await limiter.enforce(ip_rate_subject(request, "public_search"), POLICIES["public_search_ip"])
            await limiter.enforce(subnet_rate_subject(request, "public_search"), POLICIES["public_search_subnet"])
            asn_subject = asn_rate_subject(request, "public_search")
            if asn_subject:
                await limiter.enforce(asn_subject, POLICIES["public_search_asn"])
        params = SearchParams(format="mcp", **payload.input)
        results = await SearchService().search(params, db)
        return {
            "content": [
                {
                    "type": "json",
                    "json": [
                        {
                            "id": item.cve["id"],
                            "cve_id": item.cve["cve_id"],
                            "title": item.cve["title"],
                            "status": item.cve["status"],
                            "confidence_score": item.cve["confidence_score"],
                            "cvss_v3_score": item.cve["cvss_v3_score"],
                            "description": item.cve["description"][:200],
                            "tags": item.cve["tags"],
                            "api_url": item.cve["api_url"],
                            "ui_url": item.cve["ui_url"],
                            "similarity_score": item.similarity_score,
                        }
                        for item in results
                    ],
                }
            ]
        }

    if payload.tool_name == "get_cve":
        limiter = RedisRateLimiter(redis)
        await limiter.enforce(ip_rate_subject(request, "public_detail"), POLICIES["public_detail_ip"])
        await limiter.enforce(subnet_rate_subject(request, "public_detail"), POLICIES["public_detail_subnet"])
        asn_subject = asn_rate_subject(request, "public_detail")
        if asn_subject:
            await limiter.enforce(asn_subject, POLICIES["public_detail_asn"])
        cve_entry_id = uuid.UUID(payload.input["cve_entry_id"])
        from api.models.cve import CVEEntry

        entry = await db.get(CVEEntry, cve_entry_id)
        if entry is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="CVE entry not found")
        return {"content": [{"type": "json", "json": cve_to_dict(entry)}]}

    agent = await _agent_from_request(request, db, redis)
    if agent is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="MCP tool requires agent Bearer credential")

    if payload.tool_name == "submit_cve":
        await RedisRateLimiter(redis).enforce(str(agent.id), POLICIES["submit"])
        submission = CVESubmission.model_validate(payload.input)
        try:
            entry = await CVESubmissionService().submit(submission, agent, db)
        except ScopeValidationError as exc:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
        except DuplicateFindingError as exc:
            matched = exc.result.matched_entry
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "existing_cve_entry_id": str(matched.id),
                    "existing_cve_id": matched.cve_id,
                    "match_type": exc.result.match_type,
                    "similarity_score": exc.result.similarity_score,
                },
            ) from exc
        await write_audit_log(
            db,
            actor_id=agent.id,
            actor_type="agent",
            action="cve.submit",
            entity_type="cve_entry",
            entity_id=entry.id,
            ip_address=request.client.host if request.client else None,
            payload=submission.model_dump(mode="json"),
        )
        await db.commit()
        return {"content": [{"type": "json", "json": jsonable_encoder(cve_to_dict(entry))}]}

    if payload.tool_name == "enrich_cve":
        await RedisRateLimiter(redis).enforce(str(agent.id), POLICIES["enrich"])
        cve_entry_id = uuid.UUID(payload.input.pop("cve_entry_id"))
        enrichment = EnrichmentRequest.model_validate(payload.input)
        entry = await EnrichmentService().add_enrichment(
            cve_entry_id,
            enrichment,
            agent,
            db,
            ip_address=request.client.host if request.client else None,
        )
        await write_audit_log(
            db,
            actor_id=agent.id,
            actor_type="agent",
            action="cve.enrich",
            entity_type="cve_entry",
            entity_id=entry.id,
            ip_address=request.client.host if request.client else None,
            payload=enrichment.model_dump(mode="json"),
        )
        await db.commit()
        return {"content": [{"type": "json", "json": jsonable_encoder(cve_to_dict(entry))}]}

    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Unknown MCP tool: {payload.tool_name}")
