from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Request
from fastapi.responses import PlainTextResponse
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.agent_auth import bearer_scheme, authenticate_bearer_token, enforce_auth_attempt_rate_limit
from api.dependencies import get_db, get_redis
from api.schemas.search import SearchParams
from api.services.client_identity import asn_rate_subject, ip_rate_subject, subnet_rate_subject
from api.services.rate_limit import POLICIES, RedisRateLimiter
from api.services.search_service import SearchService

router = APIRouter(prefix="/cve", tags=["search"])


@router.get("/search")
async def search_cves(
    request: Request,
    params: Annotated[SearchParams, Depends()],
    credentials=Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis),
):
    limiter = RedisRateLimiter(redis)
    if credentials:
        await enforce_auth_attempt_rate_limit(request, redis)
        agent = await authenticate_bearer_token(credentials.credentials, db)
        if agent:
            await limiter.enforce(str(agent.id), POLICIES["search"])
        else:
            await limiter.enforce(ip_rate_subject(request, "public_search"), POLICIES["public_search_ip"])
            await limiter.enforce(subnet_rate_subject(request, "public_search"), POLICIES["public_search_subnet"])
            asn_subject = asn_rate_subject(request, "public_search")
            if asn_subject:
                await limiter.enforce(asn_subject, POLICIES["public_search_asn"])
    else:
        await limiter.enforce(ip_rate_subject(request, "public_search"), POLICIES["public_search_ip"])
        await limiter.enforce(subnet_rate_subject(request, "public_search"), POLICIES["public_search_subnet"])
        asn_subject = asn_rate_subject(request, "public_search")
        if asn_subject:
            await limiter.enforce(asn_subject, POLICIES["public_search_asn"])
    results = await SearchService().search(params, db)
    if params.format == "text":
        lines = ["# CVEAgentNet Search Results", ""]
        for result in results:
            cve = result.cve
            score = f" similarity={result.similarity_score:.2f}" if result.similarity_score is not None else ""
            lines.extend([f"## {cve['cve_id']} - {cve['title']}", f"status={cve['status']} confidence={cve['confidence_score']}{score}", cve["description"][:300], ""])
        return PlainTextResponse("\n".join(lines), media_type="text/markdown")
    if params.format == "mcp":
        return {
            "results": [
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
            ]
        }
    payload = {"results": [item.model_dump(mode="json") for item in results], "limit": params.limit, "offset": params.offset, "count": len(results)}
    if params.format == "json-ld":
        return {"@context": "https://cveagentnet.local/schema/jsonld_context.json", "@graph": payload["results"], **payload}
    return payload
