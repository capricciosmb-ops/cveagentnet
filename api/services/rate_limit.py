from __future__ import annotations

import time
from dataclasses import dataclass

from fastapi import HTTPException, status
from redis.asyncio import Redis

from api.config import get_settings


@dataclass(frozen=True)
class RatePolicy:
    action: str
    limit: int
    window_seconds: int = 3600


POLICIES = {
    "submit": RatePolicy("submit", 100),
    "enrich": RatePolicy("enrich", 500),
    "vote": RatePolicy("vote", 1000),
    "search": RatePolicy("search", 2000),
    "register_ip": RatePolicy("register_ip", 20),
    "register_subnet": RatePolicy("register_subnet", 100),
    "register_asn": RatePolicy("register_asn", 500),
    "auth_ip": RatePolicy("auth_ip", 3000),
    "auth_subnet": RatePolicy("auth_subnet", 15000),
    "auth_asn": RatePolicy("auth_asn", 100000),
    "public_search_ip": RatePolicy("public_search_ip", 300),
    "public_search_subnet": RatePolicy("public_search_subnet", 1500),
    "public_search_asn": RatePolicy("public_search_asn", 10000),
    "public_detail_ip": RatePolicy("public_detail_ip", 1000),
    "public_detail_subnet": RatePolicy("public_detail_subnet", 5000),
    "public_detail_asn": RatePolicy("public_detail_asn", 25000),
}


class RedisRateLimiter:
    def __init__(self, redis: Redis):
        self.redis = redis

    async def enforce(self, agent_id: str, policy: RatePolicy) -> None:
        if get_settings().disable_rate_limit:
            return
        now = time.time()
        key = f"rl:{agent_id}:{policy.action}"
        window_start = now - policy.window_seconds
        pipe = self.redis.pipeline()
        pipe.zremrangebyscore(key, 0, window_start)
        pipe.zcard(key)
        pipe.zadd(key, {str(now): now})
        pipe.expire(key, policy.window_seconds)
        _, count, _, _ = await pipe.execute()
        if int(count) >= policy.limit:
            oldest = await self.redis.zrange(key, 0, 0, withscores=True)
            retry_after = policy.window_seconds
            if oldest:
                retry_after = max(1, int(oldest[0][1] + policy.window_seconds - now))
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded for {policy.action}",
                headers={"Retry-After": str(retry_after)},
            )
