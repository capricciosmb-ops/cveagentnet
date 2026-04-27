from __future__ import annotations

from functools import lru_cache

from pydantic import AnyHttpUrl, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "CVEAgentNet"
    environment: str = "development"
    database_url: str = Field(
        default="postgresql+asyncpg://cveagentnet:cveagentnet@postgres:5432/cveagentnet",
        validation_alias="DATABASE_URL",
    )
    redis_url: str = Field(default="redis://redis:6379/0", validation_alias="REDIS_URL")
    celery_broker_url: str = Field(default="redis://redis:6379/1", validation_alias="CELERY_BROKER_URL")
    celery_result_backend: str = Field(default="redis://redis:6379/2", validation_alias="CELERY_RESULT_BACKEND")
    jwt_secret: str = Field(default="change-me-in-production", validation_alias="JWT_SECRET")
    jwt_algorithm: str = "HS256"
    jwt_ttl_minutes: int = 60
    user_oauth_jwt_secret: str = Field(default="change-me-users", validation_alias="USER_OAUTH_JWT_SECRET")
    admin_api_key: str | None = Field(default=None, validation_alias="ADMIN_API_KEY")
    api_base_url: AnyHttpUrl | str = Field(default="http://localhost:8000", validation_alias="API_BASE_URL")
    frontend_base_url: AnyHttpUrl | str = Field(default="http://localhost:3000", validation_alias="FRONTEND_BASE_URL")
    nvd_api_key: str | None = Field(default=None, validation_alias="NVD_API_KEY")
    disable_rate_limit: bool = Field(default=False, validation_alias="DISABLE_RATE_LIMIT")
    cors_origins: str = Field(default="http://localhost:3000", validation_alias="CORS_ORIGINS")
    trusted_hosts: str = Field(default="localhost,127.0.0.1,0.0.0.0,::1,api,frontend,testserver", validation_alias="TRUSTED_HOSTS")
    admin_allowed_cidrs: str = Field(
        default="127.0.0.1/32,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16",
        validation_alias="ADMIN_ALLOWED_CIDRS",
    )
    enable_public_docs: bool = Field(default=True, validation_alias="ENABLE_PUBLIC_DOCS")
    max_request_body_bytes: int = Field(default=1_000_000, validation_alias="MAX_REQUEST_BODY_BYTES")
    agent_probation_hours: int = Field(default=24, validation_alias="AGENT_PROBATION_HOURS")
    trusted_agent_min_reputation: float = Field(default=50.0, validation_alias="TRUSTED_AGENT_MIN_REPUTATION")
    edge_asn_header: str | None = Field(default=None, validation_alias="EDGE_ASN_HEADER")

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def trusted_host_list(self) -> list[str]:
        return [host.strip() for host in self.trusted_hosts.split(",") if host.strip()]

    @property
    def admin_allowed_cidr_list(self) -> list[str]:
        return [cidr.strip() for cidr in self.admin_allowed_cidrs.split(",") if cidr.strip()]

    def validate_production_ready(self) -> None:
        if self.environment.lower() not in {"production", "prod"}:
            return

        insecure_values = {
            "",
            "change-me-in-production",
            "change-me-users",
            "dev-admin-change-me",
            "replace-with-a-long-random-secret",
            "replace-with-a-second-long-random-secret",
            "replace-with-a-long-random-admin-key",
        }
        failures: list[str] = []
        if self.jwt_secret in insecure_values or len(self.jwt_secret) < 32:
            failures.append("JWT_SECRET must be a deployment-specific secret with at least 32 characters")
        if self.user_oauth_jwt_secret in insecure_values or len(self.user_oauth_jwt_secret) < 32:
            failures.append("USER_OAUTH_JWT_SECRET must be a deployment-specific secret with at least 32 characters")
        if not self.admin_api_key or self.admin_api_key in insecure_values or len(self.admin_api_key) < 32:
            failures.append("ADMIN_API_KEY must be set to a deployment-specific value with at least 32 characters")
        if self.enable_public_docs:
            failures.append("ENABLE_PUBLIC_DOCS must be false in production")
        if any("localhost" in origin or "127.0.0.1" in origin for origin in self.cors_origin_list):
            failures.append("CORS_ORIGINS must use the public frontend origin in production")
        if "*" in self.trusted_host_list:
            failures.append("TRUSTED_HOSTS must not contain wildcard hosts in production")

        if failures:
            raise RuntimeError("Unsafe production configuration: " + "; ".join(failures))


@lru_cache
def get_settings() -> Settings:
    return Settings()
