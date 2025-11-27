"""Configuration Settings for Auth Service

Manages environment variables and application configuration.
"""

from functools import lru_cache
from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    """Application settings"""

    # Service info
    service_name: str = "fm-auth-service"
    service_version: str = "1.0.0"
    environment: str = "development"

    # Server configuration
    host: str = "0.0.0.0"
    port: int = 8000
    debug: bool = False

    # Redis configuration
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 0
    redis_password: Optional[str] = None

    @property
    def redis_url(self) -> str:
        """Construct Redis URL from components"""
        if self.redis_password:
            return f"redis://:{self.redis_password}@{self.redis_host}:{self.redis_port}/{self.redis_db}"
        return f"redis://{self.redis_host}:{self.redis_port}/{self.redis_db}"

    # Database configuration (for future PostgreSQL migration)
    database_url: Optional[str] = None
    db_pool_size: int = 5
    db_max_overflow: int = 10

    # JWT configuration (for future RS256 implementation)
    jwt_algorithm: str = "HS256"  # Will change to RS256 in production
    jwt_secret_key: Optional[str] = None
    jwt_private_key_path: Optional[str] = None
    jwt_public_key_path: Optional[str] = None
    access_token_expire_minutes: int = 1440  # 24 hours

    # Service-to-Service Authentication (RS256)
    service_token_issuer: str = "fm-auth-service"
    service_permissions_config_path: str = "/app/config/service-permissions.yml"
    service_private_key_path: str = "/app/config/service-private-key.pem"
    service_token_ttl_seconds: int = 3600  # 1 hour

    # CORS configuration
    cors_origins: list[str] = ["*"]
    cors_allow_credentials: bool = True
    cors_allow_methods: list[str] = ["*"]
    cors_allow_headers: list[str] = ["*"]

    # Logging
    log_level: str = "INFO"
    log_format: str = "json"  # json or text

    # Feature flags
    enable_registration: bool = True
    enable_password_auth: bool = True
    enable_sso: bool = False

    # Rate limiting
    rate_limit_enabled: bool = False
    rate_limit_requests: int = 100
    rate_limit_period: int = 60  # seconds

    # Metrics and observability
    enable_metrics: bool = True
    enable_tracing: bool = False
    metrics_port: int = 9090

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance

    Returns:
        Settings instance
    """
    return Settings()
