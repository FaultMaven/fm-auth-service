"""
Enterprise Configuration Settings

Extends the PUBLIC foundation settings with enterprise-specific configuration.
"""

from typing import Optional

from pydantic_settings import BaseSettings


class EnterpriseConfig(BaseSettings):
    """Enterprise configuration settings"""

    # Enterprise mode flag
    enterprise_mode: bool = True
    faultmaven_edition: str = "enterprise"

    # JWT Configuration
    JWT_SECRET_KEY: str = "your-secret-key-change-in-production"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # PostgreSQL database (required for enterprise)
    database_url: str = "postgresql://localhost:5432/faultmaven_enterprise"
    db_pool_size: int = 20
    db_max_overflow: int = 40
    db_pool_timeout: int = 30

    # Multi-tenancy configuration
    enable_multitenancy: bool = True
    default_organization_name: str = "Default Organization"

    # SSO configuration
    enable_sso: bool = True
    saml_idp_entity_id: Optional[str] = None
    saml_idp_sso_url: Optional[str] = None
    saml_idp_x509_cert: Optional[str] = None
    saml_sp_entity_id: str = "https://auth.faultmaven.ai/saml/metadata"
    saml_sp_acs_url: str = "https://auth.faultmaven.ai/saml/acs"

    # OAuth/OIDC configuration
    enable_oauth: bool = False
    oauth_client_id: Optional[str] = None
    oauth_client_secret: Optional[str] = None
    oauth_authorization_url: Optional[str] = None
    oauth_token_url: Optional[str] = None

    # RBAC configuration
    enable_rbac: bool = True
    default_user_role: str = "member"
    admin_role: str = "admin"

    # Audit logging
    enable_audit_logging: bool = True
    audit_log_database_url: Optional[str] = None  # Separate DB for audit logs

    # Monitoring and observability
    sentry_dsn: Optional[str] = None
    enable_metrics: bool = True
    enable_tracing: bool = True

    # Email configuration (for invites, notifications)
    smtp_host: Optional[str] = None
    smtp_port: int = 587
    smtp_username: Optional[str] = None
    smtp_password: Optional[str] = None
    email_from: str = "noreply@faultmaven.ai"

    # License validation
    license_key: Optional[str] = None
    license_validation_url: str = "https://license.faultmaven.ai/validate"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False
        env_prefix = "ENTERPRISE_"


# Global instance
_enterprise_config: Optional[EnterpriseConfig] = None


def get_enterprise_config() -> EnterpriseConfig:
    """Get enterprise configuration singleton"""
    global _enterprise_config
    if _enterprise_config is None:
        _enterprise_config = EnterpriseConfig()
    return _enterprise_config


# Alias for compatibility with auth middleware
get_settings = get_enterprise_config
