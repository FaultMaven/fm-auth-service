"""
SSO configuration model.

Stores SAML/OAuth/OIDC configuration per organization.
"""

from datetime import datetime, timezone
from typing import Optional
from uuid import UUID, uuid4

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from enterprise.models.base import Base


def _utc_now() -> datetime:
    """Return current UTC time (timezone-aware)."""
    return datetime.now(timezone.utc)


class SSOConfiguration(Base):
    """
    SSO configuration for organization-level identity providers.

    Each organization can have multiple SSO configurations:
    - SAML 2.0 providers
    - OAuth 2.0 providers
    - OIDC providers
    """

    __tablename__ = "sso_configurations"

    # Primary key
    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)

    # Foreign key
    organization_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # SSO provider details
    provider_type: Mapped[str] = mapped_column(String(50), nullable=False)  # saml, oauth, oidc
    provider_name: Mapped[str] = mapped_column(
        String(255), nullable=False
    )  # "Okta", "Azure AD", etc.
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)

    # SAML configuration (when provider_type = 'saml')
    saml_entity_id: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    saml_sso_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    saml_slo_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # Single Logout URL
    saml_x509_cert: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    saml_name_id_format: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # OAuth/OIDC configuration (when provider_type = 'oauth' or 'oidc')
    oauth_client_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    oauth_client_secret: Mapped[Optional[str]] = mapped_column(
        String(500), nullable=True
    )  # Encrypted
    oauth_authorization_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    oauth_token_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    oauth_userinfo_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    oauth_scopes: Mapped[Optional[str]] = mapped_column(
        String(500), nullable=True
    )  # Comma-separated

    # OIDC-specific
    oidc_issuer: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    oidc_jwks_uri: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Attribute mapping (flexible JSON)
    # Maps SSO attributes to user fields: {"email": "emailAddress", "name": "displayName"}
    attribute_mapping: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    # Additional configuration
    auto_create_users: Mapped[bool] = mapped_column(
        Boolean, default=True
    )  # Auto-provision new users
    default_role_id: Mapped[Optional[UUID]] = mapped_column(
        PG_UUID(as_uuid=True), nullable=True
    )  # Default role for auto-created users

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=_utc_now, onupdate=_utc_now, nullable=False
    )

    # Relationships
    organization: Mapped["Organization"] = relationship(
        "Organization", back_populates="sso_configurations"
    )

    def __repr__(self) -> str:
        return f"<SSOConfiguration(id={self.id}, type={self.provider_type}, name={self.provider_name})>"

    @property
    def is_saml(self) -> bool:
        """Check if this is a SAML configuration."""
        return self.provider_type == "saml"

    @property
    def is_oauth(self) -> bool:
        """Check if this is an OAuth configuration."""
        return self.provider_type == "oauth"

    @property
    def is_oidc(self) -> bool:
        """Check if this is an OIDC configuration."""
        return self.provider_type == "oidc"
