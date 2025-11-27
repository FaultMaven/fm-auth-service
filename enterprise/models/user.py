"""
Enterprise User model extending PUBLIC foundation.

Adds organization/team relationships for multi-tenancy.
"""

from datetime import datetime, timezone
from typing import Optional
from uuid import UUID, uuid4


def _utc_now() -> datetime:
    """Return current UTC time (timezone-aware)."""
    return datetime.now(timezone.utc)

from sqlalchemy import String, DateTime, Boolean, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID as PG_UUID

from enterprise.models.base import Base


class EnterpriseUser(Base):
    """
    Enterprise User model for multi-tenant SaaS.

    Extends the PUBLIC User model with:
    - Organization/team relationships
    - SSO authentication tracking
    - Enhanced audit fields

    Note: This is separate from PUBLIC User (SQLite) - no migration needed.
    Enterprise database starts fresh.
    """

    __tablename__ = "users"

    # Primary key
    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid4
    )

    # Foreign keys (multi-tenancy)
    organization_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    team_id: Mapped[Optional[UUID]] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("teams.id", ondelete="SET NULL"),
        nullable=True,
        index=True
    )

    # User credentials (same as PUBLIC)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    hashed_password: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)  # None for SSO-only users

    # User profile
    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False)

    # SSO tracking
    sso_provider: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)  # saml, oauth, oidc
    sso_subject_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)

    # Security
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    password_changed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=_utc_now,
        onupdate=_utc_now,
        nullable=False
    )
    deleted_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Relationships
    organization: Mapped["Organization"] = relationship(
        "Organization",
        back_populates="users"
    )
    team: Mapped[Optional["Team"]] = relationship(
        "Team",
        back_populates="users"
    )
    roles: Mapped[list["UserRole"]] = relationship(
        "UserRole",
        back_populates="user",
        cascade="all, delete-orphan"
    )
    audit_logs: Mapped[list["AuditLog"]] = relationship(
        "AuditLog",
        back_populates="user",
        cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<EnterpriseUser(id={self.id}, email={self.email}, org_id={self.organization_id})>"

    @property
    def is_deleted(self) -> bool:
        """Check if user is soft-deleted."""
        return self.deleted_at is not None

    @property
    def is_sso_user(self) -> bool:
        """Check if user authenticates via SSO."""
        return self.sso_provider is not None

    def soft_delete(self) -> None:
        """Soft delete the user."""
        self.deleted_at = datetime.now(timezone.utc)
        self.is_active = False
