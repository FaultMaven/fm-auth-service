"""
Organization model for multi-tenant SaaS.

Each organization represents a separate tenant/customer.
"""

from datetime import datetime
from typing import Optional
from uuid import UUID, uuid4

from sqlalchemy import String, DateTime, Boolean, Integer
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID as PG_UUID

from enterprise.models.base import Base


class Organization(Base):
    """
    Organization (Tenant) model.

    Represents a company/customer in the multi-tenant SaaS.
    All data is isolated by organization_id.
    """

    __tablename__ = "organizations"

    # Primary key
    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid4
    )

    # Organization details
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    slug: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)

    # Subscription/billing
    plan: Mapped[str] = mapped_column(String(50), default="trial")  # trial, starter, professional, enterprise
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)

    # Limits and quotas
    max_users: Mapped[int] = mapped_column(Integer, default=10)
    max_teams: Mapped[int] = mapped_column(Integer, default=5)

    # Contact information
    contact_email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    contact_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False
    )
    deleted_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Relationships
    teams: Mapped[list["Team"]] = relationship(
        "Team",
        back_populates="organization",
        cascade="all, delete-orphan"
    )
    users: Mapped[list["EnterpriseUser"]] = relationship(
        "EnterpriseUser",
        back_populates="organization",
        cascade="all, delete-orphan"
    )
    sso_configurations: Mapped[list["SSOConfiguration"]] = relationship(
        "SSOConfiguration",
        back_populates="organization",
        cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Organization(id={self.id}, name={self.name}, plan={self.plan})>"

    @property
    def is_deleted(self) -> bool:
        """Check if organization is soft-deleted."""
        return self.deleted_at is not None

    def soft_delete(self) -> None:
        """Soft delete the organization."""
        self.deleted_at = datetime.utcnow()
        self.is_active = False
