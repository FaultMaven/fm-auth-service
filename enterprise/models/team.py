"""
Team model for sub-organization grouping.

Teams are groups within an organization.
"""

from datetime import datetime
from typing import Optional
from uuid import UUID, uuid4

from sqlalchemy import String, DateTime, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID as PG_UUID

from enterprise.models.base import Base


class Team(Base):
    """
    Team model for grouping users within an organization.

    Teams provide additional organizational structure within a tenant.
    """

    __tablename__ = "teams"

    # Primary key
    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid4
    )

    # Foreign keys
    organization_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )

    # Team details
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

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
    organization: Mapped["Organization"] = relationship(
        "Organization",
        back_populates="teams"
    )
    users: Mapped[list["EnterpriseUser"]] = relationship(
        "EnterpriseUser",
        back_populates="team"
    )

    def __repr__(self) -> str:
        return f"<Team(id={self.id}, name={self.name}, org_id={self.organization_id})>"

    @property
    def is_deleted(self) -> bool:
        """Check if team is soft-deleted."""
        return self.deleted_at is not None

    def soft_delete(self) -> None:
        """Soft delete the team."""
        self.deleted_at = datetime.utcnow()
