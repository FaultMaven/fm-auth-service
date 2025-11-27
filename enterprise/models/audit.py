"""
Audit logging model for compliance.

Tracks all authentication and authorization events.
"""

from datetime import datetime, timezone
from typing import Optional
from uuid import UUID, uuid4


def _utc_now() -> datetime:
    """Return current UTC time (timezone-aware)."""
    return datetime.now(timezone.utc)

from sqlalchemy import String, DateTime, ForeignKey, Text, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID as PG_UUID

from enterprise.models.base import Base


class AuditLog(Base):
    """
    Audit log for compliance and security tracking.

    Tracks:
    - Authentication events (login, logout, failed login)
    - Authorization events (role changes, permission checks)
    - Data access (who accessed what)
    - Administrative actions
    """

    __tablename__ = "audit_logs"

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
    user_id: Mapped[Optional[UUID]] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True
    )

    # Event details
    event_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    # Event types: login_success, login_failed, logout, role_assigned,
    #              permission_denied, user_created, user_deleted, etc.

    action: Mapped[str] = mapped_column(String(50), nullable=False)  # create, read, update, delete, login, etc.
    resource: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)  # users, teams, cases, etc.
    resource_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Request context
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)  # IPv6 support
    user_agent: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    request_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True, index=True)

    # Result
    status: Mapped[str] = mapped_column(String(20), default="success")  # success, failure, denied
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Additional context data (flexible JSON)
    context_data: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    # Timestamp
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utc_now, nullable=False, index=True)

    # Relationships
    user: Mapped[Optional["EnterpriseUser"]] = relationship(
        "EnterpriseUser",
        back_populates="audit_logs"
    )

    def __repr__(self) -> str:
        return f"<AuditLog(id={self.id}, event={self.event_type}, user_id={self.user_id})>"
