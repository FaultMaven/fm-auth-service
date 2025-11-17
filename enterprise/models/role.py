"""
RBAC models for enterprise access control.

Roles, permissions, and user-role assignments.
"""

from datetime import datetime
from typing import Optional
from uuid import UUID, uuid4

from sqlalchemy import String, DateTime, ForeignKey, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID as PG_UUID

from enterprise.models.base import Base


class Role(Base):
    """
    Role model for RBAC.

    Roles can be:
    - System roles: admin, member, viewer (predefined)
    - Custom roles: created by organization admins
    """

    __tablename__ = "roles"

    # Primary key
    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid4
    )

    # Role details
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # System vs custom roles
    is_system_role: Mapped[bool] = mapped_column(default=False)  # True for admin/member/viewer

    # Foreign key (null for system roles, set for custom roles)
    organization_id: Mapped[Optional[UUID]] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=True,
        index=True
    )

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False
    )

    # Relationships
    permissions: Mapped[list["Permission"]] = relationship(
        "Permission",
        back_populates="role",
        cascade="all, delete-orphan"
    )
    user_roles: Mapped[list["UserRole"]] = relationship(
        "UserRole",
        back_populates="role",
        cascade="all, delete-orphan"
    )

    __table_args__ = (
        # Unique constraint: slug must be unique within organization (or globally for system roles)
        UniqueConstraint("organization_id", "slug", name="uq_org_role_slug"),
    )

    def __repr__(self) -> str:
        return f"<Role(id={self.id}, name={self.name}, system={self.is_system_role})>"


class Permission(Base):
    """
    Permission model for fine-grained access control.

    Permissions are assigned to roles.
    """

    __tablename__ = "permissions"

    # Primary key
    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid4
    )

    # Foreign key
    role_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("roles.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )

    # Permission details
    resource: Mapped[str] = mapped_column(String(100), nullable=False)  # users, teams, cases, etc.
    action: Mapped[str] = mapped_column(String(50), nullable=False)  # create, read, update, delete

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    role: Mapped["Role"] = relationship(
        "Role",
        back_populates="permissions"
    )

    __table_args__ = (
        # Unique constraint: one permission per role per resource+action
        UniqueConstraint("role_id", "resource", "action", name="uq_role_resource_action"),
    )

    def __repr__(self) -> str:
        return f"<Permission(role_id={self.role_id}, {self.action} {self.resource})>"


class UserRole(Base):
    """
    User-Role assignment (many-to-many).

    Links users to their roles within an organization.
    """

    __tablename__ = "user_roles"

    # Primary key
    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid4
    )

    # Foreign keys
    user_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    role_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("roles.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )

    # Timestamps
    assigned_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    assigned_by: Mapped[Optional[UUID]] = mapped_column(
        PG_UUID(as_uuid=True),
        nullable=True
    )  # User ID who assigned this role

    # Relationships
    user: Mapped["EnterpriseUser"] = relationship(
        "EnterpriseUser",
        back_populates="roles"
    )
    role: Mapped["Role"] = relationship(
        "Role",
        back_populates="user_roles"
    )

    __table_args__ = (
        # Unique constraint: user can only have a role once
        UniqueConstraint("user_id", "role_id", name="uq_user_role"),
    )

    def __repr__(self) -> str:
        return f"<UserRole(user_id={self.user_id}, role_id={self.role_id})>"
