"""
User management API routes for enterprise.

Provides CRUD operations for users within organizations.
"""

from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel, EmailStr, Field

from enterprise.models import EnterpriseUser, Organization, Team
from enterprise.security import hash_password
from enterprise.middleware.auth import (
    get_current_active_user,
    require_permissions,
    require_org_admin,
    require_org_access
)

router = APIRouter(prefix="/api/v1/enterprise/users", tags=["users"])


# Pydantic schemas
class UserCreate(BaseModel):
    """Schema for creating a new user."""
    organization_id: UUID
    team_id: Optional[UUID] = None
    email: EmailStr
    full_name: str = Field(..., min_length=1, max_length=255)
    password: Optional[str] = Field(None, min_length=8)  # None for SSO-only users


class UserUpdate(BaseModel):
    """Schema for updating a user."""
    team_id: Optional[UUID] = None
    full_name: Optional[str] = Field(None, min_length=1, max_length=255)
    is_active: Optional[bool] = None


class UserResponse(BaseModel):
    """Schema for user response."""
    id: UUID
    organization_id: UUID
    team_id: Optional[UUID]
    email: str
    full_name: str
    is_active: bool
    is_verified: bool
    sso_provider: Optional[str]

    class Config:
        from_attributes = True


# Import database session dependency
from enterprise.database import get_db


@router.post("", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    user: UserCreate,
    db: AsyncSession = Depends(get_db),
    current_user: EnterpriseUser = Depends(require_permissions("users:create"))
):
    """
    Create a new user in an organization.

    Requires 'users:create' permission and user must belong to the organization.

    Args:
        user: User data
        db: Database session
        current_user: Authenticated user with required permissions

    Returns:
        Created user

    Raises:
        HTTPException: If organization not found, access denied, email exists, or user limit reached
    """
    # Multi-tenant isolation: verify user belongs to the organization
    if current_user.organization_id != user.organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: You do not belong to this organization"
        )

    # Verify organization exists
    org_result = await db.execute(
        select(Organization).where(
            Organization.id == user.organization_id,
            Organization.deleted_at.is_(None)
        )
    )
    organization = org_result.scalar_one_or_none()

    if not organization:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Organization {user.organization_id} not found"
        )

    # Check user limit
    users_result = await db.execute(
        select(EnterpriseUser).where(
            EnterpriseUser.organization_id == user.organization_id,
            EnterpriseUser.deleted_at.is_(None)
        )
    )
    user_count = len(users_result.scalars().all())

    if user_count >= organization.max_users:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Organization has reached maximum users limit ({organization.max_users})"
        )

    # Check email uniqueness (global)
    email_result = await db.execute(
        select(EnterpriseUser).where(
            EnterpriseUser.email == user.email,
            EnterpriseUser.deleted_at.is_(None)
        )
    )
    existing = email_result.scalar_one_or_none()

    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"User with email '{user.email}' already exists"
        )

    # Verify team exists if provided
    if user.team_id:
        team_result = await db.execute(
            select(Team).where(
                Team.id == user.team_id,
                Team.organization_id == user.organization_id,
                Team.deleted_at.is_(None)
            )
        )
        team = team_result.scalar_one_or_none()

        if not team:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Team {user.team_id} not found in organization"
            )

    # Create user
    user_data = user.model_dump(exclude={"password"})

    # Hash password if provided
    if user.password:
        user_data["hashed_password"] = hash_password(user.password)

    db_user = EnterpriseUser(**user_data)
    db.add(db_user)
    await db.commit()
    await db.refresh(db_user)

    return db_user


@router.get("/organization/{organization_id}", response_model=List[UserResponse])
async def list_organization_users(
    organization_id: UUID,
    team_id: Optional[UUID] = None,
    is_active: Optional[bool] = None,
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    current_user: EnterpriseUser = Depends(require_org_access)
):
    """
    List users in an organization.

    Requires user to belong to the organization (multi-tenant isolation).

    Args:
        organization_id: Organization UUID
        team_id: Optional filter by team
        is_active: Optional filter by active status
        skip: Number of records to skip
        limit: Maximum number of records to return
        db: Database session
        current_user: Authenticated user with organization access

    Returns:
        List of users
    """
    query = select(EnterpriseUser).where(
        EnterpriseUser.organization_id == organization_id,
        EnterpriseUser.deleted_at.is_(None)
    )

    if team_id:
        query = query.where(EnterpriseUser.team_id == team_id)

    if is_active is not None:
        query = query.where(EnterpriseUser.is_active == is_active)

    query = query.offset(skip).limit(limit)
    result = await db.execute(query)
    users = result.scalars().all()

    return users


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: EnterpriseUser = Depends(get_current_active_user)
):
    """
    Get user by ID.

    Requires user to belong to the same organization (multi-tenant isolation).

    Args:
        user_id: User UUID
        db: Database session
        current_user: Authenticated active user

    Returns:
        User details

    Raises:
        HTTPException: If user not found or access denied
    """
    result = await db.execute(
        select(EnterpriseUser).where(
            EnterpriseUser.id == user_id,
            EnterpriseUser.deleted_at.is_(None)
        )
    )
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User {user_id} not found"
        )

    # Multi-tenant isolation: verify both users belong to the same organization
    if current_user.organization_id != user.organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: User does not belong to your organization"
        )

    return user


@router.put("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: UUID,
    user_update: UserUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: EnterpriseUser = Depends(require_permissions("users:update"))
):
    """
    Update user.

    Requires 'users:update' permission and user must belong to the same organization.

    Args:
        user_id: User UUID
        user_update: Fields to update
        db: Database session
        current_user: Authenticated user with required permissions

    Returns:
        Updated user

    Raises:
        HTTPException: If user not found, access denied, or team not found
    """
    result = await db.execute(
        select(EnterpriseUser).where(
            EnterpriseUser.id == user_id,
            EnterpriseUser.deleted_at.is_(None)
        )
    )
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User {user_id} not found"
        )

    # Multi-tenant isolation: verify both users belong to the same organization
    if current_user.organization_id != user.organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: User does not belong to your organization"
        )

    # Verify team if being updated
    update_data = user_update.model_dump(exclude_unset=True)
    if "team_id" in update_data and update_data["team_id"]:
        team_result = await db.execute(
            select(Team).where(
                Team.id == update_data["team_id"],
                Team.organization_id == user.organization_id,
                Team.deleted_at.is_(None)
            )
        )
        team = team_result.scalar_one_or_none()

        if not team:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Team {update_data['team_id']} not found in user's organization"
            )

    # Update fields
    for field, value in update_data.items():
        setattr(user, field, value)

    await db.commit()
    await db.refresh(user)

    return user


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: EnterpriseUser = Depends(require_permissions("users:delete"))
):
    """
    Soft delete user.

    Requires 'users:delete' permission and user must belong to the same organization.

    Args:
        user_id: User UUID
        db: Database session
        current_user: Authenticated user with required permissions

    Raises:
        HTTPException: If user not found or access denied
    """
    result = await db.execute(
        select(EnterpriseUser).where(
            EnterpriseUser.id == user_id,
            EnterpriseUser.deleted_at.is_(None)
        )
    )
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User {user_id} not found"
        )

    # Multi-tenant isolation: verify both users belong to the same organization
    if current_user.organization_id != user.organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: User does not belong to your organization"
        )

    user.soft_delete()
    await db.commit()
