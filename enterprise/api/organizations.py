"""
Organization management API routes.

Provides CRUD operations for organizations (tenants).
"""

from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel, Field

from enterprise.models import Organization

router = APIRouter(prefix="/api/v1/enterprise/organizations", tags=["organizations"])


# Pydantic schemas
class OrganizationCreate(BaseModel):
    """Schema for creating a new organization."""
    name: str = Field(..., min_length=1, max_length=255)
    slug: str = Field(..., min_length=1, max_length=100, pattern=r"^[a-z0-9-]+$")
    plan: str = Field(default="trial", pattern=r"^(trial|starter|professional|enterprise)$")
    contact_email: Optional[str] = None
    contact_name: Optional[str] = None
    max_users: int = Field(default=10, ge=1)
    max_teams: int = Field(default=5, ge=1)


class OrganizationUpdate(BaseModel):
    """Schema for updating an organization."""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    plan: Optional[str] = Field(None, pattern=r"^(trial|starter|professional|enterprise)$")
    contact_email: Optional[str] = None
    contact_name: Optional[str] = None
    max_users: Optional[int] = Field(None, ge=1)
    max_teams: Optional[int] = Field(None, ge=1)
    is_active: Optional[bool] = None


class OrganizationResponse(BaseModel):
    """Schema for organization response."""
    id: UUID
    name: str
    slug: str
    plan: str
    is_active: bool
    max_users: int
    max_teams: int
    contact_email: Optional[str]
    contact_name: Optional[str]

    class Config:
        from_attributes = True


# Dependency for database session (placeholder - will be implemented with actual DB setup)
async def get_db() -> AsyncSession:
    """
    Get database session.

    TODO: Implement actual database session management with connection pooling.
    """
    raise NotImplementedError("Database session not configured")


@router.post("", response_model=OrganizationResponse, status_code=status.HTTP_201_CREATED)
async def create_organization(
    organization: OrganizationCreate,
    db: AsyncSession = Depends(get_db)
):
    """
    Create a new organization.

    Creates a new tenant organization in the multi-tenant SaaS.

    Args:
        organization: Organization data
        db: Database session

    Returns:
        Created organization

    Raises:
        HTTPException: If organization with slug already exists
    """
    # Check if slug already exists
    result = await db.execute(
        select(Organization).where(Organization.slug == organization.slug)
    )
    existing = result.scalar_one_or_none()

    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Organization with slug '{organization.slug}' already exists"
        )

    # Create organization
    db_org = Organization(**organization.model_dump())
    db.add(db_org)
    await db.commit()
    await db.refresh(db_org)

    return db_org


@router.get("", response_model=List[OrganizationResponse])
async def list_organizations(
    skip: int = 0,
    limit: int = 100,
    is_active: Optional[bool] = None,
    db: AsyncSession = Depends(get_db)
):
    """
    List organizations.

    Returns paginated list of organizations with optional filtering.

    Args:
        skip: Number of records to skip (pagination)
        limit: Maximum number of records to return
        is_active: Filter by active status
        db: Database session

    Returns:
        List of organizations
    """
    query = select(Organization).where(Organization.deleted_at.is_(None))

    if is_active is not None:
        query = query.where(Organization.is_active == is_active)

    query = query.offset(skip).limit(limit)
    result = await db.execute(query)
    organizations = result.scalars().all()

    return organizations


@router.get("/{organization_id}", response_model=OrganizationResponse)
async def get_organization(
    organization_id: UUID,
    db: AsyncSession = Depends(get_db)
):
    """
    Get organization by ID.

    Args:
        organization_id: Organization UUID
        db: Database session

    Returns:
        Organization details

    Raises:
        HTTPException: If organization not found
    """
    result = await db.execute(
        select(Organization).where(
            Organization.id == organization_id,
            Organization.deleted_at.is_(None)
        )
    )
    organization = result.scalar_one_or_none()

    if not organization:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Organization {organization_id} not found"
        )

    return organization


@router.put("/{organization_id}", response_model=OrganizationResponse)
async def update_organization(
    organization_id: UUID,
    organization_update: OrganizationUpdate,
    db: AsyncSession = Depends(get_db)
):
    """
    Update organization.

    Args:
        organization_id: Organization UUID
        organization_update: Fields to update
        db: Database session

    Returns:
        Updated organization

    Raises:
        HTTPException: If organization not found
    """
    result = await db.execute(
        select(Organization).where(
            Organization.id == organization_id,
            Organization.deleted_at.is_(None)
        )
    )
    organization = result.scalar_one_or_none()

    if not organization:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Organization {organization_id} not found"
        )

    # Update fields
    update_data = organization_update.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(organization, field, value)

    await db.commit()
    await db.refresh(organization)

    return organization


@router.delete("/{organization_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_organization(
    organization_id: UUID,
    db: AsyncSession = Depends(get_db)
):
    """
    Soft delete organization.

    Marks organization as deleted without actually removing from database.

    Args:
        organization_id: Organization UUID
        db: Database session

    Raises:
        HTTPException: If organization not found
    """
    result = await db.execute(
        select(Organization).where(
            Organization.id == organization_id,
            Organization.deleted_at.is_(None)
        )
    )
    organization = result.scalar_one_or_none()

    if not organization:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Organization {organization_id} not found"
        )

    organization.soft_delete()
    await db.commit()
