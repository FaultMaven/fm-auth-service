"""
Team management API routes.

Provides CRUD operations for teams within organizations.
"""

from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel, Field

from enterprise.models import Team, Organization

router = APIRouter(prefix="/api/v1/enterprise/teams", tags=["teams"])


# Pydantic schemas
class TeamCreate(BaseModel):
    """Schema for creating a new team."""
    organization_id: UUID
    name: str = Field(..., min_length=1, max_length=255)
    slug: str = Field(..., min_length=1, max_length=100, pattern=r"^[a-z0-9-]+$")
    description: Optional[str] = None


class TeamUpdate(BaseModel):
    """Schema for updating a team."""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    slug: Optional[str] = Field(None, min_length=1, max_length=100, pattern=r"^[a-z0-9-]+$")
    description: Optional[str] = None


class TeamResponse(BaseModel):
    """Schema for team response."""
    id: UUID
    organization_id: UUID
    name: str
    slug: str
    description: Optional[str]

    class Config:
        from_attributes = True


# Import database session dependency
from enterprise.database import get_db


@router.post("", response_model=TeamResponse, status_code=status.HTTP_201_CREATED)
async def create_team(
    team: TeamCreate,
    db: AsyncSession = Depends(get_db)
):
    """
    Create a new team within an organization.

    Args:
        team: Team data
        db: Database session

    Returns:
        Created team

    Raises:
        HTTPException: If organization not found or slug already exists
    """
    # Verify organization exists
    org_result = await db.execute(
        select(Organization).where(
            Organization.id == team.organization_id,
            Organization.deleted_at.is_(None)
        )
    )
    organization = org_result.scalar_one_or_none()

    if not organization:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Organization {team.organization_id} not found"
        )

    # Check team limit
    teams_result = await db.execute(
        select(Team).where(
            Team.organization_id == team.organization_id,
            Team.deleted_at.is_(None)
        )
    )
    team_count = len(teams_result.scalars().all())

    if team_count >= organization.max_teams:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Organization has reached maximum teams limit ({organization.max_teams})"
        )

    # Check if slug already exists in organization
    slug_result = await db.execute(
        select(Team).where(
            Team.organization_id == team.organization_id,
            Team.slug == team.slug,
            Team.deleted_at.is_(None)
        )
    )
    existing = slug_result.scalar_one_or_none()

    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Team with slug '{team.slug}' already exists in this organization"
        )

    # Create team
    db_team = Team(**team.model_dump())
    db.add(db_team)
    await db.commit()
    await db.refresh(db_team)

    return db_team


@router.get("/organization/{organization_id}", response_model=List[TeamResponse])
async def list_organization_teams(
    organization_id: UUID,
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db)
):
    """
    List teams for an organization.

    Args:
        organization_id: Organization UUID
        skip: Number of records to skip
        limit: Maximum number of records to return
        db: Database session

    Returns:
        List of teams
    """
    query = select(Team).where(
        Team.organization_id == organization_id,
        Team.deleted_at.is_(None)
    ).offset(skip).limit(limit)

    result = await db.execute(query)
    teams = result.scalars().all()

    return teams


@router.get("/{team_id}", response_model=TeamResponse)
async def get_team(
    team_id: UUID,
    db: AsyncSession = Depends(get_db)
):
    """
    Get team by ID.

    Args:
        team_id: Team UUID
        db: Database session

    Returns:
        Team details

    Raises:
        HTTPException: If team not found
    """
    result = await db.execute(
        select(Team).where(
            Team.id == team_id,
            Team.deleted_at.is_(None)
        )
    )
    team = result.scalar_one_or_none()

    if not team:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Team {team_id} not found"
        )

    return team


@router.put("/{team_id}", response_model=TeamResponse)
async def update_team(
    team_id: UUID,
    team_update: TeamUpdate,
    db: AsyncSession = Depends(get_db)
):
    """
    Update team.

    Args:
        team_id: Team UUID
        team_update: Fields to update
        db: Database session

    Returns:
        Updated team

    Raises:
        HTTPException: If team not found or slug conflict
    """
    result = await db.execute(
        select(Team).where(
            Team.id == team_id,
            Team.deleted_at.is_(None)
        )
    )
    team = result.scalar_one_or_none()

    if not team:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Team {team_id} not found"
        )

    # Check slug uniqueness if being updated
    update_data = team_update.model_dump(exclude_unset=True)
    if "slug" in update_data and update_data["slug"] != team.slug:
        slug_result = await db.execute(
            select(Team).where(
                Team.organization_id == team.organization_id,
                Team.slug == update_data["slug"],
                Team.id != team_id,
                Team.deleted_at.is_(None)
            )
        )
        existing = slug_result.scalar_one_or_none()

        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Team with slug '{update_data['slug']}' already exists in this organization"
            )

    # Update fields
    for field, value in update_data.items():
        setattr(team, field, value)

    await db.commit()
    await db.refresh(team)

    return team


@router.delete("/{team_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_team(
    team_id: UUID,
    db: AsyncSession = Depends(get_db)
):
    """
    Soft delete team.

    Args:
        team_id: Team UUID
        db: Database session

    Raises:
        HTTPException: If team not found
    """
    result = await db.execute(
        select(Team).where(
            Team.id == team_id,
            Team.deleted_at.is_(None)
        )
    )
    team = result.scalar_one_or_none()

    if not team:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Team {team_id} not found"
        )

    team.soft_delete()
    await db.commit()
