"""
SSO configuration API routes.

Provides CRUD operations for SSO configurations.
"""

from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel, Field

from enterprise.models import SSOConfiguration, Organization

router = APIRouter(prefix="/api/v1/enterprise/sso", tags=["sso"])


# Pydantic schemas
class SSOConfigurationCreate(BaseModel):
    """Schema for creating SSO configuration."""
    organization_id: UUID
    provider_type: str = Field(..., pattern=r"^(saml|oauth|oidc)$")
    provider_name: str = Field(..., min_length=1, max_length=255)
    is_enabled: bool = True

    # SAML fields
    saml_entity_id: Optional[str] = None
    saml_sso_url: Optional[str] = None
    saml_slo_url: Optional[str] = None
    saml_x509_cert: Optional[str] = None
    saml_name_id_format: Optional[str] = None

    # OAuth/OIDC fields
    oauth_client_id: Optional[str] = None
    oauth_client_secret: Optional[str] = None
    oauth_authorization_url: Optional[str] = None
    oauth_token_url: Optional[str] = None
    oauth_userinfo_url: Optional[str] = None
    oauth_scopes: Optional[str] = None

    # OIDC-specific
    oidc_issuer: Optional[str] = None
    oidc_jwks_uri: Optional[str] = None

    # Configuration
    attribute_mapping: Optional[dict] = None
    auto_create_users: bool = True
    default_role_id: Optional[UUID] = None


class SSOConfigurationUpdate(BaseModel):
    """Schema for updating SSO configuration."""
    provider_name: Optional[str] = Field(None, min_length=1, max_length=255)
    is_enabled: Optional[bool] = None
    saml_entity_id: Optional[str] = None
    saml_sso_url: Optional[str] = None
    saml_slo_url: Optional[str] = None
    saml_x509_cert: Optional[str] = None
    oauth_client_id: Optional[str] = None
    oauth_client_secret: Optional[str] = None
    attribute_mapping: Optional[dict] = None
    auto_create_users: Optional[bool] = None


class SSOConfigurationResponse(BaseModel):
    """Schema for SSO configuration response."""
    id: UUID
    organization_id: UUID
    provider_type: str
    provider_name: str
    is_enabled: bool
    auto_create_users: bool

    # SAML fields (excluding sensitive cert)
    saml_entity_id: Optional[str]
    saml_sso_url: Optional[str]

    # OAuth fields (excluding secret)
    oauth_client_id: Optional[str]
    oauth_authorization_url: Optional[str]

    # OIDC fields
    oidc_issuer: Optional[str]

    class Config:
        from_attributes = True


# Dependency placeholder
async def get_db() -> AsyncSession:
    """Get database session."""
    raise NotImplementedError("Database session not configured")


@router.post("", response_model=SSOConfigurationResponse, status_code=status.HTTP_201_CREATED)
async def create_sso_configuration(
    sso_config: SSOConfigurationCreate,
    db: AsyncSession = Depends(get_db)
):
    """
    Create SSO configuration for an organization.

    Args:
        sso_config: SSO configuration data
        db: Database session

    Returns:
        Created SSO configuration

    Raises:
        HTTPException: If organization not found
    """
    # Verify organization exists
    org_result = await db.execute(
        select(Organization).where(
            Organization.id == sso_config.organization_id,
            Organization.deleted_at.is_(None)
        )
    )
    organization = org_result.scalar_one_or_none()

    if not organization:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Organization {sso_config.organization_id} not found"
        )

    # Validate provider-specific fields
    if sso_config.provider_type == "saml":
        if not sso_config.saml_entity_id or not sso_config.saml_sso_url:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="SAML configuration requires entity_id and sso_url"
            )

    elif sso_config.provider_type in ["oauth", "oidc"]:
        if not sso_config.oauth_client_id or not sso_config.oauth_client_secret:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"{sso_config.provider_type.upper()} configuration requires client_id and client_secret"
            )

    # Create SSO configuration
    db_sso = SSOConfiguration(**sso_config.model_dump())
    db.add(db_sso)
    await db.commit()
    await db.refresh(db_sso)

    return db_sso


@router.get("/organization/{organization_id}", response_model=List[SSOConfigurationResponse])
async def list_organization_sso_configurations(
    organization_id: UUID,
    provider_type: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """
    List SSO configurations for an organization.

    Args:
        organization_id: Organization UUID
        provider_type: Optional filter by provider type
        db: Database session

    Returns:
        List of SSO configurations
    """
    query = select(SSOConfiguration).where(
        SSOConfiguration.organization_id == organization_id
    )

    if provider_type:
        query = query.where(SSOConfiguration.provider_type == provider_type)

    result = await db.execute(query)
    configs = result.scalars().all()

    return configs


@router.get("/{sso_config_id}", response_model=SSOConfigurationResponse)
async def get_sso_configuration(
    sso_config_id: UUID,
    db: AsyncSession = Depends(get_db)
):
    """
    Get SSO configuration by ID.

    Args:
        sso_config_id: SSO configuration UUID
        db: Database session

    Returns:
        SSO configuration details

    Raises:
        HTTPException: If configuration not found
    """
    result = await db.execute(
        select(SSOConfiguration).where(SSOConfiguration.id == sso_config_id)
    )
    sso_config = result.scalar_one_or_none()

    if not sso_config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"SSO configuration {sso_config_id} not found"
        )

    return sso_config


@router.put("/{sso_config_id}", response_model=SSOConfigurationResponse)
async def update_sso_configuration(
    sso_config_id: UUID,
    sso_update: SSOConfigurationUpdate,
    db: AsyncSession = Depends(get_db)
):
    """
    Update SSO configuration.

    Args:
        sso_config_id: SSO configuration UUID
        sso_update: Fields to update
        db: Database session

    Returns:
        Updated SSO configuration

    Raises:
        HTTPException: If configuration not found
    """
    result = await db.execute(
        select(SSOConfiguration).where(SSOConfiguration.id == sso_config_id)
    )
    sso_config = result.scalar_one_or_none()

    if not sso_config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"SSO configuration {sso_config_id} not found"
        )

    # Update fields
    update_data = sso_update.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(sso_config, field, value)

    await db.commit()
    await db.refresh(sso_config)

    return sso_config


@router.delete("/{sso_config_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_sso_configuration(
    sso_config_id: UUID,
    db: AsyncSession = Depends(get_db)
):
    """
    Delete SSO configuration.

    Args:
        sso_config_id: SSO configuration UUID
        db: Database session

    Raises:
        HTTPException: If configuration not found
    """
    result = await db.execute(
        select(SSOConfiguration).where(SSOConfiguration.id == sso_config_id)
    )
    sso_config = result.scalar_one_or_none()

    if not sso_config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"SSO configuration {sso_config_id} not found"
        )

    await db.delete(sso_config)
    await db.commit()
