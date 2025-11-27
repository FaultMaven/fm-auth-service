"""
SSO configuration API routes.

Provides CRUD operations for SSO configurations.
"""

from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from enterprise.middleware.auth import (
    get_current_active_user,
    require_org_access,
    require_org_admin,
)
from enterprise.models import EnterpriseUser, Organization, SSOConfiguration

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


# Import database session dependency
from enterprise.database import get_db


@router.post("", response_model=SSOConfigurationResponse, status_code=status.HTTP_201_CREATED)
async def create_sso_configuration(
    sso_config: SSOConfigurationCreate,
    db: AsyncSession = Depends(get_db),
    current_user: EnterpriseUser = Depends(require_org_admin),
):
    """
    Create SSO configuration for an organization.

    Requires organization admin role.

    Args:
        sso_config: SSO configuration data
        db: Database session
        current_user: Authenticated user with admin role

    Returns:
        Created SSO configuration

    Raises:
        HTTPException: If organization not found or access denied
    """
    # Multi-tenant isolation: verify user belongs to the organization
    if current_user.organization_id != sso_config.organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: You do not belong to this organization",
        )

    # Verify organization exists
    org_result = await db.execute(
        select(Organization).where(
            Organization.id == sso_config.organization_id, Organization.deleted_at.is_(None)
        )
    )
    organization = org_result.scalar_one_or_none()

    if not organization:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Organization {sso_config.organization_id} not found",
        )

    # Validate provider-specific fields
    if sso_config.provider_type == "saml":
        if not sso_config.saml_entity_id or not sso_config.saml_sso_url:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="SAML configuration requires entity_id and sso_url",
            )

    elif sso_config.provider_type in ["oauth", "oidc"]:
        if not sso_config.oauth_client_id or not sso_config.oauth_client_secret:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"{sso_config.provider_type.upper()} configuration requires client_id and client_secret",
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
    db: AsyncSession = Depends(get_db),
    current_user: EnterpriseUser = Depends(require_org_access),
):
    """
    List SSO configurations for an organization.

    Requires user to belong to the organization (multi-tenant isolation).

    Args:
        organization_id: Organization UUID
        provider_type: Optional filter by provider type
        db: Database session
        current_user: Authenticated user with organization access

    Returns:
        List of SSO configurations
    """
    query = select(SSOConfiguration).where(SSOConfiguration.organization_id == organization_id)

    if provider_type:
        query = query.where(SSOConfiguration.provider_type == provider_type)

    result = await db.execute(query)
    configs = result.scalars().all()

    return configs


@router.get("/{sso_config_id}", response_model=SSOConfigurationResponse)
async def get_sso_configuration(
    sso_config_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: EnterpriseUser = Depends(get_current_active_user),
):
    """
    Get SSO configuration by ID.

    Requires user to belong to the configuration's organization (multi-tenant isolation).

    Args:
        sso_config_id: SSO configuration UUID
        db: Database session
        current_user: Authenticated active user

    Returns:
        SSO configuration details

    Raises:
        HTTPException: If configuration not found or access denied
    """
    result = await db.execute(select(SSOConfiguration).where(SSOConfiguration.id == sso_config_id))
    sso_config = result.scalar_one_or_none()

    if not sso_config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"SSO configuration {sso_config_id} not found",
        )

    # Multi-tenant isolation: verify user belongs to the configuration's organization
    if current_user.organization_id != sso_config.organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: You do not belong to this configuration's organization",
        )

    return sso_config


@router.put("/{sso_config_id}", response_model=SSOConfigurationResponse)
async def update_sso_configuration(
    sso_config_id: UUID,
    sso_update: SSOConfigurationUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: EnterpriseUser = Depends(require_org_admin),
):
    """
    Update SSO configuration.

    Requires organization admin role and user must belong to the configuration's organization.

    Args:
        sso_config_id: SSO configuration UUID
        sso_update: Fields to update
        db: Database session
        current_user: Authenticated user with admin role

    Returns:
        Updated SSO configuration

    Raises:
        HTTPException: If configuration not found or access denied
    """
    result = await db.execute(select(SSOConfiguration).where(SSOConfiguration.id == sso_config_id))
    sso_config = result.scalar_one_or_none()

    if not sso_config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"SSO configuration {sso_config_id} not found",
        )

    # Multi-tenant isolation: verify user belongs to the configuration's organization
    if current_user.organization_id != sso_config.organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: You do not belong to this configuration's organization",
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
    db: AsyncSession = Depends(get_db),
    current_user: EnterpriseUser = Depends(require_org_admin),
):
    """
    Delete SSO configuration.

    Requires organization admin role and user must belong to the configuration's organization.

    Args:
        sso_config_id: SSO configuration UUID
        db: Database session
        current_user: Authenticated user with admin role

    Raises:
        HTTPException: If configuration not found or access denied
    """
    result = await db.execute(select(SSOConfiguration).where(SSOConfiguration.id == sso_config_id))
    sso_config = result.scalar_one_or_none()

    if not sso_config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"SSO configuration {sso_config_id} not found",
        )

    # Multi-tenant isolation: verify user belongs to the configuration's organization
    if current_user.organization_id != sso_config.organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: You do not belong to this configuration's organization",
        )

    await db.delete(sso_config)
    await db.commit()
