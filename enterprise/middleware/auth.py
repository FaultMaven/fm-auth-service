"""
JWT authentication and RBAC authorization middleware.

Provides FastAPI dependencies for:
- JWT token validation
- User authentication
- Permission-based authorization
- Organization-level access control
"""

from typing import List, Optional
from uuid import UUID

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from enterprise.config.settings import get_settings
from enterprise.database import get_db
from enterprise.models import EnterpriseUser, Organization, Role, Permission


# HTTP Bearer token scheme
security = HTTPBearer()

# Get settings
settings = get_settings()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db)
) -> EnterpriseUser:
    """
    Validate JWT token and return current user.

    Args:
        credentials: HTTP Authorization header with Bearer token
        db: Database session

    Returns:
        Authenticated user

    Raises:
        HTTPException: If token is invalid or user not found
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    token = credentials.credentials

    try:
        # Decode JWT token
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM]
        )
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception

    except JWTError:
        raise credentials_exception

    # Fetch user from database with relationships
    stmt = (
        select(EnterpriseUser)
        .options(
            selectinload(EnterpriseUser.organization),
            selectinload(EnterpriseUser.teams),
            selectinload(EnterpriseUser.roles).selectinload(Role.permissions)
        )
        .where(EnterpriseUser.id == UUID(user_id))
    )
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if user is None:
        raise credentials_exception

    return user


async def get_current_active_user(
    current_user: EnterpriseUser = Depends(get_current_user)
) -> EnterpriseUser:
    """
    Get current user and verify they are active.

    Args:
        current_user: Authenticated user

    Returns:
        Active user

    Raises:
        HTTPException: If user is inactive
    """
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user"
        )
    return current_user


def require_permissions(*permission_names: str):
    """
    Dependency factory for permission-based authorization.

    Usage:
        @router.get("/admin", dependencies=[Depends(require_permissions("users:admin"))])
        async def admin_endpoint():
            ...

    Args:
        *permission_names: Required permission names (e.g., "organizations:create")

    Returns:
        FastAPI dependency function

    Raises:
        HTTPException: If user doesn't have required permissions
    """
    async def permission_checker(
        current_user: EnterpriseUser = Depends(get_current_active_user)
    ):
        # Get all user permissions from their roles
        user_permissions = set()
        for role in current_user.roles:
            for permission in role.permissions:
                user_permissions.add(permission.name)

        # Check if user has all required permissions
        for required_permission in permission_names:
            if required_permission not in user_permissions:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Permission denied: {required_permission} required"
                )

        return current_user

    return permission_checker


async def require_org_admin(
    current_user: EnterpriseUser = Depends(get_current_active_user)
) -> EnterpriseUser:
    """
    Require user to be an admin of their organization.

    Args:
        current_user: Authenticated user

    Returns:
        User (if they are org admin)

    Raises:
        HTTPException: If user is not an org admin
    """
    # Check if user has admin role for their organization
    is_admin = False
    for role in current_user.roles:
        if role.name == "Admin" and role.organization_id == current_user.organization_id:
            is_admin = True
            break

    if not is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Organization admin access required"
        )

    return current_user


class OrganizationAccessChecker:
    """
    Dependency class for organization-level access control.

    Ensures user belongs to the specified organization by checking
    against the organization_id path parameter.

    Usage:
        @router.get("/orgs/{organization_id}/users")
        async def get_org_users(
            organization_id: UUID,
            user: EnterpriseUser = Depends(OrganizationAccessChecker())
        ):
            ...
    """

    def __call__(
        self,
        organization_id: UUID,
        current_user: EnterpriseUser = Depends(get_current_active_user)
    ) -> EnterpriseUser:
        """
        Check if user belongs to the organization.

        Args:
            organization_id: Organization ID from path parameter
            current_user: Authenticated user

        Returns:
            Current user if they belong to the organization

        Raises:
            HTTPException: If user doesn't belong to the organization
        """
        if current_user.organization_id != organization_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: You do not belong to this organization"
            )
        return current_user


# Create singleton instance for use as dependency
require_org_access = OrganizationAccessChecker()


async def get_org_from_user(
    current_user: EnterpriseUser = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
) -> Organization:
    """
    Get the organization of the current user.

    Useful for scoping queries to the user's organization (multi-tenant isolation).

    Args:
        current_user: Authenticated user
        db: Database session

    Returns:
        User's organization

    Raises:
        HTTPException: If organization not found
    """
    stmt = select(Organization).where(Organization.id == current_user.organization_id)
    result = await db.execute(stmt)
    organization = result.scalar_one_or_none()

    if organization is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found"
        )

    return organization
