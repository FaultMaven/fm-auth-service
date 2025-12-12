"""
Authentication API routes.

Provides endpoints for:
- User login (JWT generation)
- Token refresh
- User logout
- User registration
"""

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from enterprise.database import get_db
from enterprise.middleware.auth import get_current_user
from enterprise.models import EnterpriseUser, Organization
from enterprise.security import (
    create_access_token,
    create_refresh_token,
    hash_password,
    verify_password,
    verify_token,
)

router = APIRouter(prefix="/api/v1/enterprise/auth", tags=["authentication"])
security = HTTPBearer()


# Pydantic schemas
class LoginRequest(BaseModel):
    """Schema for login request."""

    email: EmailStr
    password: str = Field(..., min_length=8)


class TokenResponse(BaseModel):
    """Schema for token response."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds


class RefreshTokenRequest(BaseModel):
    """Schema for refresh token request."""

    refresh_token: str


class RegisterRequest(BaseModel):
    """Schema for user registration request."""

    organization_id: UUID
    email: EmailStr
    full_name: str = Field(..., min_length=1, max_length=255)
    password: str = Field(..., min_length=8)
    team_id: Optional[UUID] = None


class RegisterResponse(BaseModel):
    """Schema for registration response."""

    id: UUID
    email: str
    full_name: str
    organization_id: UUID
    message: str = "User registered successfully"


class MessageResponse(BaseModel):
    """Generic message response."""

    message: str


@router.post("/login", response_model=TokenResponse)
async def login(login_data: LoginRequest, db: AsyncSession = Depends(get_db)):
    """
    Authenticate user and return JWT tokens.

    Args:
        login_data: Email and password
        db: Database session

    Returns:
        Access and refresh tokens

    Raises:
        HTTPException: If credentials are invalid
    """
    # Find user by email
    result = await db.execute(
        select(EnterpriseUser).where(
            EnterpriseUser.email == login_data.email, EnterpriseUser.deleted_at.is_(None)
        )
    )
    user = result.scalar_one_or_none()

    # Verify user exists and password is correct
    if not user or not user.hashed_password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not verify_password(login_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check if user is active
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is disabled")

    # Generate tokens
    access_token = create_access_token(
        user_id=user.id, organization_id=user.organization_id, email=user.email
    )

    refresh_token = create_refresh_token(user_id=user.id)

    # Return tokens
    from enterprise.config.settings import get_settings

    settings = get_settings()

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,  # Convert to seconds
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(refresh_data: RefreshTokenRequest, db: AsyncSession = Depends(get_db)):
    """
    Refresh access token using refresh token.

    Args:
        refresh_data: Refresh token
        db: Database session

    Returns:
        New access and refresh tokens

    Raises:
        HTTPException: If refresh token is invalid
    """
    try:
        # Verify refresh token
        payload = verify_token(refresh_data.refresh_token, token_type="refresh")
        user_id = UUID(payload.get("sub"))

        # Fetch user
        result = await db.execute(
            select(EnterpriseUser).where(
                EnterpriseUser.id == user_id, EnterpriseUser.deleted_at.is_(None)
            )
        )
        user = result.scalar_one_or_none()

        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Check if user is active
        if not user.is_active:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is disabled")

        # Generate new tokens
        access_token = create_access_token(
            user_id=user.id, organization_id=user.organization_id, email=user.email
        )

        new_refresh_token = create_refresh_token(user_id=user.id)

        from enterprise.config.settings import get_settings

        settings = get_settings()

        return TokenResponse(
            access_token=access_token,
            refresh_token=new_refresh_token,
            token_type="bearer",
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        )

    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )


@router.post("/logout", response_model=MessageResponse)
async def logout(current_user: EnterpriseUser = Depends(get_current_user)):
    """
    Logout user (invalidate token).

    Note: JWT tokens are stateless, so logout is handled client-side
    by discarding the token. For server-side revocation, implement
    a token blacklist using Redis.

    Args:
        current_user: Authenticated user

    Returns:
        Success message
    """
    # TODO: Implement token blacklist in Redis for true server-side revocation
    # For now, logout is handled client-side by discarding tokens

    return MessageResponse(message="Logged out successfully. Please discard your tokens.")


@router.post("/register", response_model=RegisterResponse, status_code=status.HTTP_201_CREATED)
async def register(register_data: RegisterRequest, db: AsyncSession = Depends(get_db)):
    """
    Register a new user.

    Args:
        register_data: User registration data
        db: Database session

    Returns:
        Created user information

    Raises:
        HTTPException: If email already exists or organization not found
    """
    # Check if email already exists
    result = await db.execute(
        select(EnterpriseUser).where(
            EnterpriseUser.email == register_data.email, EnterpriseUser.deleted_at.is_(None)
        )
    )
    existing_user = result.scalar_one_or_none()

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"User with email '{register_data.email}' already exists",
        )

    # Verify organization exists
    org_result = await db.execute(
        select(Organization).where(
            Organization.id == register_data.organization_id, Organization.deleted_at.is_(None)
        )
    )
    organization = org_result.scalar_one_or_none()

    if not organization:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Organization {register_data.organization_id} not found",
        )

    # Check organization user limit
    users_result = await db.execute(
        select(EnterpriseUser).where(
            EnterpriseUser.organization_id == register_data.organization_id,
            EnterpriseUser.deleted_at.is_(None),
        )
    )
    user_count = len(users_result.scalars().all())

    if user_count >= organization.max_users:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Organization has reached maximum users limit ({organization.max_users})",
        )

    # Hash password
    hashed_password = hash_password(register_data.password)

    # Create user
    new_user = EnterpriseUser(
        organization_id=register_data.organization_id,
        team_id=register_data.team_id,
        email=register_data.email,
        full_name=register_data.full_name,
        hashed_password=hashed_password,
        is_active=True,  # Auto-activate for now (TODO: email verification)
        is_verified=False,  # Will be verified via email (TODO)
    )

    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)

    return RegisterResponse(
        id=new_user.id,
        email=new_user.email,
        full_name=new_user.full_name,
        organization_id=new_user.organization_id,
        message="User registered successfully. You can now login.",
    )


@router.get("/me", response_model=dict)
async def get_current_user_info(current_user: EnterpriseUser = Depends(get_current_user)):
    """
    Get current authenticated user information.

    Args:
        current_user: Authenticated user from JWT token

    Returns:
        User information including roles and permissions
    """
    # Collect user roles
    # Note: current_user.roles is a list of UserRole junction objects, not Role objects
    roles = []
    permissions = set()

    for user_role in current_user.roles:
        role = user_role.role
        roles.append({"id": str(role.id), "name": role.name, "description": role.description})
        for permission in role.permissions:
            permissions.add(permission.name)

    return {
        "id": str(current_user.id),
        "email": current_user.email,
        "full_name": current_user.full_name,
        "organization_id": str(current_user.organization_id),
        "team_id": str(current_user.team_id) if current_user.team_id else None,
        "is_active": current_user.is_active,
        "is_verified": current_user.is_verified,
        "sso_provider": current_user.sso_provider,
        "roles": roles,
        "permissions": sorted(list(permissions)),
    }
