"""Authentication Routes

Purpose: FastAPI routes for authentication operations

This module provides authentication endpoints extracted from FaultMaven monolith.
Adapted for microservice architecture with simplified dependencies.

Key Endpoints:
- POST /auth/dev-login: Development login with username
- POST /auth/dev-register: Development registration
- POST /auth/logout: Token revocation
- GET /auth/me: Current user profile
- GET /auth/health: Authentication system health
"""

import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Response
from fastapi.security import HTTPBearer

from auth_service.domain.models import (
    AuthTokenResponse,
    DevLoginRequest,
    DevUser,
    LogoutResponse,
    TokenStatus,
    UserInfoResponse,
    UserProfile,
    to_json_compatible,
)
from auth_service.infrastructure.auth.token_manager import DevTokenManager
from auth_service.infrastructure.auth.user_store import DevUserStore
from auth_service.infrastructure.redis.client import get_redis_client

# Initialize router and logger
router = APIRouter(prefix="/api/v1/auth", tags=["authentication"])
logger = logging.getLogger(__name__)

# Security scheme for OpenAPI documentation
security = HTTPBearer(auto_error=False)


# Dependency injection functions
async def get_token_manager() -> DevTokenManager:
    """Get token manager instance"""
    redis_client = await get_redis_client()
    return DevTokenManager(redis_client.get_client())


async def get_user_store() -> DevUserStore:
    """Get user store instance"""
    redis_client = await get_redis_client()
    return DevUserStore(redis_client.get_client())


async def extract_bearer_token(
    authorization: Optional[str] = Header(None, alias="Authorization")
) -> Optional[str]:
    """Extract Bearer token from Authorization header"""
    if not authorization:
        return None

    if not authorization.startswith("Bearer "):
        return None

    token = authorization[7:]  # Remove "Bearer " prefix
    if not token.strip():
        return None

    return token.strip()


async def get_current_user_optional(
    token: Optional[str] = Depends(extract_bearer_token),
    token_manager: DevTokenManager = Depends(get_token_manager),
    user_store: DevUserStore = Depends(get_user_store),
) -> Optional[DevUser]:
    """Get current user from token (optional - no error if missing/invalid)"""
    if not token:
        return None

    try:
        validation_result = await token_manager.validate_token(token, user_store)

        if validation_result.is_valid and validation_result.user:
            logger.debug(f"User authenticated: {validation_result.user.user_id}")
            return validation_result.user
        else:
            logger.debug(f"Token validation failed: {validation_result.error_message}")
            return None

    except Exception as e:
        correlation_id = str(uuid.uuid4())
        logger.warning(f"Unexpected error in optional auth: {e} (correlation: {correlation_id})")
        return None


async def require_authentication(
    user: Optional[DevUser] = Depends(get_current_user_optional),
) -> DevUser:
    """Require authenticated user (raises 401 if not authenticated)"""
    if not user:
        correlation_id = str(uuid.uuid4())
        logger.info(f"Authentication required but not provided (correlation: {correlation_id})")
        raise HTTPException(
            status_code=401,
            detail="Authentication required. Please log in to access this resource.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    logger.debug(f"Authentication successful for user: {user.user_id}")
    return user


# Authentication endpoints


@router.post("/dev-login", response_model=AuthTokenResponse, status_code=200)
async def dev_login(
    request: DevLoginRequest,
    response: Response,
    user_store: DevUserStore = Depends(get_user_store),
    token_manager: DevTokenManager = Depends(get_token_manager),
) -> AuthTokenResponse:
    """Development login endpoint

    Authenticates existing users and generates authentication tokens.
    """
    correlation_id = str(uuid.uuid4())

    try:
        # Try to find existing user
        user = await user_store.get_user_by_username(request.username)

        if user:
            logger.info(
                f"User login: {request.username} (existing user: {user.user_id})",
                extra={
                    "user_id": user.user_id,
                    "username": request.username,
                    "correlation_id": correlation_id,
                },
            )
        else:
            # User doesn't exist - return authentication error
            logger.warning(
                f"Login attempt for non-existent user: {request.username}",
                extra={"username": request.username, "correlation_id": correlation_id},
            )
            raise HTTPException(
                status_code=401,
                detail={
                    "error": "authentication_failed",
                    "message": f"User '{request.username}' does not exist. Please check the username or register a new account.",
                    "username": request.username,
                },
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Generate authentication token
        access_token = await token_manager.create_token(user)

        # Build response
        user_profile = UserProfile(
            user_id=user.user_id,
            username=user.username,
            email=user.email,
            display_name=user.display_name,
            created_at=to_json_compatible(user.created_at),
            is_dev_user=user.is_dev_user,
            roles=user.roles if user.roles else ["admin"],
        )

        token_response = AuthTokenResponse(
            access_token=access_token,
            token_type="bearer",
            expires_in=24 * 60 * 60,  # 24 hours in seconds
            user=user_profile,
        )

        # Set correlation ID in response headers
        response.headers["X-Correlation-Id"] = correlation_id

        logger.info(f"Login successful for user {user.user_id} (correlation: {correlation_id})")
        return token_response

    except HTTPException:
        raise
    except ValueError as e:
        logger.warning(
            f"Login validation error: {str(e)}",
            extra={"username": request.username, "correlation_id": correlation_id},
        )
        raise HTTPException(
            status_code=400,
            detail={"error": "validation_error", "message": str(e), "username": request.username},
        )
    except Exception as e:
        logger.error(
            f"Dev login failed: {type(e).__name__}: {str(e)}",
            extra={"correlation_id": correlation_id},
            exc_info=True,
        )
        raise HTTPException(
            status_code=500,
            detail={
                "error": "internal_error",
                "message": "Login failed due to an internal error. Please try again later.",
            },
        )


@router.post("/dev-register", response_model=AuthTokenResponse, status_code=201)
async def dev_register(
    request: DevLoginRequest,
    response: Response,
    user_store: DevUserStore = Depends(get_user_store),
    token_manager: DevTokenManager = Depends(get_token_manager),
) -> AuthTokenResponse:
    """Development registration endpoint

    Creates a new user account and generates an authentication token.
    """
    correlation_id = str(uuid.uuid4())

    try:
        # Check if user already exists
        existing_user = await user_store.get_user_by_username(request.username)
        if existing_user:
            logger.warning(f"Registration attempt for existing user: {request.username}")
            raise HTTPException(
                status_code=409,
                detail=f"User with username '{request.username}' already exists. Please use login instead.",
            )

        # Create new user
        user = await user_store.create_user(
            username=request.username, email=request.email, display_name=request.display_name
        )
        logger.info(f"User registration: {request.username} (new user: {user.user_id})")

        # Generate authentication token
        access_token = await token_manager.create_token(user)

        # Build response
        user_profile = UserProfile(
            user_id=user.user_id,
            username=user.username,
            email=user.email,
            display_name=user.display_name,
            created_at=to_json_compatible(user.created_at),
            is_dev_user=user.is_dev_user,
            roles=user.roles if user.roles else ["admin"],
        )

        token_response = AuthTokenResponse(
            access_token=access_token,
            token_type="bearer",
            expires_in=24 * 60 * 60,  # 24 hours in seconds
            user=user_profile,
        )

        # Set correlation ID in response headers
        response.headers["X-Correlation-Id"] = correlation_id

        logger.info(
            f"Registration successful for user {user.user_id} (correlation: {correlation_id})"
        )
        return token_response

    except HTTPException:
        raise
    except ValueError as e:
        logger.warning(
            f"Registration validation error: {str(e)}",
            extra={"username": request.username, "correlation_id": correlation_id},
        )
        raise HTTPException(
            status_code=400,
            detail={"error": "validation_error", "message": str(e), "username": request.username},
        )
    except Exception as e:
        logger.error(
            f"Dev registration failed: {type(e).__name__}: {str(e)}",
            extra={"correlation_id": correlation_id},
            exc_info=True,
        )
        raise HTTPException(
            status_code=500,
            detail={
                "error": "internal_error",
                "message": "Registration failed due to an internal error. Please try again later.",
            },
        )


@router.post("/logout", response_model=LogoutResponse)
async def logout(
    current_user: DevUser = Depends(require_authentication),
    token: str = Depends(extract_bearer_token),
    token_manager: DevTokenManager = Depends(get_token_manager),
) -> LogoutResponse:
    """Logout current user

    Revokes the current authentication token.
    """
    correlation_id = str(uuid.uuid4())

    try:
        # Revoke the current token
        success = await token_manager.revoke_token(token)

        if success:
            logger.info(f"User logout: {current_user.user_id} (correlation: {correlation_id})")
            return LogoutResponse(message="Logged out successfully", revoked_tokens=1)
        else:
            logger.warning(f"Token revocation failed for user {current_user.user_id}")
            raise HTTPException(status_code=500, detail="Logout failed: Could not revoke token")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Logout failed: {e} (correlation: {correlation_id})")
        raise HTTPException(status_code=500, detail=f"Logout failed: {str(e)}")


@router.get("/me", response_model=UserInfoResponse)
async def get_current_user_profile(
    current_user: DevUser = Depends(require_authentication),
    token_manager: DevTokenManager = Depends(get_token_manager),
) -> UserInfoResponse:
    """Get current user profile

    Returns detailed information about the currently authenticated user.
    """
    correlation_id = str(uuid.uuid4())

    try:
        # Get user's active tokens for statistics
        user_tokens = await token_manager.get_user_tokens(current_user.user_id)
        active_token_count = len([token for token in user_tokens if token.is_valid])

        # Build extended user profile
        user_info = UserInfoResponse(
            user_id=current_user.user_id,
            username=current_user.username,
            email=current_user.email,
            display_name=current_user.display_name,
            created_at=to_json_compatible(current_user.created_at),
            is_dev_user=current_user.is_dev_user,
            roles=current_user.roles if current_user.roles else ["admin"],
            last_login=None,  # TODO: Implement last login tracking
            token_count=active_token_count,
        )

        logger.debug(
            f"User profile requested: {current_user.user_id} (correlation: {correlation_id})"
        )
        return user_info

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get user profile failed: {e} (correlation: {correlation_id})")
        raise HTTPException(status_code=500, detail=f"Could not retrieve user profile: {str(e)}")


@router.get("/health")
async def auth_health_check():
    """Authentication system health check

    Returns the status of authentication services.
    """
    try:
        redis_client = await get_redis_client()
        redis_healthy = await redis_client.health_check()

        health_status = {
            "status": "healthy" if redis_healthy else "degraded",
            "timestamp": to_json_compatible(datetime.now(timezone.utc)),
            "services": {
                "redis": "healthy" if redis_healthy else "unhealthy",
                "token_manager": "available",
                "user_store": "available",
            },
        }

        return health_status

    except Exception as e:
        logger.error(f"Auth health check failed: {e}")
        return {
            "status": "unhealthy",
            "timestamp": to_json_compatible(datetime.now(timezone.utc)),
            "error": str(e),
        }


# Optional: Debug endpoint for development (remove in production)
@router.post("/dev/revoke-all-tokens", response_model=LogoutResponse)
async def dev_revoke_all_user_tokens(
    current_user: DevUser = Depends(require_authentication),
    token_manager: DevTokenManager = Depends(get_token_manager),
) -> LogoutResponse:
    """Development endpoint: Revoke all tokens for current user

    WARNING: This endpoint is for development use only.
    """
    correlation_id = str(uuid.uuid4())

    try:
        # Revoke all user tokens
        revoked_count = await token_manager.revoke_user_tokens(current_user.user_id)

        logger.info(
            f"Dev: Revoked all tokens for user {current_user.user_id}, count: {revoked_count} (correlation: {correlation_id})"
        )

        return LogoutResponse(
            message=f"Revoked all {revoked_count} tokens for user", revoked_tokens=revoked_count
        )

    except Exception as e:
        logger.error(f"Dev token revocation failed: {e} (correlation: {correlation_id})")
        raise HTTPException(status_code=500, detail=f"Token revocation failed: {str(e)}")
