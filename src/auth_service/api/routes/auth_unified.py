"""Unified Authentication Routes (Deployment Neutral).

Supports both local (username/password) and OIDC/SAML authentication
via pluggable provider system. Provider is selected at runtime via
AUTH_PROVIDER environment variable.

Key Endpoints:
- GET /api/v1/auth/config: Get auth configuration (tells client which mode)
- POST /api/v1/auth/login: Local auth login OR OIDC initiation
- GET /api/v1/auth/callback: OIDC/SAML callback handler
- POST /api/v1/auth/refresh: Refresh access token
- POST /api/v1/auth/logout: Logout (revoke tokens)
- GET /api/v1/auth/me: Get current user info
"""

import logging
import secrets
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Response, Query, status
from pydantic import BaseModel, EmailStr, Field

from auth_service.core.auth import get_auth_provider, AuthProvider, UserIdentity
from auth_service.core.auth.local import LocalAuthProvider, AuthenticationError
from auth_service.infrastructure.redis.client import get_redis_client

router = APIRouter(prefix="/api/v1/auth", tags=["authentication"])
logger = logging.getLogger(__name__)


# ============================================================================
# Request/Response Models
# ============================================================================

class AuthConfigResponse(BaseModel):
    """Auth configuration response (tells client which mode to use)."""
    provider: str  # 'local', 'oidc', 'saml'
    login_url: Optional[str] = None  # For OIDC/SAML, the redirect URL
    features: dict = Field(default_factory=dict)


class LoginRequest(BaseModel):
    """Local auth login request."""
    email: EmailStr
    password: str


class LoginResponse(BaseModel):
    """Successful login response."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds
    user: dict


class OIDCInitiateResponse(BaseModel):
    """OIDC login initiation response."""
    authorization_url: str
    state: str
    code_challenge: Optional[str] = None  # For PKCE (browser extensions)


class RefreshRequest(BaseModel):
    """Token refresh request."""
    refresh_token: str


class LogoutRequest(BaseModel):
    """Logout request."""
    token: Optional[str] = None


# ============================================================================
# Helper Functions
# ============================================================================

async def extract_bearer_token(
    authorization: Optional[str] = Header(None, alias="Authorization")
) -> Optional[str]:
    """Extract Bearer token from Authorization header."""
    if not authorization or not authorization.startswith("Bearer "):
        return None
    return authorization[7:].strip()


async def get_current_user(
    token: Optional[str] = Depends(extract_bearer_token),
    provider: AuthProvider = Depends(get_auth_provider)
) -> UserIdentity:
    """Get current authenticated user from token."""
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication token"
        )

    try:
        return await provider.validate_token(token)
    except AuthenticationError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )


# ============================================================================
# Endpoints
# ============================================================================

@router.get("/config", response_model=AuthConfigResponse)
async def get_auth_config(provider: AuthProvider = Depends(get_auth_provider)):
    """Get authentication configuration.

    This endpoint tells the client (browser extension, dashboard) which
    authentication mode is active and how to authenticate.

    Returns:
        Auth configuration with provider type and features
    """
    provider_name = provider.__class__.__name__.replace("AuthProvider", "").lower()

    config = AuthConfigResponse(
        provider=provider_name,
        features={
            "supports_registration": isinstance(provider, LocalAuthProvider),
            "supports_password_reset": isinstance(provider, LocalAuthProvider),
            "supports_email_verification": False,  # Future feature
            "requires_redirect": provider_name in ["oidc", "saml"]
        }
    )

    logger.info(f"Auth config requested: provider={provider_name}")
    return config


@router.post("/login")
async def login(
    request: LoginRequest,
    provider: AuthProvider = Depends(get_auth_provider)
):
    """Authenticate user (local mode only).

    For local auth: Validates email/password and returns JWT tokens.
    For OIDC/SAML: This endpoint is not used (use /login/initiate instead).

    Args:
        request: Login credentials

    Returns:
        Access token, refresh token, and user information

    Raises:
        HTTPException: If credentials are invalid or provider doesn't support local auth
    """
    if not isinstance(provider, LocalAuthProvider):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Local login not supported in {provider.__class__.__name__} mode. "
                   f"Use /login/initiate for OAuth/OIDC."
        )

    try:
        # Authenticate user
        user_identity = await provider.authenticate_user(request.email, request.password)

        return LoginResponse(
            access_token=user_identity.metadata["access_token"],
            refresh_token=user_identity.metadata["refresh_token"],
            token_type="bearer",
            expires_in=user_identity.metadata["expires_in"],
            user={
                "user_id": user_identity.user_id,
                "email": user_identity.email,
                "username": user_identity.username,
                "display_name": user_identity.display_name,
                "roles": user_identity.roles
            }
        )

    except AuthenticationError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )


@router.post("/login/initiate", response_model=OIDCInitiateResponse)
async def initiate_oidc_login(
    redirect_uri: str = Query(..., description="Callback URL after authentication"),
    code_challenge: Optional[str] = Query(None, description="PKCE code challenge"),
    code_challenge_method: Optional[str] = Query("S256", description="PKCE challenge method"),
    provider: AuthProvider = Depends(get_auth_provider)
):
    """Initiate OIDC/SAML authentication flow.

    For OIDC/SAML: Returns authorization URL to redirect user to.
    For local auth: This endpoint returns an error.

    Args:
        redirect_uri: URL to redirect back to after authentication
        code_challenge: PKCE code challenge (for browser extensions)
        code_challenge_method: PKCE challenge method (usually S256)

    Returns:
        Authorization URL and state parameter

    Raises:
        HTTPException: If provider doesn't support OAuth/OIDC
    """
    if isinstance(provider, LocalAuthProvider):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OIDC login not supported in local auth mode. Use /login instead."
        )

    # Generate CSRF state
    state = secrets.token_urlsafe(32)

    # Get authorization URL from provider
    auth_url = await provider.get_login_url(
        state=state,
        redirect_uri=redirect_uri,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method
    )

    # Store state and redirect_uri in Redis for CSRF validation in /callback
    # This prevents attackers from using a valid code with a different redirect_uri
    try:
        redis_client = await get_redis_client()
        await redis_client.get_client().setex(
            f"oidc_state:{state}",
            300,  # 5 minutes TTL
            redirect_uri
        )
        logger.info(f"OIDC login initiated: redirect_uri={redirect_uri}, state stored")
    except Exception as e:
        logger.warning(f"Failed to store OIDC state in Redis: {e}. Proceeding without state validation.")

    return OIDCInitiateResponse(
        authorization_url=auth_url,
        state=state,
        code_challenge=code_challenge
    )


@router.get("/callback")
async def oidc_callback(
    code: str = Query(..., description="Authorization code from provider"),
    state: str = Query(..., description="CSRF protection state"),
    code_verifier: Optional[str] = Query(None, description="PKCE code verifier"),
    provider: AuthProvider = Depends(get_auth_provider)
):
    """Handle OIDC/SAML callback after user authentication.

    This endpoint is called by the OIDC provider after user authenticates.
    It exchanges the authorization code for user information and JWT tokens.

    Args:
        code: Authorization code from OIDC provider
        state: CSRF state (must match /login/initiate)
        code_verifier: PKCE code verifier (for browser extensions)

    Returns:
        JWT tokens and user information

    Raises:
        HTTPException: If code exchange fails
    """
    if isinstance(provider, LocalAuthProvider):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OAuth callback not supported in local auth mode"
        )

    # Validate state and retrieve stored redirect_uri
    try:
        redis_client = await get_redis_client()
        stored_redirect_uri = await redis_client.get_client().get(f"oidc_state:{state}")

        if not stored_redirect_uri:
            logger.error(f"OIDC callback failed: Invalid or expired state={state[:8]}...")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired state parameter. Please restart login flow."
            )

        redirect_uri = stored_redirect_uri.decode() if isinstance(stored_redirect_uri, bytes) else stored_redirect_uri

        # Delete state to prevent reuse (CSRF protection)
        await redis_client.get_client().delete(f"oidc_state:{state}")
        logger.info(f"OIDC state validated: redirect_uri={redirect_uri}")

    except HTTPException:
        raise
    except Exception as e:
        logger.warning(f"Failed to validate OIDC state: {e}. Using fallback redirect_uri.")
        # Fallback for development/testing when Redis is unavailable
        redirect_uri = "http://localhost:3000/auth/callback"

    try:
        # Exchange code for user identity
        user_identity = await provider.exchange_code(
            code=code,
            redirect_uri=redirect_uri,
            code_verifier=code_verifier
        )

        logger.info(f"OIDC callback successful: user={user_identity.email}")

        # Generate internal FaultMaven JWT tokens
        # This normalizes OIDC/SAML identities into our standard JWT format
        # Downstream services expect FaultMaven JWTs, not raw Google/Azure tokens
        from datetime import datetime, timedelta, timezone
        from jose import jwt

        # Get JWT configuration (must match LocalAuthProvider)
        import os
        secret_key = os.getenv("SECRET_KEY", "dev-secret-change-in-production")
        algorithm = os.getenv("JWT_ALGORITHM", "HS256")
        access_token_expire_minutes = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
        refresh_token_expire_days = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))

        # Create access token
        now = datetime.now(timezone.utc)
        access_token_payload = {
            "sub": user_identity.user_id,
            "email": user_identity.email,
            "username": user_identity.username,
            "display_name": user_identity.display_name,
            "roles": user_identity.roles,
            "provider": user_identity.provider,
            "type": "access",
            "iat": now,
            "exp": now + timedelta(minutes=access_token_expire_minutes),
            # Store OIDC metadata for reference
            "oidc_provider": user_identity.provider,
            "oidc_sub": user_identity.user_id
        }
        internal_access_token = jwt.encode(access_token_payload, secret_key, algorithm=algorithm)

        # Create refresh token
        refresh_token_payload = {
            "sub": user_identity.user_id,
            "type": "refresh",
            "provider": user_identity.provider,
            "iat": now,
            "exp": now + timedelta(days=refresh_token_expire_days),
            # Store original OIDC refresh token for upstream refresh
            "oidc_refresh_token": user_identity.metadata.get("refresh_token")
        }
        internal_refresh_token = jwt.encode(refresh_token_payload, secret_key, algorithm=algorithm)

        logger.info(f"Generated internal JWT for OIDC user: {user_identity.email}")

        return LoginResponse(
            access_token=internal_access_token,
            refresh_token=internal_refresh_token,
            token_type="bearer",
            expires_in=access_token_expire_minutes * 60,
            user={
                "user_id": user_identity.user_id,
                "email": user_identity.email,
                "username": user_identity.username,
                "display_name": user_identity.display_name,
                "roles": user_identity.roles,
                "provider": user_identity.provider,
                "is_dev_user": False,  # OIDC users are not dev users
                "is_active": True
            }
        )

    except AuthenticationError as e:
        logger.error(f"OIDC callback failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Authentication failed: {e}"
        )


@router.post("/refresh")
async def refresh_tokens(
    request: RefreshRequest,
    provider: AuthProvider = Depends(get_auth_provider)
):
    """Refresh access token using refresh token.

    Works for both local and OIDC/SAML providers.

    Args:
        request: Refresh token

    Returns:
        New access token and refresh token

    Raises:
        HTTPException: If refresh token is invalid
    """
    try:
        new_access_token, new_refresh_token = await provider.refresh_token(
            request.refresh_token
        )

        return {
            "access_token": new_access_token,
            "refresh_token": new_refresh_token,
            "token_type": "bearer"
        }

    except AuthenticationError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Token refresh failed: {e}"
        )


@router.post("/logout")
async def logout(
    request: LogoutRequest = None,
    token: Optional[str] = Depends(extract_bearer_token),
    current_user: UserIdentity = Depends(get_current_user),
    provider: AuthProvider = Depends(get_auth_provider)
):
    """Logout user and revoke tokens.

    For local auth: Adds token to blacklist.
    For OIDC: Calls provider's revocation endpoint.

    Args:
        request: Optional logout request
        token: Current access token
        current_user: Current authenticated user

    Returns:
        Logout confirmation
    """
    try:
        await provider.logout(current_user.user_id, token)
        logger.info(f"User logged out: {current_user.email}")

        return {
            "message": "Logged out successfully",
            "revoked": True
        }

    except Exception as e:
        logger.error(f"Logout failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Logout failed: {e}"
        )


@router.get("/me")
async def get_current_user_info(
    current_user: UserIdentity = Depends(get_current_user)
):
    """Get current authenticated user information.

    Requires valid access token in Authorization header.

    Returns:
        User profile information
    """
    return {
        "user_id": current_user.user_id,
        "email": current_user.email,
        "username": current_user.username,
        "display_name": current_user.display_name,
        "roles": current_user.roles,
        "provider": current_user.provider
    }


@router.get("/health")
async def auth_health():
    """Authentication system health check."""
    return {
        "status": "healthy",
        "service": "authentication",
        "provider": get_auth_provider().__class__.__name__
    }
