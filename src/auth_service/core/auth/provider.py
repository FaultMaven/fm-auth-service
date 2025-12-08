"""Abstract authentication provider interface.

This module defines the contract that all authentication providers must implement.
Enables deployment-neutral authentication by allowing runtime provider selection.
"""

from abc import ABC, abstractmethod
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field


class UserIdentity(BaseModel):
    """User identity returned from authentication providers.

    Attributes:
        user_id: Unique user identifier
        email: User email address
        username: Username for display
        display_name: Full name for UI
        roles: List of user roles (e.g., ['admin', 'user'])
        provider: Auth provider used (local, google, okta, etc.)
        metadata: Provider-specific metadata (optional)
    """
    user_id: str
    email: str
    username: str
    display_name: str
    roles: list[str] = Field(default_factory=list)
    provider: str  # 'local', 'google', 'okta', 'azure'
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AuthProvider(ABC):
    """Abstract interface for authentication providers.

    Implementation is chosen at startup via AUTH_PROVIDER environment variable.
    This enables the same codebase to work in both self-hosted (local auth)
    and enterprise cloud (OIDC/SAML) environments.

    Example:
        # Self-Hosted
        AUTH_PROVIDER=local  # Uses username/password JWT

        # Enterprise Cloud
        AUTH_PROVIDER=oidc
        OIDC_ISSUER_URL=https://accounts.google.com
        OIDC_CLIENT_ID=xxx
        OIDC_CLIENT_SECRET=xxx
    """

    @abstractmethod
    async def get_login_url(
        self,
        state: str,
        redirect_uri: str,
        code_challenge: Optional[str] = None,
        code_challenge_method: Optional[str] = None
    ) -> str:
        """Generate the login URL for authentication flow.

        For OIDC/SAML, this returns the URL to redirect the user to the provider.
        For local auth, this might return None or a frontend login route.

        Args:
            state: CSRF protection state parameter
            redirect_uri: URL to redirect back to after authentication
            code_challenge: PKCE code challenge (for browser extensions)
            code_challenge_method: PKCE challenge method (usually S256)

        Returns:
            URL to initiate authentication flow
        """
        pass

    @abstractmethod
    async def exchange_code(
        self,
        code: str,
        redirect_uri: str,
        code_verifier: Optional[str] = None
    ) -> UserIdentity:
        """Exchange authorization code for user identity.

        For OIDC, this exchanges the auth code from the callback for an ID token.
        For local auth, this might validate username/password credentials.

        Args:
            code: Authorization code from provider callback
            redirect_uri: Same redirect_uri used in get_login_url
            code_verifier: PKCE code verifier (for browser extensions)

        Returns:
            UserIdentity with user information

        Raises:
            AuthenticationError: If code exchange fails
        """
        pass

    @abstractmethod
    async def validate_token(self, token: str) -> UserIdentity:
        """Validate a Bearer token and return user identity.

        Called on every authenticated request to verify the token is valid.

        For local auth: Validates JWT signature and expiration.
        For OIDC: Validates ID token or calls UserInfo endpoint.

        Args:
            token: Bearer token from Authorization header

        Returns:
            UserIdentity if token is valid

        Raises:
            AuthenticationError: If token is invalid or expired
        """
        pass

    @abstractmethod
    async def refresh_token(self, refresh_token: str) -> tuple[str, str]:
        """Refresh an expired access token.

        Args:
            refresh_token: Refresh token from provider

        Returns:
            Tuple of (new_access_token, new_refresh_token)

        Raises:
            AuthenticationError: If refresh fails
        """
        pass

    @abstractmethod
    async def logout(self, user_id: str, token: Optional[str] = None) -> None:
        """Logout user and invalidate tokens.

        For local auth: Add token to blacklist.
        For OIDC: Call provider's revocation endpoint.

        Args:
            user_id: User to logout
            token: Token to invalidate (optional)
        """
        pass
