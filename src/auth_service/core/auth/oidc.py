"""OpenID Connect (OIDC) authentication provider.

Supports major OIDC providers:
- Google Workspace
- Microsoft Azure AD / Entra ID
- Okta
- Auth0
- Any standard OIDC provider

Uses PKCE (Proof Key for Code Exchange) for browser extension security.
"""

import logging
from typing import Optional
from urllib.parse import urlencode

import httpx
from jose import jwt, JWTError
from jose.exceptions import ExpiredSignatureError, JWTClaimsError

from .provider import AuthProvider, UserIdentity

logger = logging.getLogger(__name__)


class OIDCAuthProvider(AuthProvider):
    """OpenID Connect authentication provider.

    Implements OAuth 2.0 + OIDC for enterprise SSO integration.

    Example Configuration:
        # Google Workspace
        AUTH_PROVIDER=oidc
        OIDC_ISSUER_URL=https://accounts.google.com
        OIDC_CLIENT_ID=xxx.apps.googleusercontent.com
        OIDC_CLIENT_SECRET=GOCSPX-xxx
        OIDC_SCOPES="openid email profile"

        # Microsoft Azure AD
        OIDC_ISSUER_URL=https://login.microsoftonline.com/{tenant-id}/v2.0
        OIDC_CLIENT_ID=xxx
        OIDC_CLIENT_SECRET=xxx

        # Okta
        OIDC_ISSUER_URL=https://{domain}.okta.com/oauth2/default
        OIDC_CLIENT_ID=xxx
        OIDC_CLIENT_SECRET=xxx
    """

    def __init__(
        self,
        issuer: str,
        client_id: str,
        client_secret: str,
        scopes: list[str] = None
    ):
        """Initialize OIDC provider.

        Args:
            issuer: OIDC issuer URL (e.g., https://accounts.google.com)
            client_id: OAuth 2.0 client ID
            client_secret: OAuth 2.0 client secret
            scopes: OIDC scopes to request (default: openid email profile)
        """
        self.issuer = issuer.rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self.scopes = scopes or ["openid", "email", "profile"]

        # Discovery endpoints (lazy-loaded)
        self._discovery: Optional[dict] = None
        self._jwks: Optional[dict] = None

    async def _get_discovery(self) -> dict:
        """Fetch OIDC discovery document (.well-known/openid-configuration)."""
        if self._discovery is None:
            discovery_url = f"{self.issuer}/.well-known/openid-configuration"
            async with httpx.AsyncClient() as client:
                response = await client.get(discovery_url)
                response.raise_for_status()
                self._discovery = response.json()
                logger.info(f"OIDC discovery loaded from {discovery_url}")
        return self._discovery

    async def _get_jwks(self) -> dict:
        """Fetch JSON Web Key Set for token validation."""
        if self._jwks is None:
            discovery = await self._get_discovery()
            jwks_uri = discovery["jwks_uri"]
            async with httpx.AsyncClient() as client:
                response = await client.get(jwks_uri)
                response.raise_for_status()
                self._jwks = response.json()
                logger.info(f"OIDC JWKS loaded from {jwks_uri}")
        return self._jwks

    async def get_login_url(
        self,
        state: str,
        redirect_uri: str,
        code_challenge: Optional[str] = None,
        code_challenge_method: Optional[str] = None
    ) -> str:
        """Generate OIDC authorization URL.

        Args:
            state: CSRF protection state
            redirect_uri: Callback URL
            code_challenge: PKCE code challenge (for browser extensions)
            code_challenge_method: PKCE method (usually S256)

        Returns:
            Authorization URL to redirect user to
        """
        discovery = await self._get_discovery()
        auth_endpoint = discovery["authorization_endpoint"]

        params = {
            "client_id": self.client_id,
            "response_type": "code",
            "scope": " ".join(self.scopes),
            "redirect_uri": redirect_uri,
            "state": state,
        }

        # Add PKCE parameters if provided (required for browser extensions)
        if code_challenge and code_challenge_method:
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = code_challenge_method

        return f"{auth_endpoint}?{urlencode(params)}"

    async def exchange_code(
        self,
        code: str,
        redirect_uri: str,
        code_verifier: Optional[str] = None
    ) -> UserIdentity:
        """Exchange authorization code for user identity.

        Args:
            code: Authorization code from OIDC callback
            redirect_uri: Same redirect_uri used in get_login_url
            code_verifier: PKCE code verifier (for browser extensions)

        Returns:
            UserIdentity with user information

        Raises:
            AuthenticationError: If code exchange fails
        """
        discovery = await self._get_discovery()
        token_endpoint = discovery["token_endpoint"]

        # Prepare token request
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }

        # Add PKCE verifier if provided
        if code_verifier:
            data["code_verifier"] = code_verifier

        # Exchange code for tokens
        async with httpx.AsyncClient() as client:
            response = await client.post(
                token_endpoint,
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )

            if response.status_code != 200:
                logger.error(f"OIDC token exchange failed: {response.text}")
                raise AuthenticationError(f"Token exchange failed: {response.status_code}")

            tokens = response.json()

        # Decode ID token to get user info
        id_token = tokens["id_token"]
        user_info = await self._decode_id_token(id_token)

        # Map OIDC claims to UserIdentity
        return UserIdentity(
            user_id=user_info.get("sub"),  # Subject (unique user ID)
            email=user_info.get("email", ""),
            username=user_info.get("preferred_username", user_info.get("email", "")),
            display_name=user_info.get("name", user_info.get("email", "")),
            roles=[],  # OIDC doesn't have standard roles; enterprise can extend this
            provider=self._get_provider_name(),
            metadata={
                "access_token": tokens.get("access_token"),
                "refresh_token": tokens.get("refresh_token"),
                "expires_in": tokens.get("expires_in"),
                "id_token": id_token,
                "oidc_claims": user_info
            }
        )

    async def validate_token(self, token: str) -> UserIdentity:
        """Validate OIDC ID token.

        Args:
            token: ID token from Authorization header

        Returns:
            UserIdentity if token is valid

        Raises:
            AuthenticationError: If token is invalid or expired
        """
        try:
            user_info = await self._decode_id_token(token)

            return UserIdentity(
                user_id=user_info.get("sub"),
                email=user_info.get("email", ""),
                username=user_info.get("preferred_username", user_info.get("email", "")),
                display_name=user_info.get("name", user_info.get("email", "")),
                roles=[],
                provider=self._get_provider_name(),
                metadata={"oidc_claims": user_info}
            )

        except (JWTError, ExpiredSignatureError, JWTClaimsError) as e:
            logger.warning(f"OIDC token validation failed: {e}")
            raise AuthenticationError(f"Invalid token: {e}")

    async def refresh_token(self, refresh_token: str) -> tuple[str, str]:
        """Refresh OIDC access token.

        Args:
            refresh_token: Refresh token from provider

        Returns:
            Tuple of (new_access_token, new_refresh_token)

        Raises:
            AuthenticationError: If refresh fails
        """
        discovery = await self._get_discovery()
        token_endpoint = discovery["token_endpoint"]

        data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(
                token_endpoint,
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )

            if response.status_code != 200:
                logger.error(f"OIDC token refresh failed: {response.text}")
                raise AuthenticationError(f"Token refresh failed: {response.status_code}")

            tokens = response.json()
            return (
                tokens["access_token"],
                tokens.get("refresh_token", refresh_token)  # Some providers don't rotate
            )

    async def logout(self, user_id: str, token: Optional[str] = None) -> None:
        """Logout user (revoke OIDC tokens).

        Args:
            user_id: User to logout
            token: Token to revoke (optional)
        """
        discovery = await self._get_discovery()

        # Check if provider supports token revocation
        revocation_endpoint = discovery.get("revocation_endpoint")
        if not revocation_endpoint or not token:
            logger.info(f"OIDC logout for user {user_id} (no revocation endpoint)")
            return

        # Revoke token
        data = {
            "token": token,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(
                revocation_endpoint,
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )

            if response.status_code == 200:
                logger.info(f"OIDC token revoked for user {user_id}")
            else:
                logger.warning(f"OIDC token revocation failed: {response.status_code}")

    async def _decode_id_token(self, id_token: str) -> dict:
        """Decode and validate OIDC ID token.

        Args:
            id_token: JWT ID token from provider

        Returns:
            Decoded token claims

        Raises:
            JWTError: If token is invalid
        """
        jwks = await self._get_jwks()

        # Decode token (validates signature, expiration, issuer, audience)
        claims = jwt.decode(
            id_token,
            jwks,
            algorithms=["RS256"],  # Most OIDC providers use RS256
            issuer=self.issuer,
            audience=self.client_id,
            options={"verify_at_hash": False}  # Skip access token hash validation
        )

        return claims

    def _get_provider_name(self) -> str:
        """Get human-readable provider name from issuer URL."""
        if "google" in self.issuer:
            return "google"
        elif "microsoft" in self.issuer or "azure" in self.issuer:
            return "azure"
        elif "okta" in self.issuer:
            return "okta"
        elif "auth0" in self.issuer:
            return "auth0"
        else:
            return "oidc"


class AuthenticationError(Exception):
    """Authentication failed."""
    pass
