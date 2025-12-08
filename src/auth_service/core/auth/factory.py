"""Authentication provider factory.

Selects and instantiates the appropriate auth provider based on environment configuration.
"""

import os
import logging
from typing import Optional

from .provider import AuthProvider

logger = logging.getLogger(__name__)

# Global provider instance (initialized on first call)
_provider_instance: Optional[AuthProvider] = None


def get_auth_provider() -> AuthProvider:
    """Get the configured authentication provider instance.

    Provider is selected via AUTH_PROVIDER environment variable:
    - local: Username/password with JWT (default for self-hosted)
    - oidc: OpenID Connect (Google, Okta, Azure AD)
    - saml: SAML 2.0 (enterprise SSO)

    Returns:
        Configured AuthProvider instance

    Raises:
        ValueError: If AUTH_PROVIDER is invalid
        ImportError: If required dependencies are missing
    """
    global _provider_instance

    # Return cached instance
    if _provider_instance is not None:
        return _provider_instance

    mode = os.getenv("AUTH_PROVIDER", "local").lower()
    logger.info(f"Initializing authentication provider: {mode}")

    if mode == "local":
        from .local import LocalAuthProvider
        _provider_instance = LocalAuthProvider(
            secret_key=os.getenv("SECRET_KEY", "dev-secret-change-in-production"),
            algorithm=os.getenv("JWT_ALGORITHM", "HS256"),
            access_token_expire_minutes=int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60")),
            refresh_token_expire_days=int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))
        )

    elif mode == "oidc":
        from .oidc import OIDCAuthProvider

        # Validate required ENV variables
        issuer = os.getenv("OIDC_ISSUER_URL")
        client_id = os.getenv("OIDC_CLIENT_ID")
        client_secret = os.getenv("OIDC_CLIENT_SECRET")

        if not all([issuer, client_id, client_secret]):
            raise ValueError(
                "OIDC provider requires: OIDC_ISSUER_URL, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET"
            )

        _provider_instance = OIDCAuthProvider(
            issuer=issuer,
            client_id=client_id,
            client_secret=client_secret,
            scopes=os.getenv("OIDC_SCOPES", "openid email profile").split()
        )

    elif mode == "saml":
        # Defer import to avoid crashing if python3-saml is not installed
        try:
            from .saml import SAMLAuthProvider
        except ImportError as e:
            raise ImportError(
                "SAML provider requires python3-saml: pip install python3-saml"
            ) from e

        metadata_url = os.getenv("SAML_IDP_METADATA_URL")
        if not metadata_url:
            raise ValueError("SAML provider requires: SAML_IDP_METADATA_URL")

        _provider_instance = SAMLAuthProvider(
            idp_metadata_url=metadata_url,
            sp_entity_id=os.getenv("SAML_SP_ENTITY_ID", "faultmaven"),
            sp_acs_url=os.getenv("SAML_SP_ACS_URL")
        )

    else:
        raise ValueError(
            f"Unknown AUTH_PROVIDER: {mode}. "
            f"Valid options: local, oidc, saml"
        )

    logger.info(f"Auth provider initialized: {_provider_instance.__class__.__name__}")
    return _provider_instance


def reset_provider() -> None:
    """Reset the global provider instance (for testing)."""
    global _provider_instance
    _provider_instance = None
