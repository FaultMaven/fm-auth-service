"""JWKS (JSON Web Key Set) Routes

Provides public key discovery for JWT validation.
This endpoint is used by fm-api-gateway to validate tokens.

Standard endpoint: /.well-known/jwks.json
"""

import logging
from typing import Any, Dict

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from auth_service.infrastructure.auth.jwt_manager import get_jwt_manager

logger = logging.getLogger(__name__)

# Create router for JWKS endpoints
router = APIRouter(tags=["jwks"])


@router.get("/.well-known/jwks.json")
async def get_jwks() -> Dict[str, Any]:
    """Get JSON Web Key Set (JWKS)

    This endpoint provides the public key(s) used to sign JWT tokens.
    API Gateway and other services use this to validate token signatures.

    Returns:
        JWKS document with public keys

    Example Response:
        {
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "alg": "RS256",
                    "n": "base64url-encoded-modulus",
                    "e": "base64url-encoded-exponent"
                }
            ]
        }
    """
    try:
        jwt_manager = get_jwt_manager()
        jwk = jwt_manager.get_jwk()

        # JWKS format (array of keys)
        jwks = {"keys": [jwk]}

        logger.info("JWKS endpoint accessed")
        return jwks

    except Exception as e:
        logger.error(f"Error generating JWKS: {e}")
        return JSONResponse(
            status_code=500,
            content={"error": "internal_server_error", "message": "Failed to generate JWKS"},
        )


@router.get("/.well-known/openid-configuration")
async def get_openid_configuration() -> Dict[str, Any]:
    """Get OpenID Connect discovery document

    Provides metadata about the auth service.
    Optional but helpful for compatibility with OIDC clients.

    Returns:
        OpenID Connect discovery document
    """
    jwt_manager = get_jwt_manager()

    # OpenID Connect discovery document
    config = {
        "issuer": jwt_manager.issuer,
        "authorization_endpoint": f"{jwt_manager.issuer}/auth/authorize",
        "token_endpoint": f"{jwt_manager.issuer}/auth/token",
        "jwks_uri": f"{jwt_manager.issuer}/.well-known/jwks.json",
        "response_types_supported": ["code", "token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "email", "profile"],
        "token_endpoint_auth_methods_supported": ["client_secret_post"],
        "claims_supported": ["sub", "email", "email_verified", "roles", "iat", "exp"],
    }

    logger.info("OpenID configuration endpoint accessed")
    return config
