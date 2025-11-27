"""Service Token Manager

Manages JWT token generation for service-to-service authentication.
"""

import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List

import jwt
import yaml

logger = logging.getLogger(__name__)


class ServiceTokenManager:
    """Manages service authentication tokens using RS256 JWT."""

    def __init__(
        self,
        private_key_path: str,
        permissions_config_path: str,
        token_issuer: str = "fm-auth-service",
        default_ttl_seconds: int = 3600,
    ):
        """Initialize service token manager.

        Args:
            private_key_path: Path to RSA private key file
            permissions_config_path: Path to service permissions YAML config
            token_issuer: JWT issuer identifier
            default_ttl_seconds: Default token TTL (default: 1 hour)
        """
        self.token_issuer = token_issuer
        self.default_ttl_seconds = default_ttl_seconds

        # Load RSA private key
        try:
            with open(private_key_path, "r") as f:
                self.private_key = f.read()
            logger.info(f"Loaded RSA private key from {private_key_path}")
        except Exception as e:
            logger.error(f"Failed to load private key: {e}")
            raise ValueError(f"Cannot load private key from {private_key_path}: {e}")

        # Load service permissions configuration
        try:
            with open(permissions_config_path, "r") as f:
                config = yaml.safe_load(f)
                self.permissions_map: Dict[str, List[str]] = config.get("services", {})
            logger.info(
                f"Loaded permissions for {len(self.permissions_map)} services "
                f"from {permissions_config_path}"
            )
        except Exception as e:
            logger.error(f"Failed to load permissions config: {e}")
            raise ValueError(
                f"Cannot load permissions from {permissions_config_path}: {e}"
            )

    def create_service_token(
        self, service_id: str, audience: List[str], ttl_seconds: int = None
    ) -> Dict[str, Any]:
        """Create a service authentication token.

        Args:
            service_id: Service identifier (e.g., "fm-agent-service")
            audience: List of services this token can call (e.g., ["fm-case-service"])
            ttl_seconds: Token TTL in seconds (default: use default_ttl_seconds)

        Returns:
            Dict with token, expires_at (ISO format), and expires_in (seconds)

        Raises:
            ValueError: If service_id not found in permissions config
        """
        # Validate service ID
        if service_id not in self.permissions_map:
            raise ValueError(
                f"Service '{service_id}' not found in permissions configuration"
            )

        # Get permissions for this service
        permissions = self.permissions_map[service_id]

        # Calculate expiration
        ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl_seconds
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=ttl)

        # Build JWT claims
        claims = {
            "iss": self.token_issuer,  # Issuer
            "sub": service_id,  # Subject (service ID)
            "aud": audience,  # Audience (services this token can call)
            "iat": int(now.timestamp()),  # Issued at
            "exp": int(expires_at.timestamp()),  # Expiration
            "service_id": service_id,  # Custom claim: service identifier
            "permissions": permissions,  # Custom claim: service permissions
        }

        # Sign JWT with RSA private key
        token = jwt.encode(claims, self.private_key, algorithm="RS256")

        logger.info(
            f"Created service token for {service_id}, "
            f"audience={audience}, permissions={permissions}, "
            f"expires_in={ttl}s"
        )

        return {
            "token": token,
            "expires_at": expires_at.isoformat(),
            "expires_in": ttl,
        }


# Global singleton instance
_service_token_manager: ServiceTokenManager | None = None


def initialize_service_token_manager(
    private_key_path: str,
    permissions_config_path: str,
    token_issuer: str = "fm-auth-service",
    default_ttl_seconds: int = 3600,
) -> ServiceTokenManager:
    """Initialize the global service token manager.

    Args:
        private_key_path: Path to RSA private key
        permissions_config_path: Path to permissions YAML config
        token_issuer: JWT issuer
        default_ttl_seconds: Default token TTL

    Returns:
        Initialized ServiceTokenManager instance
    """
    global _service_token_manager
    _service_token_manager = ServiceTokenManager(
        private_key_path=private_key_path,
        permissions_config_path=permissions_config_path,
        token_issuer=token_issuer,
        default_ttl_seconds=default_ttl_seconds,
    )
    return _service_token_manager


def get_service_token_manager() -> ServiceTokenManager:
    """Get the global service token manager instance.

    Returns:
        ServiceTokenManager instance

    Raises:
        RuntimeError: If manager not initialized
    """
    if _service_token_manager is None:
        raise RuntimeError(
            "ServiceTokenManager not initialized. "
            "Call initialize_service_token_manager() first."
        )
    return _service_token_manager
