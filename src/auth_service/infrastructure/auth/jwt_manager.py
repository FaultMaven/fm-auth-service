"""JWT Token Manager (RS256)

Production-ready JWT token management using RS256 algorithm.
Compatible with Supabase and Auth0 token formats.

This replaces the development token manager with proper JWT tokens.
"""

import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Optional

import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger(__name__)


@dataclass
class JWTTokenResult:
    """Result of JWT token creation"""

    access_token: str
    token_type: str = "bearer"
    expires_in: int = 86400  # 24 hours in seconds


@dataclass
class JWTValidationResult:
    """Result of JWT token validation"""

    valid: bool
    user_id: Optional[str] = None
    email: Optional[str] = None
    roles: Optional[list[str]] = None
    error: Optional[str] = None


class JWTManager:
    """Manages RS256 JWT tokens compatible with Supabase/Auth0 format

    Token Format (matches SaaS providers):
    {
        "sub": "user-uuid",              # Subject (user_id)
        "email": "user@example.com",      # User email
        "email_verified": true,           # Email verification status
        "roles": ["admin"],               # User roles
        "iss": "https://auth.faultmaven.ai",  # Issuer
        "aud": "faultmaven-api",          # Audience
        "iat": 1700000000,                # Issued at
        "exp": 1700086400,                # Expires at
        "jti": "token-uuid"               # JWT ID (unique token identifier)
    }
    """

    def __init__(
        self,
        private_key_path: str,
        public_key_path: str,
        issuer: str = "https://auth.faultmaven.ai",
        audience: str = "faultmaven-api",
        access_token_expire_minutes: int = 1440,  # 24 hours
    ):
        """Initialize JWT manager

        Args:
            private_key_path: Path to RSA private key (PEM format)
            public_key_path: Path to RSA public key (PEM format)
            issuer: JWT issuer claim (iss)
            audience: JWT audience claim (aud)
            access_token_expire_minutes: Token expiration in minutes
        """
        self.issuer = issuer
        self.audience = audience
        self.access_token_expire_minutes = access_token_expire_minutes

        # Load RSA keys
        self.private_key = self._load_private_key(private_key_path)
        self.public_key = self._load_public_key(public_key_path)

        logger.info(f"JWT Manager initialized (issuer={issuer}, audience={audience})")

    def _load_private_key(self, key_path: str):
        """Load RSA private key from PEM file"""
        try:
            path = Path(key_path)
            if not path.exists():
                raise FileNotFoundError(f"Private key not found: {key_path}")

            with open(path, "rb") as f:
                private_key = serialization.load_pem_private_key(
                    f.read(), password=None, backend=default_backend()
                )

            logger.info(f"Loaded RSA private key from {key_path}")
            return private_key

        except Exception as e:
            logger.error(f"Failed to load private key: {e}")
            raise

    def _load_public_key(self, key_path: str):
        """Load RSA public key from PEM file"""
        try:
            path = Path(key_path)
            if not path.exists():
                raise FileNotFoundError(f"Public key not found: {key_path}")

            with open(path, "rb") as f:
                public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())

            logger.info(f"Loaded RSA public key from {key_path}")
            return public_key

        except Exception as e:
            logger.error(f"Failed to load public key: {e}")
            raise

    def create_access_token(
        self,
        user_id: str,
        email: str,
        roles: Optional[list[str]] = None,
        email_verified: bool = True,
        additional_claims: Optional[Dict[str, Any]] = None,
    ) -> JWTTokenResult:
        """Create a new JWT access token

        Args:
            user_id: User UUID
            email: User email address
            roles: List of user roles (e.g., ["admin", "investigator"])
            email_verified: Whether email is verified
            additional_claims: Optional additional JWT claims

        Returns:
            JWTTokenResult with access token and metadata
        """
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(minutes=self.access_token_expire_minutes)

        # Standard JWT claims (matches Supabase/Auth0 format)
        claims = {
            "sub": user_id,  # Subject (user_id)
            "email": email,  # User email
            "email_verified": email_verified,  # Email verification status
            "roles": roles or [],  # User roles
            "iss": self.issuer,  # Issuer
            "aud": self.audience,  # Audience
            "iat": int(now.timestamp()),  # Issued at
            "exp": int(expires_at.timestamp()),  # Expires at
            "jti": str(uuid.uuid4()),  # JWT ID (unique token identifier)
        }

        # Add additional claims if provided
        if additional_claims:
            claims.update(additional_claims)

        # Sign token with RS256
        try:
            # Convert private key to PEM format for PyJWT
            private_key_pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )

            access_token = jwt.encode(claims, private_key_pem, algorithm="RS256")

            logger.info(f"Created JWT token for user {user_id} (jti={claims['jti']})")

            return JWTTokenResult(
                access_token=access_token,
                token_type="bearer",
                expires_in=self.access_token_expire_minutes * 60,  # Convert to seconds
            )

        except Exception as e:
            logger.error(f"Failed to create JWT token: {e}")
            raise

    def validate_token(self, token: str) -> JWTValidationResult:
        """Validate a JWT access token

        Args:
            token: JWT token string

        Returns:
            JWTValidationResult with validation status and claims
        """
        try:
            # Convert public key to PEM format for PyJWT
            public_key_pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

            # Decode and validate token
            claims = jwt.decode(
                token,
                public_key_pem,
                algorithms=["RS256"],
                audience=self.audience,
                issuer=self.issuer,
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_iat": True,
                    "verify_aud": True,
                    "verify_iss": True,
                },
            )

            logger.info(
                f"Validated JWT token for user {claims.get('sub')} (jti={claims.get('jti')})"
            )

            return JWTValidationResult(
                valid=True,
                user_id=claims.get("sub"),
                email=claims.get("email"),
                roles=claims.get("roles", []),
            )

        except jwt.ExpiredSignatureError:
            logger.warning("JWT token expired")
            return JWTValidationResult(valid=False, error="token_expired")

        except jwt.InvalidAudienceError:
            logger.warning("JWT token has invalid audience")
            return JWTValidationResult(valid=False, error="invalid_audience")

        except jwt.InvalidIssuerError:
            logger.warning("JWT token has invalid issuer")
            return JWTValidationResult(valid=False, error="invalid_issuer")

        except jwt.InvalidSignatureError:
            logger.warning("JWT token has invalid signature")
            return JWTValidationResult(valid=False, error="invalid_signature")

        except jwt.DecodeError:
            logger.warning("Failed to decode JWT token")
            return JWTValidationResult(valid=False, error="decode_error")

        except Exception as e:
            logger.error(f"Unexpected error validating JWT token: {e}")
            return JWTValidationResult(valid=False, error="validation_error")

    def get_public_key_pem(self) -> str:
        """Get public key in PEM format (for JWK endpoint)

        Returns:
            Public key as PEM string
        """
        public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return public_key_pem.decode("utf-8")

    def get_jwk(self) -> Dict[str, Any]:
        """Get public key as JWK (JSON Web Key)

        This is used by API Gateway to validate tokens.

        Returns:
            JWK dictionary
        """
        from cryptography.hazmat.primitives.asymmetric import rsa

        # Get public key numbers
        public_numbers = self.public_key.public_numbers()

        # Convert to JWK format
        import base64

        def int_to_base64url(value: int) -> str:
            """Convert integer to base64url encoding"""
            value_bytes = value.to_bytes((value.bit_length() + 7) // 8, byteorder="big")
            return base64.urlsafe_b64encode(value_bytes).rstrip(b"=").decode("utf-8")

        jwk = {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "n": int_to_base64url(public_numbers.n),  # Modulus
            "e": int_to_base64url(public_numbers.e),  # Exponent
        }

        return jwk


# Singleton instance (will be initialized in dependency injection)
_jwt_manager_instance: Optional[JWTManager] = None


def get_jwt_manager() -> JWTManager:
    """Get JWT manager singleton instance

    Returns:
        JWTManager instance

    Raises:
        RuntimeError: If JWT manager not initialized
    """
    global _jwt_manager_instance

    if _jwt_manager_instance is None:
        raise RuntimeError("JWT manager not initialized. Call initialize_jwt_manager() first.")

    return _jwt_manager_instance


def initialize_jwt_manager(
    private_key_path: str,
    public_key_path: str,
    issuer: str = "https://auth.faultmaven.ai",
    audience: str = "faultmaven-api",
    access_token_expire_minutes: int = 1440,
) -> JWTManager:
    """Initialize JWT manager singleton

    Args:
        private_key_path: Path to RSA private key
        public_key_path: Path to RSA public key
        issuer: JWT issuer
        audience: JWT audience
        access_token_expire_minutes: Token expiration in minutes

    Returns:
        Initialized JWTManager instance
    """
    global _jwt_manager_instance

    _jwt_manager_instance = JWTManager(
        private_key_path=private_key_path,
        public_key_path=public_key_path,
        issuer=issuer,
        audience=audience,
        access_token_expire_minutes=access_token_expire_minutes,
    )

    logger.info("JWT manager singleton initialized")
    return _jwt_manager_instance
