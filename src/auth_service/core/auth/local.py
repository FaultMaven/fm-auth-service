"""Local authentication provider (username/password with JWT).

Default provider for self-hosted deployments.
Uses existing JWT manager and user store infrastructure.
"""

import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, Set
import asyncio

import bcrypt
from jose import jwt, JWTError

from .provider import AuthProvider, UserIdentity
from auth_service.infrastructure.auth.jwt_manager import get_jwt_manager
from auth_service.infrastructure.auth.user_store import DevUserStore
from auth_service.infrastructure.redis.client import get_redis_client

logger = logging.getLogger(__name__)

# In-memory token blacklist (fallback when Redis is unavailable)
# WARNING: This only works for single-instance deployments!
# In production with multiple instances, you MUST use Redis
_memory_blacklist: Set[str] = set()
_blacklist_lock = asyncio.Lock()


class LocalAuthProvider(AuthProvider):
    """Local username/password authentication with JWT tokens.

    This provider implements traditional email/password authentication
    using bcrypt for password hashing and JWT for session management.

    Features:
    - User registration with email/password
    - Login with email/password
    - JWT access tokens (configurable expiration)
    - JWT refresh tokens for token renewal
    - Redis-backed token blacklist for logout

    Configuration:
        AUTH_PROVIDER=local (default)
        SECRET_KEY=<your-secret-key>
        JWT_ALGORITHM=HS256 (default)
        ACCESS_TOKEN_EXPIRE_MINUTES=60 (default)
        REFRESH_TOKEN_EXPIRE_DAYS=7 (default)
    """

    def __init__(
        self,
        secret_key: str,
        algorithm: str = "HS256",
        access_token_expire_minutes: int = 60,
        refresh_token_expire_days: int = 7
    ):
        """Initialize local auth provider.

        Args:
            secret_key: Secret key for JWT signing
            algorithm: JWT signing algorithm (HS256 recommended)
            access_token_expire_minutes: Access token TTL in minutes
            refresh_token_expire_days: Refresh token TTL in days
        """
        self.secret_key = secret_key
        self.algorithm = algorithm
        self.access_token_expire = timedelta(minutes=access_token_expire_minutes)
        self.refresh_token_expire = timedelta(days=refresh_token_expire_days)

        # Validate configuration
        if secret_key == "dev-secret-change-in-production":
            logger.warning(
                "Using default SECRET_KEY! "
                "Set SECRET_KEY environment variable in production!"
            )

    async def get_login_url(
        self,
        state: str,
        redirect_uri: str,
        code_challenge: Optional[str] = None,
        code_challenge_method: Optional[str] = None
    ) -> str:
        """Local auth doesn't use OAuth redirect flow.

        Returns a special marker indicating frontend should show login form.

        Args:
            state: Unused for local auth
            redirect_uri: Unused for local auth
            code_challenge: Unused for local auth
            code_challenge_method: Unused for local auth

        Returns:
            Empty string (frontend renders login form)
        """
        return ""  # Frontend will render username/password form

    async def exchange_code(
        self,
        code: str,
        redirect_uri: str,
        code_verifier: Optional[str] = None
    ) -> UserIdentity:
        """Local auth doesn't use OAuth code exchange.

        This method is not called for local auth.
        Instead, use authenticate_user() directly.

        Raises:
            NotImplementedError: Local auth uses direct authentication
        """
        raise NotImplementedError(
            "Local auth does not support code exchange. "
            "Use authenticate_user(email, password) instead."
        )

    async def authenticate_user(self, email: str, password: str) -> UserIdentity:
        """Authenticate user with email and password.

        This is the primary authentication method for local provider.

        Args:
            email: User email address
            password: User password (plain text)

        Returns:
            UserIdentity with user information and JWT tokens

        Raises:
            AuthenticationError: If credentials are invalid
        """
        # Get user store
        redis_client = await get_redis_client()
        user_store = DevUserStore(redis_client.get_client())

        # Fetch user by email
        user = await user_store.get_user_by_email(email)
        if not user:
            logger.warning(f"Login failed: User not found (email: {email})")
            raise AuthenticationError("Invalid email or password")

        # Verify password
        if not bcrypt.checkpw(password.encode(), user.password_hash.encode()):
            logger.warning(f"Login failed: Invalid password (email: {email})")
            raise AuthenticationError("Invalid email or password")

        # Check if user is active
        if not user.is_active:
            logger.warning(f"Login failed: User inactive (email: {email})")
            raise AuthenticationError("User account is inactive")

        # Generate tokens
        access_token = self._create_access_token(user.user_id, user.email)
        refresh_token = self._create_refresh_token(user.user_id)

        logger.info(f"User authenticated successfully: {user.email} ({user.user_id})")

        return UserIdentity(
            user_id=user.user_id,
            email=user.email,
            username=user.username,
            display_name=user.display_name or user.username,
            roles=user.roles,
            provider="local",
            metadata={
                "access_token": access_token,
                "refresh_token": refresh_token,
                "expires_in": int(self.access_token_expire.total_seconds()),
                "token_type": "bearer"
            }
        )

    async def validate_token(self, token: str) -> UserIdentity:
        """Validate JWT access token.

        Args:
            token: JWT access token

        Returns:
            UserIdentity if token is valid

        Raises:
            AuthenticationError: If token is invalid or expired
        """
        try:
            # Decode JWT token
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm]
            )

            user_id = payload.get("sub")
            email = payload.get("email")

            if not user_id or not email:
                raise AuthenticationError("Invalid token payload")

            # Check if token is blacklisted (logout)
            if await self._is_token_blacklisted(token):
                raise AuthenticationError("Token has been revoked")

            # Fetch user to get current roles
            redis_client = await get_redis_client()
            user_store = DevUserStore(redis_client.get_client())
            user = await user_store.get_user_by_id(user_id)

            if not user or not user.is_active:
                raise AuthenticationError("User not found or inactive")

            return UserIdentity(
                user_id=user_id,
                email=email,
                username=user.username,
                display_name=user.display_name or user.username,
                roles=user.roles,
                provider="local",
                metadata={"jwt_payload": payload}
            )

        except JWTError as e:
            logger.warning(f"Token validation failed: {e}")
            raise AuthenticationError(f"Invalid token: {e}")

    async def refresh_token(self, refresh_token: str) -> tuple[str, str]:
        """Refresh access token using refresh token.

        Args:
            refresh_token: JWT refresh token

        Returns:
            Tuple of (new_access_token, new_refresh_token)

        Raises:
            AuthenticationError: If refresh token is invalid
        """
        try:
            # Decode refresh token
            payload = jwt.decode(
                refresh_token,
                self.secret_key,
                algorithms=[self.algorithm]
            )

            user_id = payload.get("sub")
            token_type = payload.get("type")

            if not user_id or token_type != "refresh":
                raise AuthenticationError("Invalid refresh token")

            # Check if token is blacklisted
            if await self._is_token_blacklisted(refresh_token):
                raise AuthenticationError("Refresh token has been revoked")

            # Fetch user
            redis_client = await get_redis_client()
            user_store = DevUserStore(redis_client.get_client())
            user = await user_store.get_user_by_id(user_id)

            if not user or not user.is_active:
                raise AuthenticationError("User not found or inactive")

            # Generate new tokens
            new_access_token = self._create_access_token(user.user_id, user.email)
            new_refresh_token = self._create_refresh_token(user.user_id)

            logger.info(f"Token refreshed for user: {user.email}")

            return (new_access_token, new_refresh_token)

        except JWTError as e:
            logger.warning(f"Refresh token validation failed: {e}")
            raise AuthenticationError(f"Invalid refresh token: {e}")

    async def logout(self, user_id: str, token: Optional[str] = None) -> None:
        """Logout user by blacklisting their token.

        Args:
            user_id: User to logout
            token: Token to blacklist (optional)
        """
        if token:
            await self._blacklist_token(token)
            logger.info(f"User logged out: {user_id}")
        else:
            logger.info(f"User logout requested without token: {user_id}")

    def _create_access_token(self, user_id: str, email: str) -> str:
        """Create JWT access token.

        Args:
            user_id: User ID
            email: User email

        Returns:
            Encoded JWT access token
        """
        now = datetime.now(timezone.utc)
        expire = now + self.access_token_expire

        payload = {
            "sub": user_id,
            "email": email,
            "type": "access",
            "iat": now,
            "exp": expire,
            "jti": str(uuid.uuid4()),  # Unique token ID
        }

        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

    def _create_refresh_token(self, user_id: str) -> str:
        """Create JWT refresh token.

        Args:
            user_id: User ID

        Returns:
            Encoded JWT refresh token
        """
        now = datetime.now(timezone.utc)
        expire = now + self.refresh_token_expire

        payload = {
            "sub": user_id,
            "type": "refresh",
            "iat": now,
            "exp": expire,
            "jti": str(uuid.uuid4()),  # Unique token ID for rotation
        }

        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

    async def _blacklist_token(self, token: str) -> None:
        """Add token to blacklist (Redis preferred, in-memory fallback).

        Args:
            token: Token to blacklist
        """
        try:
            # Try Redis first (required for multi-instance deployments)
            redis_client = await get_redis_client()
            client = redis_client.get_client()

            # Decode token to get expiration
            try:
                payload = jwt.decode(
                    token,
                    self.secret_key,
                    algorithms=[self.algorithm],
                    options={"verify_exp": False}  # Don't fail on expired tokens
                )
                exp = payload.get("exp")
                if exp:
                    ttl = int(exp - datetime.now(timezone.utc).timestamp())
                    if ttl > 0:
                        await client.setex(f"blacklist:{token}", ttl, "1")
                        logger.debug(f"Token blacklisted in Redis (TTL: {ttl}s)")
            except JWTError:
                # If token is malformed, blacklist for 1 hour as fallback
                await client.setex(f"blacklist:{token}", 3600, "1")
                logger.debug("Malformed token blacklisted in Redis (1h)")

        except Exception as e:
            # Redis unavailable - use in-memory fallback
            logger.warning(
                f"Redis unavailable for token blacklist, using in-memory fallback: {e}. "
                "WARNING: This only works for single-instance deployments!"
            )
            async with _blacklist_lock:
                _memory_blacklist.add(token)
                logger.debug(f"Token blacklisted in memory (size: {len(_memory_blacklist)})")

    async def _is_token_blacklisted(self, token: str) -> bool:
        """Check if token is blacklisted (Redis preferred, in-memory fallback).

        Args:
            token: Token to check

        Returns:
            True if token is blacklisted
        """
        try:
            # Try Redis first
            redis_client = await get_redis_client()
            client = redis_client.get_client()
            return await client.exists(f"blacklist:{token}") > 0

        except Exception as e:
            # Redis unavailable - check in-memory fallback
            logger.debug(f"Redis unavailable for blacklist check, using in-memory: {e}")
            async with _blacklist_lock:
                return token in _memory_blacklist


class AuthenticationError(Exception):
    """Authentication failed."""
    pass
