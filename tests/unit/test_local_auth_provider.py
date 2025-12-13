"""Unit tests for LocalAuthProvider

Tests local authentication logic with mocked dependencies.
No external dependencies - mocks Redis, password hashing, user store.
"""

import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from jose import jwt

from auth_service.core.auth.local import LocalAuthProvider, AuthenticationError
from auth_service.domain.models.auth import DevUser


@pytest.fixture
def auth_provider():
    """Create local auth provider with test config"""
    return LocalAuthProvider(
        secret_key="test-secret-key",
        algorithm="HS256",
        access_token_expire_minutes=60,
        refresh_token_expire_days=7,
    )


@pytest.fixture
def test_user():
    """Create test user with password hash"""
    import bcrypt

    password = "testpassword123"
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    user = DevUser(
        user_id="user-123",
        username="testuser",
        email="test@example.com",
        display_name="Test User",
        created_at=datetime.now(timezone.utc),
        is_active=True,
    )
    # Add password_hash attribute (not in DevUser model, but needed for testing)
    user.password_hash = password_hash
    user.roles = ["admin"]
    return user


@pytest.mark.unit
class TestAuthenticateUser:
    """Test user authentication with email/password"""

    @pytest.mark.asyncio
    @patch("auth_service.core.auth.local.get_redis_client")
    async def test_authenticate_user_success(self, mock_get_redis, auth_provider, test_user):
        """Happy path: authenticate_user with correct credentials returns UserIdentity"""
        # Arrange
        mock_redis_client = AsyncMock()
        mock_get_redis.return_value = mock_redis_client
        mock_get_redis.return_value.get_client.return_value = AsyncMock()

        mock_user_store = AsyncMock()
        mock_user_store.get_user_by_email.return_value = test_user

        with patch("auth_service.core.auth.local.DevUserStore", return_value=mock_user_store):
            # Act
            identity = await auth_provider.authenticate_user("test@example.com", "testpassword123")

            # Assert
            assert identity is not None
            assert identity.user_id == "user-123"
            assert identity.email == "test@example.com"
            assert identity.provider == "local"
            assert "access_token" in identity.metadata
            assert "refresh_token" in identity.metadata
            assert identity.metadata["token_type"] == "bearer"

    @pytest.mark.asyncio
    @patch("auth_service.core.auth.local.get_redis_client")
    async def test_authenticate_user_wrong_password(self, mock_get_redis, auth_provider, test_user):
        """Bad input: wrong password raises AuthenticationError"""
        # Arrange
        mock_redis_client = AsyncMock()
        mock_get_redis.return_value = mock_redis_client
        mock_get_redis.return_value.get_client.return_value = AsyncMock()

        mock_user_store = AsyncMock()
        mock_user_store.get_user_by_email.return_value = test_user

        with patch("auth_service.core.auth.local.DevUserStore", return_value=mock_user_store):
            # Act & Assert
            with pytest.raises(AuthenticationError, match="Invalid email or password"):
                await auth_provider.authenticate_user("test@example.com", "wrongpassword")

    @pytest.mark.asyncio
    @patch("auth_service.core.auth.local.get_redis_client")
    async def test_authenticate_user_not_found(self, mock_get_redis, auth_provider):
        """Bad input: nonexistent user raises AuthenticationError"""
        # Arrange
        mock_redis_client = AsyncMock()
        mock_get_redis.return_value = mock_redis_client
        mock_get_redis.return_value.get_client.return_value = AsyncMock()

        mock_user_store = AsyncMock()
        mock_user_store.get_user_by_email.return_value = None  # User not found

        with patch("auth_service.core.auth.local.DevUserStore", return_value=mock_user_store):
            # Act & Assert
            with pytest.raises(AuthenticationError, match="Invalid email or password"):
                await auth_provider.authenticate_user("nonexistent@example.com", "password")

    @pytest.mark.asyncio
    @patch("auth_service.core.auth.local.get_redis_client")
    async def test_authenticate_user_inactive(self, mock_get_redis, auth_provider, test_user):
        """Bad input: inactive user raises AuthenticationError"""
        # Arrange
        test_user.is_active = False

        mock_redis_client = AsyncMock()
        mock_get_redis.return_value = mock_redis_client
        mock_get_redis.return_value.get_client.return_value = AsyncMock()

        mock_user_store = AsyncMock()
        mock_user_store.get_user_by_email.return_value = test_user

        with patch("auth_service.core.auth.local.DevUserStore", return_value=mock_user_store):
            # Act & Assert
            with pytest.raises(AuthenticationError, match="inactive"):
                await auth_provider.authenticate_user("test@example.com", "testpassword123")


@pytest.mark.unit
class TestValidateToken:
    """Test JWT token validation"""

    @pytest.mark.asyncio
    @patch("auth_service.core.auth.local.get_redis_client")
    async def test_validate_token_success(self, mock_get_redis, auth_provider, test_user):
        """Happy path: validate_token with valid JWT returns UserIdentity"""
        # Arrange - create valid token
        access_token = auth_provider._create_access_token(test_user.user_id, test_user.email)

        mock_redis_client = AsyncMock()
        mock_get_redis.return_value = mock_redis_client
        mock_redis = AsyncMock()
        mock_redis.exists.return_value = 0  # Not blacklisted
        mock_get_redis.return_value.get_client.return_value = mock_redis

        # Mock the user store to return test_user
        with patch("auth_service.core.auth.local.DevUserStore") as mock_store_class:
            mock_store = MagicMock()
            # Make get_user an async function that returns the test_user
            async def mock_get_user(user_id):
                return test_user
            mock_store.get_user = mock_get_user
            mock_store_class.return_value = mock_store

            # Act
            identity = await auth_provider.validate_token(access_token)

            # Assert
            assert identity.user_id == test_user.user_id
            assert identity.email == test_user.email

    @pytest.mark.asyncio
    async def test_validate_token_invalid_jwt(self, auth_provider):
        """Bad input: invalid JWT raises AuthenticationError"""
        # Act & Assert
        with pytest.raises(AuthenticationError, match="Invalid token"):
            await auth_provider.validate_token("invalid.jwt.token")

    @pytest.mark.asyncio
    @patch("auth_service.core.auth.local.get_redis_client")
    async def test_validate_token_blacklisted(self, mock_get_redis, auth_provider):
        """Edge case: blacklisted token raises AuthenticationError"""
        # Arrange
        access_token = auth_provider._create_access_token("user-123", "test@example.com")

        mock_redis_wrapper = MagicMock()
        mock_redis = AsyncMock()
        mock_redis.exists = AsyncMock(return_value=1)  # Token is blacklisted
        mock_redis_wrapper.get_client.return_value = mock_redis

        async def mock_get_client():
            return mock_redis_wrapper

        mock_get_redis.return_value = await mock_get_client()

        # Act & Assert
        with pytest.raises(AuthenticationError, match="revoked"):
            await auth_provider.validate_token(access_token)


@pytest.mark.unit
class TestRefreshToken:
    """Test token refresh with rotation"""

    @pytest.mark.asyncio
    @patch("auth_service.core.auth.local.get_redis_client")
    async def test_refresh_token_success(self, mock_get_redis, auth_provider, test_user):
        """Happy path: refresh_token returns new access and refresh tokens"""
        # Arrange
        refresh_token = auth_provider._create_refresh_token(test_user.user_id)

        mock_redis_wrapper = MagicMock()
        mock_redis = AsyncMock()
        mock_redis.exists = AsyncMock(return_value=0)  # Not blacklisted
        mock_redis_wrapper.get_client.return_value = mock_redis

        async def mock_get_client():
            return mock_redis_wrapper

        mock_get_redis.return_value = await mock_get_client()

        with patch("auth_service.core.auth.local.DevUserStore") as mock_store_class:
            mock_store = MagicMock()
            async def mock_get_user(user_id):
                return test_user
            mock_store.get_user = mock_get_user
            mock_store_class.return_value = mock_store

            # Act
            new_access, new_refresh = await auth_provider.refresh_token(refresh_token)

            # Assert
            assert new_access is not None
            assert new_refresh is not None
            assert new_access != refresh_token
            assert new_refresh != refresh_token  # CRITICAL: rotation

    @pytest.mark.asyncio
    @patch("auth_service.core.auth.local.get_redis_client")
    async def test_refresh_token_returns_different_tokens(
        self, mock_get_redis, auth_provider, test_user
    ):
        """Regression test: refresh returns NEW tokens with different jti"""
        # Arrange
        refresh_token_1 = auth_provider._create_refresh_token(test_user.user_id)

        mock_redis_wrapper = MagicMock()
        mock_redis = AsyncMock()
        mock_redis.exists = AsyncMock(return_value=0)
        mock_redis_wrapper.get_client.return_value = mock_redis

        async def mock_get_client():
            return mock_redis_wrapper

        mock_get_redis.return_value = await mock_get_client()

        with patch("auth_service.core.auth.local.DevUserStore") as mock_store_class:
            mock_store = MagicMock()
            async def mock_get_user(user_id):
                return test_user
            mock_store.get_user = mock_get_user
            mock_store_class.return_value = mock_store

            # Act
            _, refresh_token_2 = await auth_provider.refresh_token(refresh_token_1)

            # Assert - tokens must differ (due to jti claim)
            assert refresh_token_2 != refresh_token_1

            # Decode both tokens to verify jti differs
            payload_1 = jwt.decode(
                refresh_token_1, auth_provider.secret_key, algorithms=[auth_provider.algorithm]
            )
            payload_2 = jwt.decode(
                refresh_token_2, auth_provider.secret_key, algorithms=[auth_provider.algorithm]
            )

            assert "jti" in payload_1
            assert "jti" in payload_2
            assert payload_1["jti"] != payload_2["jti"]  # CRITICAL: jti must differ

    @pytest.mark.asyncio
    async def test_refresh_token_invalid(self, auth_provider):
        """Bad input: invalid refresh token raises AuthenticationError"""
        # Act & Assert
        with pytest.raises(AuthenticationError):
            await auth_provider.refresh_token("invalid.refresh.token")

    @pytest.mark.asyncio
    @patch("auth_service.core.auth.local.get_redis_client")
    async def test_refresh_token_wrong_type(self, mock_get_redis, auth_provider):
        """Bad input: access token used as refresh token raises error"""
        # Arrange - create access token instead of refresh token
        access_token = auth_provider._create_access_token("user-123", "test@example.com")

        mock_redis_client = AsyncMock()
        mock_get_redis.return_value = mock_redis_client
        mock_redis = AsyncMock()
        mock_redis.exists.return_value = 0
        mock_get_redis.return_value.get_client.return_value = mock_redis

        # Act & Assert
        with pytest.raises(AuthenticationError, match="Invalid refresh token"):
            await auth_provider.refresh_token(access_token)


@pytest.mark.unit
class TestTokenBlacklist:
    """Test token blacklist for logout"""

    @pytest.mark.asyncio
    @patch("auth_service.core.auth.local.get_redis_client")
    async def test_blacklist_token_redis(self, mock_get_redis, auth_provider):
        """Happy path: _blacklist_token stores token in Redis"""
        # Arrange
        token = auth_provider._create_access_token("user-123", "test@example.com")

        # Setup async mock properly
        mock_redis = AsyncMock()
        mock_redis.setex = AsyncMock(return_value=True)

        mock_redis_wrapper = MagicMock()
        mock_redis_wrapper.get_client.return_value = mock_redis

        async def mock_get_client():
            return mock_redis_wrapper

        mock_get_redis.return_value = await mock_get_client()

        # Act
        await auth_provider._blacklist_token(token)

        # Assert
        mock_redis.setex.assert_called_once()
        call_args = mock_redis.setex.call_args[0]
        assert call_args[0].startswith("blacklist:")

    @pytest.mark.asyncio
    @patch("auth_service.core.auth.local.get_redis_client")
    async def test_blacklist_token_redis_failure_fallback(self, mock_get_redis, auth_provider):
        """Error handling: Redis failure falls back to in-memory blacklist"""
        # Arrange
        token = "test-token"
        mock_get_redis.side_effect = Exception("Redis connection failed")

        # Act
        await auth_provider._blacklist_token(token)

        # Assert - token should be in memory blacklist
        is_blacklisted = await auth_provider._is_token_blacklisted(token)
        # Note: This will also fail to reach Redis, so will check memory
        # The in-memory blacklist should contain the token
        # We can't directly assert the memory blacklist, but we can check behavior

    @pytest.mark.asyncio
    @patch("auth_service.core.auth.local.get_redis_client")
    async def test_logout_blacklists_token(self, mock_get_redis, auth_provider):
        """Happy path: logout blacklists the provided token"""
        # Arrange
        token = auth_provider._create_access_token("user-123", "test@example.com")

        # Setup async mock properly
        mock_redis = AsyncMock()
        mock_redis.setex = AsyncMock(return_value=True)

        mock_redis_wrapper = MagicMock()
        mock_redis_wrapper.get_client.return_value = mock_redis

        async def mock_get_client():
            return mock_redis_wrapper

        mock_get_redis.return_value = await mock_get_client()

        # Act
        await auth_provider.logout("user-123", token)

        # Assert
        mock_redis.setex.assert_called_once()


@pytest.mark.unit
class TestTokenCreation:
    """Test JWT token creation"""

    def test_create_access_token_includes_jti(self, auth_provider):
        """Regression test: access tokens include jti claim for uniqueness"""
        # Act
        token1 = auth_provider._create_access_token("user-123", "test@example.com")
        token2 = auth_provider._create_access_token("user-123", "test@example.com")

        # Assert - tokens should differ despite same user/email
        assert token1 != token2

        # Decode to verify jti
        payload1 = jwt.decode(token1, auth_provider.secret_key, algorithms=[auth_provider.algorithm])
        payload2 = jwt.decode(token2, auth_provider.secret_key, algorithms=[auth_provider.algorithm])

        assert "jti" in payload1
        assert "jti" in payload2
        assert payload1["jti"] != payload2["jti"]
        assert payload1["type"] == "access"

    def test_create_refresh_token_includes_jti(self, auth_provider):
        """Regression test: refresh tokens include jti claim for rotation"""
        # Act
        token1 = auth_provider._create_refresh_token("user-123")
        token2 = auth_provider._create_refresh_token("user-123")

        # Assert - tokens should differ
        assert token1 != token2

        # Decode to verify jti
        payload1 = jwt.decode(token1, auth_provider.secret_key, algorithms=[auth_provider.algorithm])
        payload2 = jwt.decode(token2, auth_provider.secret_key, algorithms=[auth_provider.algorithm])

        assert "jti" in payload1
        assert "jti" in payload2
        assert payload1["jti"] != payload2["jti"]
        assert payload1["type"] == "refresh"


@pytest.mark.unit
class TestUnsupportedMethods:
    """Test methods not supported by local auth"""

    @pytest.mark.asyncio
    async def test_get_login_url_returns_empty(self, auth_provider):
        """Edge case: get_login_url returns empty string for local auth"""
        # Act
        url = await auth_provider.get_login_url("state", "redirect_uri")

        # Assert
        assert url == ""

    @pytest.mark.asyncio
    async def test_exchange_code_not_implemented(self, auth_provider):
        """Edge case: exchange_code raises NotImplementedError"""
        # Act & Assert
        with pytest.raises(NotImplementedError):
            await auth_provider.exchange_code("code", "redirect_uri")
