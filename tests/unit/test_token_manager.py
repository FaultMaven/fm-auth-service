"""Unit tests for DevTokenManager

Tests token lifecycle operations with mocked Redis.
No external dependencies - uses unittest.mock for Redis operations.
"""

import json
import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from auth_service.domain.models.auth import AuthToken, DevUser, TokenStatus
from auth_service.infrastructure.auth.token_manager import DevTokenManager


@pytest.fixture
def mock_redis():
    """Mock Redis client"""
    redis = AsyncMock()
    redis.setex = AsyncMock(return_value=True)
    redis.set = AsyncMock(return_value=True)
    redis.get = AsyncMock(return_value=None)
    redis.delete = AsyncMock(return_value=1)
    redis.sadd = AsyncMock(return_value=1)
    redis.smembers = AsyncMock(return_value=set())
    redis.expire = AsyncMock(return_value=True)
    return redis


@pytest.fixture
def token_manager(mock_redis):
    """Create token manager with mocked Redis"""
    return DevTokenManager(mock_redis)


@pytest.fixture
def test_user():
    """Create test user"""
    return DevUser(
        user_id="user-123",
        username="testuser",
        email="test@example.com",
        display_name="Test User",
        created_at=datetime.now(timezone.utc),
        is_active=True,
    )


@pytest.mark.unit
class TestCreateToken:
    """Test token creation"""

    @pytest.mark.asyncio
    async def test_create_token_success(self, token_manager, mock_redis, test_user):
        """Happy path: create_token generates valid token and stores in Redis"""
        # Act
        token = await token_manager.create_token(test_user)

        # Assert
        assert token is not None
        assert len(token) == 36  # UUID format

        # Verify Redis operations called
        assert mock_redis.setex.call_count >= 2  # token key + meta key
        assert mock_redis.sadd.call_count == 1  # user tokens set
        assert mock_redis.expire.call_count == 1  # user tokens set expiry

    @pytest.mark.asyncio
    async def test_create_token_stores_correct_data(self, token_manager, mock_redis, test_user):
        """Verify token storage includes correct user_id and metadata"""
        # Act
        token = await token_manager.create_token(test_user)

        # Assert - check setex was called with user_id
        setex_calls = mock_redis.setex.call_args_list

        # First call should store token_hash -> user_id
        token_key_call = setex_calls[0]
        assert test_user.user_id in str(token_key_call)

        # Second call should store token metadata
        meta_call = setex_calls[1]
        meta_json = meta_call[0][2]  # Third arg to setex
        meta_dict = json.loads(meta_json)
        assert meta_dict["user_id"] == test_user.user_id
        assert "token_id" in meta_dict
        assert "token_hash" in meta_dict
        assert "expires_at" in meta_dict

    @pytest.mark.asyncio
    async def test_create_token_redis_failure_raises(self, token_manager, mock_redis, test_user):
        """Error handling: Redis failure propagates exception"""
        # Arrange
        mock_redis.setex.side_effect = Exception("Redis connection failed")

        # Act & Assert
        with pytest.raises(Exception, match="Redis connection failed"):
            await token_manager.create_token(test_user)


@pytest.mark.unit
class TestValidateToken:
    """Test token validation"""

    @pytest.mark.asyncio
    async def test_validate_token_success(self, token_manager, mock_redis, test_user):
        """Happy path: valid token returns VALID status with user"""
        # Arrange - simulate stored token
        token = "test-token-uuid"
        token_hash = token_manager._hash_token(token)
        token_id = str(uuid4())

        expires_at = datetime.now(timezone.utc) + timedelta(hours=24)
        auth_token = AuthToken(
            token_id=token_id,
            user_id=test_user.user_id,
            token_hash=token_hash,
            expires_at=expires_at,
            created_at=datetime.now(timezone.utc),
        )

        # Mock Redis responses
        mock_redis.get.side_effect = [
            test_user.user_id,  # First call: token key -> user_id
            json.dumps(auth_token.to_dict()),  # Second call: meta key -> metadata
        ]
        mock_redis.smembers.return_value = {token_id}

        # Mock user store
        mock_user_store = AsyncMock()
        mock_user_store.get_user = AsyncMock(return_value=test_user)

        # Act
        result = await token_manager.validate_token(token, user_store=mock_user_store)

        # Assert
        assert result.status == TokenStatus.VALID
        assert result.user is not None
        assert result.user.user_id == test_user.user_id
        assert result.error_message is None

    @pytest.mark.asyncio
    async def test_validate_token_empty_token(self, token_manager):
        """Bad input: empty token returns INVALID"""
        # Act
        result = await token_manager.validate_token("")

        # Assert
        assert result.status == TokenStatus.INVALID
        assert result.error_message == "Token is empty"
        assert result.user is None

    @pytest.mark.asyncio
    async def test_validate_token_not_found(self, token_manager, mock_redis):
        """Edge case: token not in Redis returns INVALID"""
        # Arrange
        mock_redis.get.return_value = None  # Token not found

        # Act
        result = await token_manager.validate_token("nonexistent-token")

        # Assert
        assert result.status == TokenStatus.INVALID
        assert "not found or expired" in result.error_message

    @pytest.mark.asyncio
    async def test_validate_token_expired(self, token_manager, mock_redis):
        """Edge case: expired token returns EXPIRED status"""
        # Arrange
        token = "expired-token"
        token_hash = token_manager._hash_token(token)
        token_id = str(uuid4())

        # Token expired 1 hour ago
        expired_at = datetime.now(timezone.utc) - timedelta(hours=1)
        auth_token = AuthToken(
            token_id=token_id,
            user_id="user-123",
            token_hash=token_hash,
            expires_at=expired_at,
            created_at=datetime.now(timezone.utc) - timedelta(hours=25),
        )

        mock_redis.get.side_effect = [
            "user-123",
            json.dumps(auth_token.to_dict()),
        ]
        mock_redis.smembers.return_value = {token_id}

        # Act
        result = await token_manager.validate_token(token)

        # Assert
        assert result.status == TokenStatus.EXPIRED
        assert "expired" in result.error_message.lower()

    @pytest.mark.asyncio
    async def test_validate_token_revoked(self, token_manager, mock_redis):
        """Edge case: revoked token returns REVOKED status"""
        # Arrange
        token = "revoked-token"
        token_hash = token_manager._hash_token(token)
        token_id = str(uuid4())

        auth_token = AuthToken(
            token_id=token_id,
            user_id="user-123",
            token_hash=token_hash,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
            created_at=datetime.now(timezone.utc),
            is_revoked=True,
        )

        mock_redis.get.side_effect = [
            "user-123",
            json.dumps(auth_token.to_dict()),
        ]
        mock_redis.smembers.return_value = {token_id}

        # Act
        result = await token_manager.validate_token(token)

        # Assert
        assert result.status == TokenStatus.REVOKED
        assert "revoked" in result.error_message.lower()


@pytest.mark.unit
class TestRevokeToken:
    """Test token revocation"""

    @pytest.mark.asyncio
    async def test_revoke_token_success(self, token_manager, mock_redis):
        """Happy path: revoke_token marks token as revoked and removes from active tokens"""
        # Arrange
        token = "valid-token"
        token_hash = token_manager._hash_token(token)
        token_id = str(uuid4())
        user_id = "user-123"

        auth_token = AuthToken(
            token_id=token_id,
            user_id=user_id,
            token_hash=token_hash,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
            created_at=datetime.now(timezone.utc),
        )

        mock_redis.get.side_effect = [
            user_id,  # First get: token key -> user_id
            json.dumps(auth_token.to_dict()),  # Second get: meta key
        ]
        mock_redis.smembers.return_value = {token_id}

        # Act
        result = await token_manager.revoke_token(token)

        # Assert
        assert result is True
        assert mock_redis.delete.call_count == 1  # Token key deleted
        assert mock_redis.setex.call_count == 1  # Metadata updated with is_revoked=True

    @pytest.mark.asyncio
    async def test_revoke_token_not_found(self, token_manager, mock_redis):
        """Edge case: revoking nonexistent token returns False"""
        # Arrange
        mock_redis.get.return_value = None  # Token doesn't exist

        # Act
        result = await token_manager.revoke_token("nonexistent-token")

        # Assert
        assert result is False


@pytest.mark.unit
class TestRevokeUserTokens:
    """Test bulk user token revocation"""

    @pytest.mark.asyncio
    async def test_revoke_user_tokens_success(self, token_manager, mock_redis):
        """Happy path: revoke_user_tokens revokes all user tokens"""
        # Arrange
        user_id = "user-123"
        token_id_1 = str(uuid4())
        token_id_2 = str(uuid4())

        token_1 = AuthToken(
            token_id=token_id_1,
            user_id=user_id,
            token_hash="hash1",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
            created_at=datetime.now(timezone.utc),
        )
        token_2 = AuthToken(
            token_id=token_id_2,
            user_id=user_id,
            token_hash="hash2",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
            created_at=datetime.now(timezone.utc),
        )

        mock_redis.smembers.return_value = {token_id_1, token_id_2}
        mock_redis.get.side_effect = [
            json.dumps(token_1.to_dict()),
            json.dumps(token_2.to_dict()),
        ]

        # Act
        count = await token_manager.revoke_user_tokens(user_id)

        # Assert
        assert count == 2
        assert mock_redis.delete.call_count == 2  # Both tokens deleted
        assert mock_redis.setex.call_count == 2  # Both metadata updated

    @pytest.mark.asyncio
    async def test_revoke_user_tokens_no_tokens(self, token_manager, mock_redis):
        """Edge case: revoking tokens for user with no tokens returns 0"""
        # Arrange
        mock_redis.smembers.return_value = set()  # No tokens

        # Act
        count = await token_manager.revoke_user_tokens("user-no-tokens")

        # Assert
        assert count == 0


@pytest.mark.unit
class TestGetUserTokens:
    """Test retrieving user tokens"""

    @pytest.mark.asyncio
    async def test_get_user_tokens_success(self, token_manager, mock_redis):
        """Happy path: get_user_tokens returns list of user's tokens"""
        # Arrange
        user_id = "user-123"
        token_id = str(uuid4())

        auth_token = AuthToken(
            token_id=token_id,
            user_id=user_id,
            token_hash="hash123",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
            created_at=datetime.now(timezone.utc),
        )

        mock_redis.smembers.return_value = {token_id}
        mock_redis.get.return_value = json.dumps(auth_token.to_dict())

        # Act
        tokens = await token_manager.get_user_tokens(user_id)

        # Assert
        assert len(tokens) == 1
        assert tokens[0].token_id == token_id
        assert tokens[0].user_id == user_id

    @pytest.mark.asyncio
    async def test_get_user_tokens_empty(self, token_manager, mock_redis):
        """Edge case: user with no tokens returns empty list"""
        # Arrange
        mock_redis.smembers.return_value = set()

        # Act
        tokens = await token_manager.get_user_tokens("user-no-tokens")

        # Assert
        assert tokens == []
