"""Unit tests for authentication models"""

from datetime import datetime, timedelta, timezone

import pytest

from auth_service.domain.models import (
    AuthToken,
    DevUser,
    TokenStatus,
    TokenValidationResult,
)

pytestmark = pytest.mark.unit


class TestDevUser:
    """Test DevUser model"""

    def test_create_user(self):
        """Test creating a user"""
        now = datetime.now(timezone.utc)
        user = DevUser(
            user_id="test-123",
            username="testuser",
            email="test@example.com",
            display_name="Test User",
            created_at=now,
        )

        assert user.user_id == "test-123"
        assert user.username == "testuser"
        assert user.email == "test@example.com"
        assert user.is_dev_user is True
        assert user.is_active is True
        assert user.roles == ["admin"]  # Default

    def test_user_to_dict(self):
        """Test user serialization to dict"""
        now = datetime.now(timezone.utc)
        user = DevUser(
            user_id="test-123",
            username="testuser",
            email="test@example.com",
            display_name="Test User",
            created_at=now,
        )

        user_dict = user.to_dict()

        assert user_dict["user_id"] == "test-123"
        assert user_dict["username"] == "testuser"
        assert user_dict["email"] == "test@example.com"
        assert user_dict["roles"] == ["admin"]
        assert isinstance(user_dict["created_at"], str)

    def test_user_from_dict(self):
        """Test user deserialization from dict"""
        user_data = {
            "user_id": "test-123",
            "username": "testuser",
            "email": "test@example.com",
            "display_name": "Test User",
            "created_at": "2025-01-15T10:00:00+00:00",
            "is_dev_user": True,
            "is_active": True,
            "roles": ["user", "admin"],
        }

        user = DevUser.from_dict(user_data)

        assert user.user_id == "test-123"
        assert user.username == "testuser"
        assert user.roles == ["user", "admin"]


class TestAuthToken:
    """Test AuthToken model"""

    def test_create_token(self):
        """Test creating an auth token"""
        now = datetime.now(timezone.utc)
        expires = now + timedelta(hours=24)

        token = AuthToken(
            token_id="token-123",
            user_id="user-456",
            token_hash="abc123",
            expires_at=expires,
            created_at=now,
        )

        assert token.token_id == "token-123"
        assert token.user_id == "user-456"
        assert token.is_revoked is False

    def test_token_is_expired(self):
        """Test token expiration check"""
        now = datetime.now(timezone.utc)
        past = now - timedelta(hours=1)

        token = AuthToken(
            token_id="token-123",
            user_id="user-456",
            token_hash="abc123",
            expires_at=past,  # Expired 1 hour ago
            created_at=now - timedelta(hours=25),
        )

        assert token.is_expired is True
        assert token.is_valid is False

    def test_token_is_valid(self):
        """Test token validity check"""
        now = datetime.now(timezone.utc)
        future = now + timedelta(hours=24)

        token = AuthToken(
            token_id="token-123",
            user_id="user-456",
            token_hash="abc123",
            expires_at=future,
            created_at=now,
        )

        assert token.is_expired is False
        assert token.is_revoked is False
        assert token.is_valid is True


class TestTokenValidationResult:
    """Test TokenValidationResult"""

    def test_valid_result(self):
        """Test valid validation result"""
        user = DevUser(
            user_id="test-123",
            username="testuser",
            email="test@example.com",
            display_name="Test User",
            created_at=datetime.now(timezone.utc),
        )

        result = TokenValidationResult(status=TokenStatus.VALID, user=user)

        assert result.is_valid is True
        assert result.is_expired is False
        assert result.user.user_id == "test-123"

    def test_expired_result(self):
        """Test expired validation result"""
        result = TokenValidationResult(
            status=TokenStatus.EXPIRED, error_message="Token has expired"
        )

        assert result.is_valid is False
        assert result.is_expired is True
        assert result.user is None

    def test_invalid_result(self):
        """Test invalid validation result"""
        result = TokenValidationResult(status=TokenStatus.INVALID, error_message="Token not found")

        assert result.is_valid is False
        assert result.is_expired is False
        assert result.user is None
