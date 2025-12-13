"""Unit tests for DevUserStore

Tests user storage operations with mocked Redis.
No external dependencies - uses unittest.mock for Redis operations.
"""

import json
import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock
from uuid import uuid4

from auth_service.domain.models.auth import DevUser
from auth_service.infrastructure.auth.user_store import DevUserStore


@pytest.fixture
def mock_redis():
    """Mock Redis client"""
    redis = AsyncMock()
    redis.set = AsyncMock(return_value=True)
    redis.get = AsyncMock(return_value=None)
    redis.delete = AsyncMock(return_value=1)
    redis.sadd = AsyncMock(return_value=1)
    redis.srem = AsyncMock(return_value=1)
    redis.smembers = AsyncMock(return_value=set())
    redis.scard = AsyncMock(return_value=0)
    return redis


@pytest.fixture
def user_store(mock_redis):
    """Create user store with mocked Redis"""
    return DevUserStore(mock_redis)


@pytest.mark.unit
class TestCreateUser:
    """Test user creation"""

    @pytest.mark.asyncio
    async def test_create_user_success(self, user_store, mock_redis):
        """Happy path: create_user generates valid user and stores in Redis"""
        # Arrange
        mock_redis.get.return_value = None  # No existing user

        # Act
        user = await user_store.create_user(
            username="testuser", email="test@example.com", display_name="Test User"
        )

        # Assert
        assert user is not None
        assert user.username == "testuser"
        assert user.email == "test@example.com"
        assert user.display_name == "Test User"
        assert user.is_dev_user is True
        assert user.is_active is True

        # Verify Redis operations
        assert mock_redis.set.call_count == 3  # user key + username key + email key
        assert mock_redis.sadd.call_count == 1  # user list

    @pytest.mark.asyncio
    async def test_create_user_auto_generate_display_name(self, user_store, mock_redis):
        """Edge case: display_name auto-generated from username"""
        # Arrange
        mock_redis.get.return_value = None

        # Act
        user = await user_store.create_user(username="john.doe")

        # Assert
        assert user.display_name == "John Doe"  # Auto-generated from username

    @pytest.mark.asyncio
    async def test_create_user_auto_generate_email_from_username(self, user_store, mock_redis):
        """Edge case: email auto-generated for non-email username"""
        # Arrange
        mock_redis.get.return_value = None

        # Act
        user = await user_store.create_user(username="testuser")

        # Assert
        assert user.email == "testuser@dev.faultmaven.local"

    @pytest.mark.asyncio
    async def test_create_user_username_is_email(self, user_store, mock_redis):
        """Edge case: username that is an email uses it directly"""
        # Arrange
        mock_redis.get.return_value = None

        # Act
        user = await user_store.create_user(username="user@example.com")

        # Assert
        assert user.email == "user@example.com"  # Username used as email
        assert user.username == "user@example.com"

    @pytest.mark.asyncio
    async def test_create_user_duplicate_username(self, user_store, mock_redis):
        """Bad input: duplicate username raises ValueError"""
        # Arrange - simulate existing user
        existing_user = DevUser(
            user_id="existing-id",
            username="testuser",
            email="existing@example.com",
            display_name="Existing User",
            created_at=datetime.now(timezone.utc),
        )
        mock_redis.get.side_effect = [
            "existing-id",  # username lookup returns existing user_id
            json.dumps(existing_user.to_dict()),  # user data
        ]

        # Act & Assert
        with pytest.raises(ValueError, match="already exists"):
            await user_store.create_user(username="testuser")

    @pytest.mark.asyncio
    async def test_create_user_duplicate_email(self, user_store, mock_redis):
        """Bad input: duplicate email raises ValueError"""
        # Arrange
        existing_user = DevUser(
            user_id="existing-id",
            username="otheruser",
            email="test@example.com",
            display_name="Existing User",
            created_at=datetime.now(timezone.utc),
        )

        # First get is username check (returns None), second get is email check
        mock_redis.get.side_effect = [
            None,  # Username doesn't exist
            "existing-id",  # Email lookup returns existing user_id
            json.dumps(existing_user.to_dict()),  # User data
        ]

        # Act & Assert
        with pytest.raises(ValueError, match="already exists"):
            await user_store.create_user(username="newuser", email="test@example.com")

    @pytest.mark.asyncio
    async def test_create_user_invalid_username(self, user_store, mock_redis):
        """Bad input: invalid username format raises ValueError"""
        # Act & Assert
        with pytest.raises(ValueError, match="Invalid username format"):
            await user_store.create_user(username="ab")  # Too short

        with pytest.raises(ValueError, match="Invalid username format"):
            await user_store.create_user(username="a" * 51)  # Too long

    @pytest.mark.asyncio
    async def test_create_user_invalid_email(self, user_store, mock_redis):
        """Bad input: invalid email format raises ValueError"""
        # Arrange
        mock_redis.get.return_value = None

        # Act & Assert
        with pytest.raises(ValueError, match="Invalid email format"):
            await user_store.create_user(username="testuser", email="not-an-email")


@pytest.mark.unit
class TestGetUser:
    """Test user retrieval by ID"""

    @pytest.mark.asyncio
    async def test_get_user_success(self, user_store, mock_redis):
        """Happy path: get_user returns user by ID"""
        # Arrange
        user = DevUser(
            user_id="user-123",
            username="testuser",
            email="test@example.com",
            display_name="Test User",
            created_at=datetime.now(timezone.utc),
        )
        mock_redis.get.return_value = json.dumps(user.to_dict())

        # Act
        result = await user_store.get_user("user-123")

        # Assert
        assert result is not None
        assert result.user_id == "user-123"
        assert result.username == "testuser"

    @pytest.mark.asyncio
    async def test_get_user_not_found(self, user_store, mock_redis):
        """Edge case: get_user returns None for nonexistent user"""
        # Arrange
        mock_redis.get.return_value = None

        # Act
        result = await user_store.get_user("nonexistent-id")

        # Assert
        assert result is None

    @pytest.mark.asyncio
    async def test_get_user_empty_id(self, user_store, mock_redis):
        """Bad input: empty user_id returns None"""
        # Act
        result = await user_store.get_user("")

        # Assert
        assert result is None


@pytest.mark.unit
class TestGetUserByUsername:
    """Test user retrieval by username"""

    @pytest.mark.asyncio
    async def test_get_user_by_username_success(self, user_store, mock_redis):
        """Happy path: get_user_by_username returns user"""
        # Arrange
        user = DevUser(
            user_id="user-123",
            username="testuser",
            email="test@example.com",
            display_name="Test User",
            created_at=datetime.now(timezone.utc),
        )
        mock_redis.get.side_effect = [
            "user-123",  # username -> user_id
            json.dumps(user.to_dict()),  # user_id -> user data
        ]

        # Act
        result = await user_store.get_user_by_username("testuser")

        # Assert
        assert result is not None
        assert result.username == "testuser"

    @pytest.mark.asyncio
    async def test_get_user_by_username_case_insensitive(self, user_store, mock_redis):
        """Edge case: username lookup is case-insensitive"""
        # Arrange
        user = DevUser(
            user_id="user-123",
            username="TestUser",
            email="test@example.com",
            display_name="Test User",
            created_at=datetime.now(timezone.utc),
        )
        mock_redis.get.side_effect = [
            "user-123",
            json.dumps(user.to_dict()),
        ]

        # Act - lookup with different case
        result = await user_store.get_user_by_username("TESTUSER")

        # Assert
        assert result is not None
        assert result.username == "TestUser"

    @pytest.mark.asyncio
    async def test_get_user_by_username_not_found(self, user_store, mock_redis):
        """Edge case: nonexistent username returns None"""
        # Arrange
        mock_redis.get.return_value = None

        # Act
        result = await user_store.get_user_by_username("nonexistent")

        # Assert
        assert result is None


@pytest.mark.unit
class TestGetUserByEmail:
    """Test user retrieval by email"""

    @pytest.mark.asyncio
    async def test_get_user_by_email_success(self, user_store, mock_redis):
        """Happy path: get_user_by_email returns user"""
        # Arrange
        user = DevUser(
            user_id="user-123",
            username="testuser",
            email="test@example.com",
            display_name="Test User",
            created_at=datetime.now(timezone.utc),
        )
        mock_redis.get.side_effect = [
            "user-123",  # email -> user_id
            json.dumps(user.to_dict()),  # user_id -> user data
        ]

        # Act
        result = await user_store.get_user_by_email("test@example.com")

        # Assert
        assert result is not None
        assert result.email == "test@example.com"

    @pytest.mark.asyncio
    async def test_get_user_by_email_case_insensitive(self, user_store, mock_redis):
        """Edge case: email lookup is case-insensitive"""
        # Arrange
        user = DevUser(
            user_id="user-123",
            username="testuser",
            email="test@example.com",
            display_name="Test User",
            created_at=datetime.now(timezone.utc),
        )
        mock_redis.get.side_effect = [
            "user-123",
            json.dumps(user.to_dict()),
        ]

        # Act - lookup with different case
        result = await user_store.get_user_by_email("TEST@EXAMPLE.COM")

        # Assert
        assert result is not None

    @pytest.mark.asyncio
    async def test_get_user_by_email_not_found(self, user_store, mock_redis):
        """Edge case: nonexistent email returns None"""
        # Arrange
        mock_redis.get.return_value = None

        # Act
        result = await user_store.get_user_by_email("nonexistent@example.com")

        # Assert
        assert result is None


@pytest.mark.unit
class TestUpdateUser:
    """Test user update"""

    @pytest.mark.asyncio
    async def test_update_user_success(self, user_store, mock_redis):
        """Happy path: update_user modifies user data"""
        # Arrange
        existing_user = DevUser(
            user_id="user-123",
            username="testuser",
            email="old@example.com",
            display_name="Old Name",
            created_at=datetime.now(timezone.utc),
        )

        updated_user = DevUser(
            user_id="user-123",
            username="testuser",
            email="new@example.com",
            display_name="New Name",
            created_at=existing_user.created_at,
        )

        mock_redis.get.side_effect = [
            json.dumps(existing_user.to_dict()),  # get existing user
            None,  # email uniqueness check
        ]

        # Act
        result = await user_store.update_user(updated_user)

        # Assert
        assert result.email == "new@example.com"
        assert result.display_name == "New Name"
        assert mock_redis.set.call_count >= 1  # User data updated
        assert mock_redis.delete.call_count == 1  # Old email mapping deleted

    @pytest.mark.asyncio
    async def test_update_user_not_found(self, user_store, mock_redis):
        """Bad input: updating nonexistent user raises ValueError"""
        # Arrange
        user = DevUser(
            user_id="nonexistent",
            username="testuser",
            email="test@example.com",
            display_name="Test",
            created_at=datetime.now(timezone.utc),
        )
        mock_redis.get.return_value = None  # User doesn't exist

        # Act & Assert
        with pytest.raises(ValueError, match="not found"):
            await user_store.update_user(user)


@pytest.mark.unit
class TestDeleteUser:
    """Test user deletion"""

    @pytest.mark.asyncio
    async def test_delete_user_success(self, user_store, mock_redis):
        """Happy path: delete_user removes user from storage"""
        # Arrange
        user = DevUser(
            user_id="user-123",
            username="testuser",
            email="test@example.com",
            display_name="Test User",
            created_at=datetime.now(timezone.utc),
        )
        mock_redis.get.return_value = json.dumps(user.to_dict())

        # Act
        result = await user_store.delete_user("user-123")

        # Assert
        assert result is True
        assert mock_redis.delete.call_count == 3  # user, username, email keys
        assert mock_redis.srem.call_count == 1  # user list

    @pytest.mark.asyncio
    async def test_delete_user_not_found(self, user_store, mock_redis):
        """Edge case: deleting nonexistent user returns False"""
        # Arrange
        mock_redis.get.return_value = None

        # Act
        result = await user_store.delete_user("nonexistent")

        # Assert
        assert result is False


@pytest.mark.unit
class TestValidation:
    """Test validation methods"""

    def test_validate_username_valid(self, user_store):
        """Happy path: valid usernames pass validation"""
        assert user_store._validate_username("testuser") is True
        assert user_store._validate_username("test.user") is True
        assert user_store._validate_username("test_user") is True
        assert user_store._validate_username("test-user") is True
        assert user_store._validate_username("user123") is True
        assert user_store._validate_username("test@example.com") is True  # Email allowed

    def test_validate_username_invalid(self, user_store):
        """Bad input: invalid usernames fail validation"""
        assert user_store._validate_username("ab") is False  # Too short
        assert user_store._validate_username("a" * 51) is False  # Too long
        assert user_store._validate_username("") is False  # Empty

    def test_validate_email_valid(self, user_store):
        """Happy path: valid emails pass validation"""
        assert user_store._validate_email("test@example.com") is True
        assert user_store._validate_email("user.name@domain.co.uk") is True

    def test_validate_email_invalid(self, user_store):
        """Bad input: invalid emails fail validation"""
        assert user_store._validate_email("not-an-email") is False
        assert user_store._validate_email("@example.com") is False
        assert user_store._validate_email("user@") is False
        assert user_store._validate_email("") is False

    def test_generate_display_name_from_username(self, user_store):
        """Edge case: display name generated from username"""
        assert user_store._generate_display_name("john.doe") == "John Doe"
        assert user_store._generate_display_name("jane_smith") == "Jane Smith"
        assert user_store._generate_display_name("bob-jones") == "Bob Jones"

    def test_generate_display_name_from_email(self, user_store):
        """Edge case: display name generated from email"""
        assert user_store._generate_display_name("john.doe@example.com") == "John Doe"
        assert user_store._generate_display_name("jane_smith@test.org") == "Jane Smith"
