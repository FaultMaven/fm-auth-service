"""
Unit tests for security utilities (password hashing and JWT tokens).
"""

from datetime import timedelta
from uuid import uuid4

import pytest
from jose import JWTError, jwt

from enterprise.config.settings import get_settings
from enterprise.security import (
    create_access_token,
    create_refresh_token,
    hash_password,
    verify_password,
    verify_token,
)

pytestmark = pytest.mark.unit

settings = get_settings()


class TestPasswordHashing:
    """Test password hashing and verification."""

    def test_hash_password_returns_string(self):
        """Test that hash_password returns a string."""
        password = "testpassword123"
        hashed = hash_password(password)

        assert isinstance(hashed, str)
        assert len(hashed) > 0
        assert hashed != password

    def test_hash_password_different_each_time(self):
        """Test that same password produces different hashes (salt)."""
        password = "testpassword123"
        hash1 = hash_password(password)
        hash2 = hash_password(password)

        assert hash1 != hash2

    def test_verify_password_correct(self):
        """Test password verification with correct password."""
        password = "testpassword123"
        hashed = hash_password(password)

        assert verify_password(password, hashed) is True

    def test_verify_password_incorrect(self):
        """Test password verification with incorrect password."""
        password = "testpassword123"
        wrong_password = "wrongpassword"
        hashed = hash_password(password)

        assert verify_password(wrong_password, hashed) is False

    def test_verify_password_empty(self):
        """Test password verification with empty password."""
        hashed = hash_password("testpassword123")

        assert verify_password("", hashed) is False

    def test_verify_password_invalid_hash(self):
        """Test password verification with invalid hash."""
        assert verify_password("testpassword123", "invalid_hash") is False


class TestAccessTokenGeneration:
    """Test access token generation."""

    def test_create_access_token_returns_string(self):
        """Test that create_access_token returns a JWT string."""
        user_id = uuid4()
        org_id = uuid4()
        email = "test@example.com"

        token = create_access_token(user_id=user_id, organization_id=org_id, email=email)

        assert isinstance(token, str)
        assert len(token) > 0

    def test_access_token_contains_correct_claims(self):
        """Test that access token contains expected claims."""
        user_id = uuid4()
        org_id = uuid4()
        email = "test@example.com"

        token = create_access_token(user_id=user_id, organization_id=org_id, email=email)

        # Decode token without verification for testing
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])

        assert payload["sub"] == str(user_id)
        assert payload["email"] == email
        assert payload["org_id"] == str(org_id)
        assert payload["type"] == "access"
        assert "exp" in payload
        assert "iat" in payload

    def test_access_token_custom_expiration(self):
        """Test access token with custom expiration."""
        user_id = uuid4()
        org_id = uuid4()
        email = "test@example.com"
        custom_expiry = timedelta(minutes=60)

        token = create_access_token(
            user_id=user_id, organization_id=org_id, email=email, expires_delta=custom_expiry
        )

        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])

        # Verify expiration is approximately 60 minutes from now
        exp_diff = payload["exp"] - payload["iat"]
        assert exp_diff == 3600  # 60 minutes in seconds

    def test_access_token_signature_valid(self):
        """Test that access token signature is valid."""
        user_id = uuid4()
        org_id = uuid4()
        email = "test@example.com"

        token = create_access_token(user_id=user_id, organization_id=org_id, email=email)

        # Should not raise exception
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])

        assert payload is not None


class TestRefreshTokenGeneration:
    """Test refresh token generation."""

    def test_create_refresh_token_returns_string(self):
        """Test that create_refresh_token returns a JWT string."""
        user_id = uuid4()

        token = create_refresh_token(user_id=user_id)

        assert isinstance(token, str)
        assert len(token) > 0

    def test_refresh_token_contains_correct_claims(self):
        """Test that refresh token contains expected claims."""
        user_id = uuid4()

        token = create_refresh_token(user_id=user_id)

        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])

        assert payload["sub"] == str(user_id)
        assert payload["type"] == "refresh"
        assert "exp" in payload
        assert "iat" in payload
        # Refresh token should not have email or org_id
        assert "email" not in payload
        assert "org_id" not in payload

    def test_refresh_token_custom_expiration(self):
        """Test refresh token with custom expiration."""
        user_id = uuid4()
        custom_expiry = timedelta(days=14)

        token = create_refresh_token(user_id=user_id, expires_delta=custom_expiry)

        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])

        # Verify expiration is approximately 14 days from now
        exp_diff = payload["exp"] - payload["iat"]
        assert exp_diff == 14 * 24 * 60 * 60  # 14 days in seconds

    def test_refresh_token_different_from_access_token(self):
        """Test that refresh token has different claims than access token."""
        user_id = uuid4()
        org_id = uuid4()
        email = "test@example.com"

        access_token = create_access_token(user_id=user_id, organization_id=org_id, email=email)
        refresh_token = create_refresh_token(user_id=user_id)

        access_payload = jwt.decode(
            access_token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM]
        )
        refresh_payload = jwt.decode(
            refresh_token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM]
        )

        assert access_payload["type"] == "access"
        assert refresh_payload["type"] == "refresh"
        assert "email" in access_payload
        assert "email" not in refresh_payload


class TestTokenVerification:
    """Test token verification."""

    def test_verify_access_token_success(self):
        """Test successful access token verification."""
        user_id = uuid4()
        org_id = uuid4()
        email = "test@example.com"

        token = create_access_token(user_id=user_id, organization_id=org_id, email=email)

        payload = verify_token(token, token_type="access")

        assert payload["sub"] == str(user_id)
        assert payload["type"] == "access"

    def test_verify_refresh_token_success(self):
        """Test successful refresh token verification."""
        user_id = uuid4()

        token = create_refresh_token(user_id=user_id)

        payload = verify_token(token, token_type="refresh")

        assert payload["sub"] == str(user_id)
        assert payload["type"] == "refresh"

    def test_verify_token_wrong_type(self):
        """Test token verification with wrong type expectation."""
        user_id = uuid4()

        # Create refresh token but try to verify as access token
        token = create_refresh_token(user_id=user_id)

        with pytest.raises(ValueError, match="Invalid token type"):
            verify_token(token, token_type="access")

    def test_verify_token_invalid_signature(self):
        """Test token verification with invalid signature."""
        # Create token with wrong secret
        user_id = uuid4()
        token = jwt.encode(
            {"sub": str(user_id), "type": "access"}, "wrong_secret_key", algorithm="HS256"
        )

        with pytest.raises(JWTError):
            verify_token(token, token_type="access")

    def test_verify_token_malformed(self):
        """Test token verification with malformed token."""
        with pytest.raises(JWTError):
            verify_token("not.a.valid.token", token_type="access")

    def test_verify_token_empty(self):
        """Test token verification with empty token."""
        with pytest.raises(JWTError):
            verify_token("", token_type="access")


class TestTokenUniqueness:
    """Regression tests for token uniqueness (jti claim)."""

    def test_access_token_includes_jti_claim(self):
        """Regression test: Access tokens include jti claim for uniqueness.

        Bug #673a0b5: Tokens with identical payloads (created within same second)
        produced identical JWT strings, breaking refresh token rotation.

        Fix: Added 'jti' (JWT ID) claim using uuid4 to ensure uniqueness.
        """
        user_id = uuid4()
        org_id = uuid4()
        email = "test@example.com"

        # Create two access tokens with identical parameters
        token1 = create_access_token(user_id=user_id, organization_id=org_id, email=email)
        token2 = create_access_token(user_id=user_id, organization_id=org_id, email=email)

        # Tokens must be different despite same user/email
        assert token1 != token2, "Access tokens with same payload should differ due to jti claim"

        # Decode to verify jti
        payload1 = jwt.decode(token1, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        payload2 = jwt.decode(token2, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])

        assert "jti" in payload1, "Access token missing jti claim"
        assert "jti" in payload2, "Access token missing jti claim"
        assert payload1["jti"] != payload2["jti"], "Access tokens have identical jti claims"

    def test_refresh_token_includes_jti_claim(self):
        """Regression test: Refresh tokens include jti claim for rotation.

        This ensures refresh token rotation works correctly - each refresh
        operation returns a NEW token with a different jti.
        """
        user_id = uuid4()

        # Create two refresh tokens for same user
        token1 = create_refresh_token(user_id=user_id)
        token2 = create_refresh_token(user_id=user_id)

        # Tokens must be different
        assert token1 != token2, "Refresh tokens with same user should differ due to jti claim"

        # Decode to verify jti
        payload1 = jwt.decode(token1, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        payload2 = jwt.decode(token2, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])

        assert "jti" in payload1, "Refresh token missing jti claim"
        assert "jti" in payload2, "Refresh token missing jti claim"
        assert payload1["jti"] != payload2["jti"], "Refresh tokens have identical jti claims"

    def test_jti_is_uuid_format(self):
        """Verify that jti claim uses UUID format."""
        from uuid import UUID

        user_id = uuid4()
        token = create_access_token(user_id=user_id, organization_id=uuid4(), email="test@example.com")

        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])

        # Should be able to parse jti as UUID
        try:
            UUID(payload["jti"])
        except (ValueError, KeyError):
            pytest.fail("jti claim should be a valid UUID string")
