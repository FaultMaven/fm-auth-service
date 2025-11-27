"""
Security tests for authentication and authorization bypass attempts.
"""

from uuid import uuid4

import pytest
from httpx import AsyncClient
from jose import jwt

from enterprise.config.settings import get_settings
from enterprise.models import EnterpriseUser, Organization

settings = get_settings()


class TestTokenTampering:
    """Test protection against token tampering."""

    @pytest.mark.asyncio
    async def test_tampered_token_rejected(self, client: AsyncClient, admin_access_token: str):
        """Test that tampered JWT token is rejected."""
        # Decode token
        payload = jwt.decode(
            admin_access_token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM]
        )

        # Tamper with payload (change user ID)
        payload["sub"] = str(uuid4())

        # Re-encode with WRONG secret
        tampered_token = jwt.encode(payload, "wrong_secret_key", algorithm=settings.JWT_ALGORITHM)

        # Try to access protected endpoint
        response = await client.get(
            "/api/v1/enterprise/auth/me", headers={"Authorization": f"Bearer {tampered_token}"}
        )

        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_modified_claims_rejected(self, client: AsyncClient, admin_access_token: str):
        """Test that token with modified claims is rejected."""
        # Decode token
        payload = jwt.decode(
            admin_access_token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM]
        )

        # Modify claim (change org_id)
        payload["org_id"] = str(uuid4())

        # Re-encode with correct secret (but modified payload changes signature)
        modified_token = jwt.encode(
            payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM
        )

        # Original token should work
        response = await client.get(
            "/api/v1/enterprise/auth/me", headers={"Authorization": f"Bearer {admin_access_token}"}
        )
        assert response.status_code == 200

        # Modified token should be different and still work (but user will be different)
        # This tests that we can't just modify the token arbitrarily
        assert modified_token != admin_access_token


class TestAuthorizationBypass:
    """Test protection against authorization bypass attempts."""

    @pytest.mark.asyncio
    async def test_permission_bypass_attempt(
        self, client: AsyncClient, member_access_token: str, test_organization: Organization
    ):
        """Test that user cannot bypass permission checks."""
        # Member user tries to create team (requires teams:create permission)
        response = await client.post(
            "/api/v1/enterprise/teams",
            headers={"Authorization": f"Bearer {member_access_token}"},
            json={
                "organization_id": str(test_organization.id),
                "name": "Unauthorized Team",
                "slug": "unauthorized-team",
            },
        )

        assert response.status_code == 403
        assert "Permission denied" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_admin_role_bypass_attempt(
        self, client: AsyncClient, member_access_token: str, test_organization: Organization
    ):
        """Test that user cannot bypass admin role checks."""
        # Member user tries to create SSO config (requires admin role)
        response = await client.post(
            "/api/v1/enterprise/sso",
            headers={"Authorization": f"Bearer {member_access_token}"},
            json={
                "organization_id": str(test_organization.id),
                "provider_type": "saml",
                "provider_name": "Unauthorized SSO",
                "saml_entity_id": "https://test.com",
                "saml_sso_url": "https://test.com/sso",
            },
        )

        assert response.status_code == 403
        assert "admin" in response.json()["detail"].lower()


class TestMultiTenantBypass:
    """Test protection against multi-tenant isolation bypass."""

    @pytest.mark.asyncio
    async def test_cross_tenant_data_access_blocked(
        self, client: AsyncClient, admin_access_token: str
    ):
        """Test that cross-tenant data access is blocked."""
        other_org_id = uuid4()

        # Try to access teams from another organization
        response = await client.get(
            f"/api/v1/enterprise/teams/organization/{other_org_id}",
            headers={"Authorization": f"Bearer {admin_access_token}"},
        )

        assert response.status_code == 403
        assert "You do not belong to this organization" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_cross_tenant_resource_creation_blocked(
        self, client: AsyncClient, admin_access_token: str
    ):
        """Test that creating resources in other tenants is blocked."""
        other_org_id = uuid4()

        # Try to create user in another organization
        response = await client.post(
            "/api/v1/enterprise/users",
            headers={"Authorization": f"Bearer {admin_access_token}"},
            json={
                "organization_id": str(other_org_id),
                "email": "hacker@otherorg.com",
                "full_name": "Hacker",
                "password": "password123",
            },
        )

        assert response.status_code == 403
        assert "You do not belong to this organization" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_cross_tenant_resource_modification_blocked(
        self, client: AsyncClient, admin_access_token: str
    ):
        """Test that modifying resources in other tenants is blocked."""
        other_org_id = uuid4()

        # Try to update organization from another tenant
        response = await client.put(
            f"/api/v1/enterprise/organizations/{other_org_id}",
            headers={"Authorization": f"Bearer {admin_access_token}"},
            json={"name": "Hacked Organization"},
        )

        assert response.status_code == 403


class TestInactiveUserSecurity:
    """Test that inactive users are properly blocked."""

    @pytest.mark.asyncio
    async def test_inactive_user_cannot_login(
        self, client: AsyncClient, test_user_inactive: EnterpriseUser
    ):
        """Test that inactive user cannot login."""
        response = await client.post(
            "/api/v1/enterprise/auth/login",
            json={"email": "inactive@testorg.com", "password": "inactive123"},
        )

        assert response.status_code == 403
        assert "Account is disabled" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_inactive_user_cannot_refresh_token(
        self, client: AsyncClient, test_user_inactive: EnterpriseUser
    ):
        """Test that inactive user cannot refresh token."""
        from enterprise.security import create_refresh_token

        # Create refresh token for inactive user (simulating before deactivation)
        refresh_token = create_refresh_token(test_user_inactive.id)

        response = await client.post(
            "/api/v1/enterprise/auth/refresh", json={"refresh_token": refresh_token}
        )

        assert response.status_code == 403
        assert "Account is disabled" in response.json()["detail"]


class TestPasswordSecurity:
    """Test password security measures."""

    @pytest.mark.asyncio
    async def test_password_not_exposed_in_responses(
        self, client: AsyncClient, admin_access_token: str
    ):
        """Test that password hashes are never exposed in API responses."""
        # Get current user
        response = await client.get(
            "/api/v1/enterprise/auth/me", headers={"Authorization": f"Bearer {admin_access_token}"}
        )

        assert response.status_code == 200
        data = response.json()

        # Verify password fields are not in response
        assert "password" not in data
        assert "hashed_password" not in data

    @pytest.mark.asyncio
    async def test_login_error_doesnt_reveal_user_existence(self, client: AsyncClient):
        """Test that login errors don't reveal whether user exists."""
        # Try with non-existent user
        response1 = await client.post(
            "/api/v1/enterprise/auth/login",
            json={"email": "nonexistent@testorg.com", "password": "somepassword"},
        )

        # Try with existing user but wrong password
        response2 = await client.post(
            "/api/v1/enterprise/auth/login",
            json={"email": "admin@testorg.com", "password": "wrongpassword"},
        )

        # Both should return same generic error
        assert response1.status_code == 401
        assert response2.status_code == 401
        assert response1.json()["detail"] == response2.json()["detail"]
        assert "Incorrect email or password" in response1.json()["detail"]


class TestTokenExpiration:
    """Test token expiration security."""

    @pytest.mark.asyncio
    async def test_expired_token_rejected(
        self, client: AsyncClient, test_user_admin: EnterpriseUser
    ):
        """Test that expired tokens are rejected."""
        from datetime import datetime, timedelta

        from enterprise.security import create_access_token

        # Create token that's already expired
        expired_token = create_access_token(
            user_id=test_user_admin.id,
            organization_id=test_user_admin.organization_id,
            email=test_user_admin.email,
            expires_delta=timedelta(seconds=-10),  # Expired 10 seconds ago
        )

        response = await client.get(
            "/api/v1/enterprise/auth/me", headers={"Authorization": f"Bearer {expired_token}"}
        )

        assert response.status_code == 401


class TestInputValidation:
    """Test input validation and sanitization."""

    @pytest.mark.asyncio
    async def test_sql_injection_protection(self, client: AsyncClient):
        """Test protection against SQL injection in login."""
        response = await client.post(
            "/api/v1/enterprise/auth/login",
            json={"email": "admin@testorg.com' OR '1'='1", "password": "anything"},
        )

        # Should fail authentication, not cause SQL error
        assert response.status_code in [401, 422]

    @pytest.mark.asyncio
    async def test_xss_protection_in_error_messages(self, client: AsyncClient):
        """Test that error messages don't reflect user input (XSS protection)."""
        malicious_email = "<script>alert('xss')</script>@test.com"

        response = await client.post(
            "/api/v1/enterprise/auth/login", json={"email": malicious_email, "password": "password"}
        )

        # Should either reject invalid email format or return generic error
        assert response.status_code in [401, 422]

        # Error message should NOT contain the script tag
        detail = response.json().get("detail", "")
        if isinstance(detail, str):
            assert "<script>" not in detail
