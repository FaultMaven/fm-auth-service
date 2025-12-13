"""
Integration tests for authentication endpoints.
"""

import pytest
from httpx import AsyncClient

from enterprise.models import EnterpriseUser, Organization


class TestLoginEndpoint:
    """Test POST /api/v1/enterprise/auth/login endpoint."""

    @pytest.mark.asyncio
    async def test_login_success(self, client: AsyncClient, test_user_admin: EnterpriseUser):
        """Test successful login with correct credentials."""
        response = await client.post(
            "/api/v1/enterprise/auth/login",
            json={"email": "admin@testorg.com", "password": "admin123"},
        )

        assert response.status_code == 200
        data = response.json()

        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"
        assert data["expires_in"] == 1800  # 30 minutes in seconds

        # Verify tokens are non-empty strings
        assert len(data["access_token"]) > 0
        assert len(data["refresh_token"]) > 0

    @pytest.mark.asyncio
    async def test_login_wrong_password(self, client: AsyncClient, test_user_admin: EnterpriseUser):
        """Test login with incorrect password."""
        response = await client.post(
            "/api/v1/enterprise/auth/login",
            json={"email": "admin@testorg.com", "password": "wrongpassword"},
        )

        assert response.status_code == 401
        data = response.json()
        assert "Incorrect email or password" in data["detail"]

    @pytest.mark.asyncio
    async def test_login_nonexistent_user(self, client: AsyncClient):
        """Test login with non-existent email."""
        response = await client.post(
            "/api/v1/enterprise/auth/login",
            json={"email": "nonexistent@testorg.com", "password": "somepassword"},
        )

        assert response.status_code == 401
        data = response.json()
        assert "Incorrect email or password" in data["detail"]

    @pytest.mark.asyncio
    async def test_login_inactive_user(
        self, client: AsyncClient, test_user_inactive: EnterpriseUser
    ):
        """Test login with inactive user account."""
        response = await client.post(
            "/api/v1/enterprise/auth/login",
            json={"email": "inactive@testorg.com", "password": "inactive123"},
        )

        assert response.status_code == 403
        data = response.json()
        assert "Account is disabled" in data["detail"]

    @pytest.mark.asyncio
    async def test_login_invalid_email_format(self, client: AsyncClient):
        """Test login with invalid email format."""
        response = await client.post(
            "/api/v1/enterprise/auth/login",
            json={"email": "not-an-email", "password": "somepassword"},
        )

        assert response.status_code == 422  # Validation error

    @pytest.mark.asyncio
    async def test_login_missing_fields(self, client: AsyncClient):
        """Test login with missing fields."""
        response = await client.post(
            "/api/v1/enterprise/auth/login", json={"email": "admin@testorg.com"}
        )

        assert response.status_code == 422  # Validation error


class TestRegisterEndpoint:
    """Test POST /api/v1/enterprise/auth/register endpoint."""

    @pytest.mark.asyncio
    async def test_register_success(self, client: AsyncClient, test_organization: Organization):
        """Test successful user registration."""
        response = await client.post(
            "/api/v1/enterprise/auth/register",
            json={
                "organization_id": str(test_organization.id),
                "email": "newuser@testorg.com",
                "full_name": "New User",
                "password": "newpass123",
            },
        )

        assert response.status_code == 201
        data = response.json()

        assert "id" in data
        assert data["email"] == "newuser@testorg.com"
        assert data["full_name"] == "New User"
        assert data["organization_id"] == str(test_organization.id)
        assert "User registered successfully" in data["message"]

    @pytest.mark.asyncio
    async def test_register_duplicate_email(
        self, client: AsyncClient, test_organization: Organization, test_user_admin: EnterpriseUser
    ):
        """Test registration with existing email."""
        response = await client.post(
            "/api/v1/enterprise/auth/register",
            json={
                "organization_id": str(test_organization.id),
                "email": "admin@testorg.com",  # Already exists
                "full_name": "Another Admin",
                "password": "password123",
            },
        )

        assert response.status_code == 409
        data = response.json()
        assert "already exists" in data["detail"]

    @pytest.mark.asyncio
    async def test_register_nonexistent_organization(self, client: AsyncClient):
        """Test registration with non-existent organization."""
        from uuid import uuid4

        response = await client.post(
            "/api/v1/enterprise/auth/register",
            json={
                "organization_id": str(uuid4()),
                "email": "user@testorg.com",
                "full_name": "Test User",
                "password": "password123",
            },
        )

        assert response.status_code == 404
        data = response.json()
        assert "not found" in data["detail"]

    @pytest.mark.asyncio
    async def test_register_invalid_email(
        self, client: AsyncClient, test_organization: Organization
    ):
        """Test registration with invalid email format."""
        response = await client.post(
            "/api/v1/enterprise/auth/register",
            json={
                "organization_id": str(test_organization.id),
                "email": "not-an-email",
                "full_name": "Test User",
                "password": "password123",
            },
        )

        assert response.status_code == 422  # Validation error

    @pytest.mark.asyncio
    async def test_register_short_password(
        self, client: AsyncClient, test_organization: Organization
    ):
        """Test registration with password too short."""
        response = await client.post(
            "/api/v1/enterprise/auth/register",
            json={
                "organization_id": str(test_organization.id),
                "email": "user@testorg.com",
                "full_name": "Test User",
                "password": "short",  # Less than 8 characters
            },
        )

        assert response.status_code == 422  # Validation error


class TestRefreshTokenEndpoint:
    """Test POST /api/v1/enterprise/auth/refresh endpoint."""

    @pytest.mark.asyncio
    async def test_refresh_token_success(self, client: AsyncClient, admin_refresh_token: str):
        """Test successful token refresh."""
        response = await client.post(
            "/api/v1/enterprise/auth/refresh", json={"refresh_token": admin_refresh_token}
        )

        assert response.status_code == 200
        data = response.json()

        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"
        assert data["expires_in"] == 1800

        # Verify new tokens are different from old
        assert data["refresh_token"] != admin_refresh_token

    @pytest.mark.asyncio
    async def test_refresh_token_with_access_token(
        self, client: AsyncClient, admin_access_token: str
    ):
        """Test refresh with access token (should fail)."""
        response = await client.post(
            "/api/v1/enterprise/auth/refresh", json={"refresh_token": admin_access_token}
        )

        assert response.status_code == 401
        data = response.json()
        assert "Invalid token type" in data["detail"] or "Invalid refresh token" in data["detail"]

    @pytest.mark.asyncio
    async def test_refresh_token_invalid_token(self, client: AsyncClient):
        """Test refresh with invalid token."""
        response = await client.post(
            "/api/v1/enterprise/auth/refresh", json={"refresh_token": "invalid.token.here"}
        )

        assert response.status_code == 401
        data = response.json()
        assert "Invalid refresh token" in data["detail"]

    @pytest.mark.asyncio
    async def test_refresh_token_inactive_user(
        self, client: AsyncClient, test_user_inactive: EnterpriseUser
    ):
        """Test token refresh for inactive user."""
        from enterprise.security import create_refresh_token

        # Create refresh token for inactive user
        inactive_refresh_token = create_refresh_token(test_user_inactive.id)

        response = await client.post(
            "/api/v1/enterprise/auth/refresh", json={"refresh_token": inactive_refresh_token}
        )

        assert response.status_code == 403
        data = response.json()
        assert "Account is disabled" in data["detail"]


class TestLogoutEndpoint:
    """Test POST /api/v1/enterprise/auth/logout endpoint."""

    @pytest.mark.asyncio
    async def test_logout_success(self, client: AsyncClient, admin_access_token: str):
        """Test successful logout."""
        response = await client.post(
            "/api/v1/enterprise/auth/logout",
            headers={"Authorization": f"Bearer {admin_access_token}"},
        )

        assert response.status_code == 200
        data = response.json()
        assert "Logged out successfully" in data["message"]

    @pytest.mark.asyncio
    async def test_logout_without_token(self, client: AsyncClient):
        """Test logout without authentication token."""
        response = await client.post("/api/v1/enterprise/auth/logout")

        assert response.status_code == 403  # No credentials provided

    @pytest.mark.asyncio
    async def test_logout_with_invalid_token(self, client: AsyncClient):
        """Test logout with invalid token."""
        response = await client.post(
            "/api/v1/enterprise/auth/logout", headers={"Authorization": "Bearer invalid.token.here"}
        )

        assert response.status_code == 401


class TestGetCurrentUserEndpoint:
    """Test GET /api/v1/enterprise/auth/me endpoint."""

    @pytest.mark.asyncio
    async def test_get_current_user_success(
        self, client: AsyncClient, admin_access_token: str, test_user_admin: EnterpriseUser
    ):
        """Test successful retrieval of current user info."""
        response = await client.get(
            "/api/v1/enterprise/auth/me", headers={"Authorization": f"Bearer {admin_access_token}"}
        )

        assert response.status_code == 200
        data = response.json()

        assert data["id"] == str(test_user_admin.id)
        assert data["email"] == test_user_admin.email
        assert data["full_name"] == test_user_admin.full_name
        assert data["organization_id"] == str(test_user_admin.organization_id)
        assert data["is_active"] is True

        # Verify roles and permissions
        assert "roles" in data
        assert len(data["roles"]) > 0
        assert "permissions" in data
        assert len(data["permissions"]) > 0

        # Admin should have create permissions
        assert "teams:create" in data["permissions"]
        assert "users:create" in data["permissions"]

    @pytest.mark.asyncio
    async def test_get_current_user_without_token(self, client: AsyncClient):
        """Test /me endpoint without authentication."""
        response = await client.get("/api/v1/enterprise/auth/me")

        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_get_current_user_with_invalid_token(self, client: AsyncClient):
        """Test /me endpoint with invalid token."""
        response = await client.get(
            "/api/v1/enterprise/auth/me", headers={"Authorization": "Bearer invalid.token.here"}
        )

        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_get_current_user_member_permissions(
        self, client: AsyncClient, member_access_token: str, test_user_member: EnterpriseUser
    ):
        """Test /me endpoint returns correct permissions for member user."""
        response = await client.get(
            "/api/v1/enterprise/auth/me", headers={"Authorization": f"Bearer {member_access_token}"}
        )

        assert response.status_code == 200
        data = response.json()

        assert data["email"] == test_user_member.email

        # Member should only have read permissions
        assert "teams:read" in data["permissions"]
        assert "users:read" in data["permissions"]

        # Member should NOT have create permissions
        assert "teams:create" not in data["permissions"]
        assert "users:create" not in data["permissions"]


class TestRegressionBugs:
    """Regression tests for specific bugs that were fixed."""

    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_refresh_token_rotation_returns_new_token(
        self, client: AsyncClient, test_user_admin: EnterpriseUser
    ):
        """Regression test for bug #673a0b5: Refresh must return NEW token.

        Bug: Refresh endpoint returned same token because tokens with identical
        payloads (created within same second) produced identical JWT strings.

        Fix: Added 'jti' (JWT ID) claim using uuid4 to ensure uniqueness.

        This test verifies that:
        1. Refresh returns a different token than the input
        2. Both tokens have different 'jti' claims
        """
        # Login to get initial tokens
        login_response = await client.post(
            "/api/v1/enterprise/auth/login",
            json={"email": "admin@testorg.com", "password": "admin123"},
        )
        assert login_response.status_code == 200
        refresh_token_1 = login_response.json()["refresh_token"]

        # Refresh the token
        refresh_response = await client.post(
            "/api/v1/enterprise/auth/refresh", json={"refresh_token": refresh_token_1}
        )
        assert refresh_response.status_code == 200
        refresh_token_2 = refresh_response.json()["refresh_token"]

        # CRITICAL: New refresh token must be different due to unique jti claim
        assert refresh_token_2 != refresh_token_1, (
            "Refresh token rotation failed: new token matches old token. "
            "This indicates the jti claim is not unique or missing."
        )

        # Decode both tokens to verify jti differs
        from jose import jwt
        from enterprise.config.settings import get_settings

        settings = get_settings()
        payload_1 = jwt.decode(refresh_token_1, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        payload_2 = jwt.decode(refresh_token_2, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])

        assert "jti" in payload_1, "Original refresh token missing jti claim"
        assert "jti" in payload_2, "New refresh token missing jti claim"
        assert payload_1["jti"] != payload_2["jti"], (
            "Refresh tokens have identical jti claims, rotation will fail"
        )

    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_get_me_serializes_user_role_to_role(
        self, client: AsyncClient, admin_access_token: str, test_user_admin: EnterpriseUser
    ):
        """Regression test for bug #52e7e60: /auth/me must traverse UserRole→Role.

        Bug: get_current_user_info endpoint treated current_user.roles as Role objects,
        but they're actually UserRole junction objects. Caused AttributeError when
        accessing role.name and role.description.

        Fix: Iterate over UserRole objects and access related Role via user_role.role:
            for user_role in current_user.roles:
                role = user_role.role
                roles.append({"id": role.id, "name": role.name, ...})

        This test verifies that:
        1. /auth/me returns roles array with proper structure
        2. Each role has id, name, description fields
        3. No AttributeError occurs during serialization
        """
        response = await client.get(
            "/api/v1/enterprise/auth/me", headers={"Authorization": f"Bearer {admin_access_token}"}
        )

        assert response.status_code == 200, (
            f"Failed to get current user info: {response.status_code} {response.text}"
        )
        data = response.json()

        # CRITICAL: Must have roles array with proper structure
        assert "roles" in data, "Response missing 'roles' field"
        assert isinstance(data["roles"], list), "Roles must be a list"
        assert len(data["roles"]) > 0, "Admin user should have at least one role"

        # Each role must have id, name, description (from Role model, not UserRole)
        for role in data["roles"]:
            assert "id" in role, f"Role missing 'id' field: {role}"
            assert "name" in role, f"Role missing 'name' field: {role}"
            assert "description" in role, f"Role missing 'description' field: {role}"
            assert isinstance(role["name"], str), "Role name must be a string"
            assert isinstance(role["description"], str), "Role description must be a string"

        # Verify permissions are also included (another field from the same endpoint)
        assert "permissions" in data, "Response missing 'permissions' field"
        assert isinstance(data["permissions"], list), "Permissions must be a list"
