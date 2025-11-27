"""
Integration tests for protected API endpoints (RBAC and multi-tenancy).
"""

import pytest
from httpx import AsyncClient
from uuid import uuid4

from enterprise.models import EnterpriseUser, Organization


class TestOrganizationsEndpointAuth:
    """Test authentication and authorization on organizations endpoints."""

    @pytest.mark.asyncio
    async def test_list_organizations_without_auth(self, client: AsyncClient):
        """Test listing organizations without authentication."""
        response = await client.get("/api/v1/enterprise/organizations")

        assert response.status_code == 403  # No credentials

    @pytest.mark.asyncio
    async def test_list_organizations_with_auth(
        self, client: AsyncClient, admin_access_token: str, test_organization: Organization
    ):
        """Test listing organizations with authentication."""
        response = await client.get(
            "/api/v1/enterprise/organizations",
            headers={"Authorization": f"Bearer {admin_access_token}"},
        )

        assert response.status_code == 200
        data = response.json()

        # Should only return user's organization (multi-tenant isolation)
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["id"] == str(test_organization.id)

    @pytest.mark.asyncio
    async def test_get_organization_requires_org_access(
        self, client: AsyncClient, admin_access_token: str, test_organization: Organization
    ):
        """Test getting organization requires organization access."""
        # Access own organization - should succeed
        response = await client.get(
            f"/api/v1/enterprise/organizations/{test_organization.id}",
            headers={"Authorization": f"Bearer {admin_access_token}"},
        )

        assert response.status_code == 200

        # Try to access different organization - should fail
        different_org_id = uuid4()
        response = await client.get(
            f"/api/v1/enterprise/organizations/{different_org_id}",
            headers={"Authorization": f"Bearer {admin_access_token}"},
        )

        assert response.status_code == 403
        assert "You do not belong to this organization" in response.json()["detail"]


class TestTeamsEndpointAuth:
    """Test authentication and authorization on teams endpoints."""

    @pytest.mark.asyncio
    async def test_create_team_without_permission(
        self, client: AsyncClient, member_access_token: str, test_organization: Organization
    ):
        """Test creating team without required permission."""
        response = await client.post(
            "/api/v1/enterprise/teams",
            headers={"Authorization": f"Bearer {member_access_token}"},
            json={
                "organization_id": str(test_organization.id),
                "name": "New Team",
                "slug": "new-team",
            },
        )

        assert response.status_code == 403
        assert "Permission denied" in response.json()["detail"]
        assert "teams:create" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_create_team_with_permission(
        self, client: AsyncClient, admin_access_token: str, test_organization: Organization
    ):
        """Test creating team with required permission."""
        response = await client.post(
            "/api/v1/enterprise/teams",
            headers={"Authorization": f"Bearer {admin_access_token}"},
            json={
                "organization_id": str(test_organization.id),
                "name": "Engineering Team",
                "slug": "engineering-team",
            },
        )

        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "Engineering Team"
        assert data["organization_id"] == str(test_organization.id)

    @pytest.mark.asyncio
    async def test_create_team_different_org_blocked(
        self, client: AsyncClient, admin_access_token: str
    ):
        """Test creating team in different organization is blocked."""
        different_org_id = uuid4()

        response = await client.post(
            "/api/v1/enterprise/teams",
            headers={"Authorization": f"Bearer {admin_access_token}"},
            json={
                "organization_id": str(different_org_id),
                "name": "Cross-Org Team",
                "slug": "cross-org-team",
            },
        )

        assert response.status_code == 403
        assert "You do not belong to this organization" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_list_teams_enforces_multi_tenancy(
        self, client: AsyncClient, admin_access_token: str, test_organization: Organization
    ):
        """Test listing teams enforces multi-tenancy."""
        # Try to list teams for different organization
        different_org_id = uuid4()

        response = await client.get(
            f"/api/v1/enterprise/teams/organization/{different_org_id}",
            headers={"Authorization": f"Bearer {admin_access_token}"},
        )

        assert response.status_code == 403
        assert "You do not belong to this organization" in response.json()["detail"]


class TestUsersEndpointAuth:
    """Test authentication and authorization on users endpoints."""

    @pytest.mark.asyncio
    async def test_create_user_without_permission(
        self, client: AsyncClient, member_access_token: str, test_organization: Organization
    ):
        """Test creating user without required permission."""
        response = await client.post(
            "/api/v1/enterprise/users",
            headers={"Authorization": f"Bearer {member_access_token}"},
            json={
                "organization_id": str(test_organization.id),
                "email": "newuser@testorg.com",
                "full_name": "New User",
                "password": "password123",
            },
        )

        assert response.status_code == 403
        assert "Permission denied" in response.json()["detail"]
        assert "users:create" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_create_user_with_permission(
        self, client: AsyncClient, admin_access_token: str, test_organization: Organization
    ):
        """Test creating user with required permission."""
        response = await client.post(
            "/api/v1/enterprise/users",
            headers={"Authorization": f"Bearer {admin_access_token}"},
            json={
                "organization_id": str(test_organization.id),
                "email": "newmember@testorg.com",
                "full_name": "New Member",
                "password": "password123",
            },
        )

        assert response.status_code == 201
        data = response.json()
        assert data["email"] == "newmember@testorg.com"
        assert data["organization_id"] == str(test_organization.id)

    @pytest.mark.asyncio
    async def test_create_user_different_org_blocked(
        self, client: AsyncClient, admin_access_token: str
    ):
        """Test creating user in different organization is blocked."""
        different_org_id = uuid4()

        response = await client.post(
            "/api/v1/enterprise/users",
            headers={"Authorization": f"Bearer {admin_access_token}"},
            json={
                "organization_id": str(different_org_id),
                "email": "crossorg@test.com",
                "full_name": "Cross Org User",
                "password": "password123",
            },
        )

        assert response.status_code == 403
        assert "You do not belong to this organization" in response.json()["detail"]


class TestSSOEndpointAuth:
    """Test authentication and authorization on SSO endpoints."""

    @pytest.mark.asyncio
    async def test_create_sso_config_without_admin(
        self, client: AsyncClient, member_access_token: str, test_organization: Organization
    ):
        """Test creating SSO config without admin role."""
        response = await client.post(
            "/api/v1/enterprise/sso",
            headers={"Authorization": f"Bearer {member_access_token}"},
            json={
                "organization_id": str(test_organization.id),
                "provider_type": "saml",
                "provider_name": "Test SSO",
                "saml_entity_id": "https://test.example.com",
                "saml_sso_url": "https://test.example.com/sso",
            },
        )

        assert response.status_code == 403
        assert "Organization admin access required" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_create_sso_config_with_admin(
        self, client: AsyncClient, admin_access_token: str, test_organization: Organization
    ):
        """Test creating SSO config with admin role."""
        response = await client.post(
            "/api/v1/enterprise/sso",
            headers={"Authorization": f"Bearer {admin_access_token}"},
            json={
                "organization_id": str(test_organization.id),
                "provider_type": "saml",
                "provider_name": "Test SAML",
                "saml_entity_id": "https://test.example.com",
                "saml_sso_url": "https://test.example.com/sso",
            },
        )

        assert response.status_code == 201
        data = response.json()
        assert data["provider_name"] == "Test SAML"
        assert data["organization_id"] == str(test_organization.id)


class TestMultiTenantIsolation:
    """Test multi-tenant data isolation across all endpoints."""

    @pytest.mark.asyncio
    async def test_cannot_access_other_org_teams(
        self, client: AsyncClient, admin_access_token: str, test_team
    ):
        """Test cannot access teams from other organizations."""
        # Create another organization (simulated by using wrong UUID)
        other_org_id = uuid4()

        response = await client.get(
            f"/api/v1/enterprise/teams/organization/{other_org_id}",
            headers={"Authorization": f"Bearer {admin_access_token}"},
        )

        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_cannot_access_other_org_users(
        self, client: AsyncClient, admin_access_token: str
    ):
        """Test cannot access users from other organizations."""
        other_org_id = uuid4()

        response = await client.get(
            f"/api/v1/enterprise/users/organization/{other_org_id}",
            headers={"Authorization": f"Bearer {admin_access_token}"},
        )

        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_cannot_update_other_org_resources(
        self, client: AsyncClient, admin_access_token: str, test_organization: Organization
    ):
        """Test cannot update resources from other organizations."""
        other_org_id = uuid4()

        response = await client.put(
            f"/api/v1/enterprise/organizations/{other_org_id}",
            headers={"Authorization": f"Bearer {admin_access_token}"},
            json={"name": "Hacked Org"},
        )

        assert response.status_code == 403
