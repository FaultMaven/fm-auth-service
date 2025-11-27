"""
Unit tests for authentication middleware.
"""

import pytest
from fastapi import HTTPException

from enterprise.middleware.auth import (
    OrganizationAccessChecker,
    get_current_active_user,
    require_org_admin,
    require_permissions,
)
from enterprise.models import EnterpriseUser

pytestmark = pytest.mark.unit


class TestGetCurrentActiveUser:
    """Test get_current_active_user function."""

    @pytest.mark.asyncio
    async def test_active_user_passes(self, test_user_admin: EnterpriseUser):
        """Test that active user passes check."""
        result = await get_current_active_user(test_user_admin)
        assert result == test_user_admin

    @pytest.mark.asyncio
    async def test_inactive_user_raises_exception(self, test_user_inactive: EnterpriseUser):
        """Test that inactive user raises HTTPException."""
        with pytest.raises(HTTPException) as exc_info:
            await get_current_active_user(test_user_inactive)

        assert exc_info.value.status_code == 403
        assert "Inactive user" in exc_info.value.detail


class TestRequirePermissions:
    """Test require_permissions authorization."""

    @pytest.mark.asyncio
    async def test_user_with_permission_passes(self, test_user_admin: EnterpriseUser):
        """Test that user with required permission passes."""
        # Admin has "teams:create" permission
        checker = require_permissions("teams:create")
        result = await checker(current_user=test_user_admin)

        assert result == test_user_admin

    @pytest.mark.asyncio
    async def test_user_with_multiple_permissions_passes(self, test_user_admin: EnterpriseUser):
        """Test that user with all required permissions passes."""
        # Admin has all these permissions
        checker = require_permissions("teams:create", "users:create")
        result = await checker(current_user=test_user_admin)

        assert result == test_user_admin

    @pytest.mark.asyncio
    async def test_user_without_permission_raises_exception(self, test_user_member: EnterpriseUser):
        """Test that user without required permission raises HTTPException."""
        # Member does not have "teams:create" permission
        checker = require_permissions("teams:create")

        with pytest.raises(HTTPException) as exc_info:
            await checker(current_user=test_user_member)

        assert exc_info.value.status_code == 403
        assert "Permission denied" in exc_info.value.detail
        assert "teams:create" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_user_with_partial_permissions_raises_exception(
        self, test_user_member: EnterpriseUser
    ):
        """Test that user with only some permissions raises HTTPException."""
        # Member has "teams:read" but not "teams:create"
        checker = require_permissions("teams:read", "teams:create")

        with pytest.raises(HTTPException) as exc_info:
            await checker(current_user=test_user_member)

        assert exc_info.value.status_code == 403


class TestRequireOrgAdmin:
    """Test require_org_admin authorization."""

    @pytest.mark.asyncio
    async def test_admin_user_passes(self, test_user_admin: EnterpriseUser):
        """Test that admin user passes check."""
        result = await require_org_admin(test_user_admin)
        assert result == test_user_admin

    @pytest.mark.asyncio
    async def test_non_admin_user_raises_exception(self, test_user_member: EnterpriseUser):
        """Test that non-admin user raises HTTPException."""
        with pytest.raises(HTTPException) as exc_info:
            await require_org_admin(test_user_member)

        assert exc_info.value.status_code == 403
        assert "Organization admin access required" in exc_info.value.detail


class TestOrganizationAccessChecker:
    """Test OrganizationAccessChecker class."""

    def test_user_with_matching_org_passes(self, test_user_admin: EnterpriseUser):
        """Test that user with matching organization ID passes."""
        checker = OrganizationAccessChecker()
        result = checker(
            organization_id=test_user_admin.organization_id, current_user=test_user_admin
        )

        assert result == test_user_admin

    def test_user_with_different_org_raises_exception(
        self, test_user_admin: EnterpriseUser, test_organization
    ):
        """Test that user with different organization raises HTTPException."""
        from uuid import uuid4

        checker = OrganizationAccessChecker()
        different_org_id = uuid4()  # Different from test_user_admin.organization_id

        with pytest.raises(HTTPException) as exc_info:
            checker(organization_id=different_org_id, current_user=test_user_admin)

        assert exc_info.value.status_code == 403
        assert "You do not belong to this organization" in exc_info.value.detail
