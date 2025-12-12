"""
Pytest configuration and fixtures for enterprise authentication tests.

Provides fixtures for:
- Database session
- Test client
- Test users and organizations
- JWT tokens
"""

import asyncio
from typing import AsyncGenerator, Generator

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import selectinload
from sqlalchemy.pool import NullPool

from enterprise.database import Base, get_db
from enterprise.main import app

# Import all models to ensure they're registered with Base.metadata before create_all()
from enterprise.models import EnterpriseUser, Organization, Permission, Role, Team
from enterprise.models.audit import AuditLog  # noqa: F401
from enterprise.models.role import UserRole  # noqa: F401
from enterprise.models.sso import SSOConfiguration  # noqa: F401
from enterprise.security import create_access_token, create_refresh_token, hash_password

# Test database URL (use file-based SQLite for tests to ensure table persistence)
TEST_DATABASE_URL = "sqlite+aiosqlite:///test_db.sqlite"


@pytest.fixture(scope="session")
def event_loop() -> Generator:
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture
async def test_engine():
    """Create test database engine."""
    import os

    # Remove old test database if exists
    if os.path.exists("test_db.sqlite"):
        os.remove("test_db.sqlite")

    engine = create_async_engine(TEST_DATABASE_URL, poolclass=NullPool, echo=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

    await engine.dispose()

    # Clean up test database file
    if os.path.exists("test_db.sqlite"):
        os.remove("test_db.sqlite")


@pytest_asyncio.fixture
async def test_db(test_engine) -> AsyncGenerator[AsyncSession, None]:
    """Create test database session."""
    async_session = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)

    async with async_session() as session:
        yield session


@pytest_asyncio.fixture
async def test_organization(test_db: AsyncSession) -> Organization:
    """Create test organization."""
    org = Organization(
        name="Test Organization",
        slug="test-org",
        plan="professional",
        contact_email="admin@testorg.com",
        contact_name="Test Admin",
        max_users=50,
        max_teams=10,
        is_active=True,
    )
    test_db.add(org)
    await test_db.commit()
    await test_db.refresh(org)
    return org


@pytest_asyncio.fixture
async def test_role_admin(test_db: AsyncSession, test_organization: Organization) -> Role:
    """Create admin role with all permissions."""
    role = Role(
        organization_id=test_organization.id,
        name="Admin",
        slug="admin",
        description="Full access administrator",
    )
    test_db.add(role)
    await test_db.flush()

    # Create permissions with role_id (required foreign key)
    permission_names = [
        ("organizations:create", "Create organizations"),
        ("organizations:read", "Read organizations"),
        ("organizations:update", "Update organizations"),
        ("organizations:delete", "Delete organizations"),
        ("teams:create", "Create teams"),
        ("teams:read", "Read teams"),
        ("teams:update", "Update teams"),
        ("teams:delete", "Delete teams"),
        ("users:create", "Create users"),
        ("users:read", "Read users"),
        ("users:update", "Update users"),
        ("users:delete", "Delete users"),
    ]

    for name, description in permission_names:
        perm = Permission(role_id=role.id, name=name, description=description)
        test_db.add(perm)

    await test_db.commit()
    await test_db.refresh(role)
    return role


@pytest_asyncio.fixture
async def test_role_member(test_db: AsyncSession, test_organization: Organization) -> Role:
    """Create member role with limited permissions."""
    role = Role(
        organization_id=test_organization.id,
        name="Member",
        slug="member",
        description="Standard member",
    )
    test_db.add(role)
    await test_db.flush()

    # Create limited permissions with role_id (required foreign key)
    permission_names = [
        ("teams:read", "Read teams"),
        ("users:read", "Read users"),
    ]

    for name, description in permission_names:
        perm = Permission(role_id=role.id, name=name, description=description)
        test_db.add(perm)

    await test_db.commit()
    await test_db.refresh(role)
    return role


@pytest_asyncio.fixture
async def test_team(test_db: AsyncSession, test_organization: Organization) -> Team:
    """Create test team."""
    team = Team(
        organization_id=test_organization.id,
        name="Test Team",
        slug="test-team",
        description="Test team for testing",
    )
    test_db.add(team)
    await test_db.commit()
    await test_db.refresh(team)
    return team


@pytest_asyncio.fixture
async def test_user_admin(
    test_db: AsyncSession, test_organization: Organization, test_role_admin: Role, test_team: Team
) -> EnterpriseUser:
    """Create test admin user."""
    user = EnterpriseUser(
        organization_id=test_organization.id,
        team_id=test_team.id,
        email="admin@testorg.com",
        full_name="Admin User",
        hashed_password=hash_password("admin123"),
        is_active=True,
        is_verified=True,
    )
    test_db.add(user)
    await test_db.flush()

    # Assign admin role via UserRole junction table
    user_role_obj = UserRole(user_id=user.id, role_id=test_role_admin.id)
    test_db.add(user_role_obj)

    await test_db.commit()

    # Re-fetch user with eager loading of relationships
    stmt = (
        select(EnterpriseUser)
        .options(
            selectinload(EnterpriseUser.organization),
            selectinload(EnterpriseUser.team),
            selectinload(EnterpriseUser.roles)
            .selectinload(UserRole.role)
            .selectinload(Role.permissions),
        )
        .where(EnterpriseUser.id == user.id)
    )
    result = await test_db.execute(stmt)
    return result.scalar_one()


@pytest_asyncio.fixture
async def test_user_member(
    test_db: AsyncSession, test_organization: Organization, test_role_member: Role, test_team: Team
) -> EnterpriseUser:
    """Create test member user."""
    user = EnterpriseUser(
        organization_id=test_organization.id,
        team_id=test_team.id,
        email="member@testorg.com",
        full_name="Member User",
        hashed_password=hash_password("member123"),
        is_active=True,
        is_verified=True,
    )
    test_db.add(user)
    await test_db.flush()

    # Assign member role via UserRole junction table
    user_role_obj = UserRole(user_id=user.id, role_id=test_role_member.id)
    test_db.add(user_role_obj)

    await test_db.commit()

    # Re-fetch user with eager loading of relationships
    stmt = (
        select(EnterpriseUser)
        .options(
            selectinload(EnterpriseUser.organization),
            selectinload(EnterpriseUser.team),
            selectinload(EnterpriseUser.roles)
            .selectinload(UserRole.role)
            .selectinload(Role.permissions),
        )
        .where(EnterpriseUser.id == user.id)
    )
    result = await test_db.execute(stmt)
    return result.scalar_one()


@pytest_asyncio.fixture
async def test_user_inactive(
    test_db: AsyncSession, test_organization: Organization, test_team: Team
) -> EnterpriseUser:
    """Create inactive test user."""
    user = EnterpriseUser(
        organization_id=test_organization.id,
        team_id=test_team.id,
        email="inactive@testorg.com",
        full_name="Inactive User",
        hashed_password=hash_password("inactive123"),
        is_active=False,  # Inactive
        is_verified=True,
    )
    test_db.add(user)
    await test_db.commit()
    await test_db.refresh(user)
    return user


@pytest_asyncio.fixture
async def admin_access_token(test_user_admin: EnterpriseUser) -> str:
    """Create access token for admin user."""
    return create_access_token(
        user_id=test_user_admin.id,
        organization_id=test_user_admin.organization_id,
        email=test_user_admin.email,
    )


@pytest_asyncio.fixture
async def admin_refresh_token(test_user_admin: EnterpriseUser) -> str:
    """Create refresh token for admin user."""
    return create_refresh_token(user_id=test_user_admin.id)


@pytest_asyncio.fixture
async def member_access_token(test_user_member: EnterpriseUser) -> str:
    """Create access token for member user."""
    return create_access_token(
        user_id=test_user_member.id,
        organization_id=test_user_member.organization_id,
        email=test_user_member.email,
    )


@pytest_asyncio.fixture
async def client(test_db: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    """Create test HTTP client with database session override."""

    async def override_get_db():
        yield test_db

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    app.dependency_overrides.clear()
