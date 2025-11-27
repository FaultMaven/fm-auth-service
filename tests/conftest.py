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
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from enterprise.database import Base, get_db
from enterprise.main import app
from enterprise.models import EnterpriseUser, Organization, Permission, Role, Team
from enterprise.security import create_access_token, create_refresh_token, hash_password

# Test database URL (use in-memory SQLite for tests)
TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"


@pytest.fixture(scope="session")
def event_loop() -> Generator:
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture
async def test_engine():
    """Create test database engine."""
    engine = create_async_engine(TEST_DATABASE_URL, poolclass=NullPool, echo=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

    await engine.dispose()


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
        organization_id=test_organization.id, name="Admin", description="Full access administrator"
    )
    test_db.add(role)
    await test_db.flush()

    # Create permissions
    permissions = [
        Permission(name="organizations:create", description="Create organizations"),
        Permission(name="organizations:read", description="Read organizations"),
        Permission(name="organizations:update", description="Update organizations"),
        Permission(name="organizations:delete", description="Delete organizations"),
        Permission(name="teams:create", description="Create teams"),
        Permission(name="teams:read", description="Read teams"),
        Permission(name="teams:update", description="Update teams"),
        Permission(name="teams:delete", description="Delete teams"),
        Permission(name="users:create", description="Create users"),
        Permission(name="users:read", description="Read users"),
        Permission(name="users:update", description="Update users"),
        Permission(name="users:delete", description="Delete users"),
    ]

    for perm in permissions:
        test_db.add(perm)

    await test_db.flush()

    # Associate permissions with role
    role.permissions = permissions

    await test_db.commit()
    await test_db.refresh(role)
    return role


@pytest_asyncio.fixture
async def test_role_member(test_db: AsyncSession, test_organization: Organization) -> Role:
    """Create member role with limited permissions."""
    role = Role(organization_id=test_organization.id, name="Member", description="Standard member")
    test_db.add(role)
    await test_db.flush()

    # Create limited permissions
    permissions = [
        Permission(name="teams:read", description="Read teams"),
        Permission(name="users:read", description="Read users"),
    ]

    for perm in permissions:
        test_db.add(perm)

    await test_db.flush()

    role.permissions = permissions

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

    # Assign admin role
    user.roles = [test_role_admin]

    await test_db.commit()
    await test_db.refresh(user)
    return user


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

    # Assign member role
    user.roles = [test_role_member]

    await test_db.commit()
    await test_db.refresh(user)
    return user


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

    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac

    app.dependency_overrides.clear()
