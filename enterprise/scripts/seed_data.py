"""
Seed data script for local development.

Creates sample organizations, teams, users, and SSO configurations
for testing the enterprise platform.
"""

import asyncio
from uuid import uuid4

from sqlalchemy import select

from enterprise.database import AsyncSessionLocal, init_db
from enterprise.models import Organization, Team, EnterpriseUser, Role, Permission, UserRole, SSOConfiguration
from enterprise.security import hash_password


async def seed_database():
    """Create seed data for development."""

    print("🌱 Seeding database with sample data...")

    async with AsyncSessionLocal() as db:
        # Check if data already exists
        result = await db.execute(select(Organization))
        if result.scalars().first():
            print("⚠️  Database already has data. Skipping seed.")
            return

        # Create Organizations
        print("\n📦 Creating organizations...")
        acme = Organization(
            id=uuid4(),
            name="Acme Corporation",
            slug="acme-corp",
            plan="professional",
            is_active=True,
            max_users=50,
            max_teams=10,
            contact_email="admin@acme.com",
            contact_name="John Doe"
        )

        techstart = Organization(
            id=uuid4(),
            name="TechStart Inc",
            slug="techstart",
            plan="starter",
            is_active=True,
            max_users=10,
            max_teams=3,
            contact_email="info@techstart.io",
            contact_name="Jane Smith"
        )

        enterprise_co = Organization(
            id=uuid4(),
            name="Enterprise Co",
            slug="enterprise-co",
            plan="enterprise",
            is_active=True,
            max_users=200,
            max_teams=50,
            contact_email="admin@enterprise.co",
            contact_name="Alice Johnson"
        )

        db.add_all([acme, techstart, enterprise_co])
        await db.commit()
        print(f"  ✅ Created {acme.name}")
        print(f"  ✅ Created {techstart.name}")
        print(f"  ✅ Created {enterprise_co.name}")

        # Create Teams
        print("\n👥 Creating teams...")
        acme_engineering = Team(
            id=uuid4(),
            organization_id=acme.id,
            name="Engineering",
            slug="engineering",
            description="Product development team"
        )

        acme_sales = Team(
            id=uuid4(),
            organization_id=acme.id,
            name="Sales",
            slug="sales",
            description="Sales and customer success"
        )

        techstart_dev = Team(
            id=uuid4(),
            organization_id=techstart.id,
            name="Development",
            slug="development",
            description="Core development team"
        )

        enterprise_platform = Team(
            id=uuid4(),
            organization_id=enterprise_co.id,
            name="Platform Team",
            slug="platform",
            description="Infrastructure and platform"
        )

        db.add_all([acme_engineering, acme_sales, techstart_dev, enterprise_platform])
        await db.commit()
        print(f"  ✅ Created {acme_engineering.name} ({acme.name})")
        print(f"  ✅ Created {acme_sales.name} ({acme.name})")
        print(f"  ✅ Created {techstart_dev.name} ({techstart.name})")
        print(f"  ✅ Created {enterprise_platform.name} ({enterprise_co.name})")

        # Create System Roles
        print("\n🔐 Creating system roles...")
        admin_role = Role(
            id=uuid4(),
            name="Admin",
            slug="admin",
            description="Full system access",
            is_system_role=True,
            organization_id=None
        )

        member_role = Role(
            id=uuid4(),
            name="Member",
            slug="member",
            description="Standard member access",
            is_system_role=True,
            organization_id=None
        )

        viewer_role = Role(
            id=uuid4(),
            name="Viewer",
            slug="viewer",
            description="Read-only access",
            is_system_role=True,
            organization_id=None
        )

        db.add_all([admin_role, member_role, viewer_role])
        await db.commit()
        print(f"  ✅ Created system role: {admin_role.name}")
        print(f"  ✅ Created system role: {member_role.name}")
        print(f"  ✅ Created system role: {viewer_role.name}")

        # Create Permissions for Admin Role
        print("\n🔑 Creating permissions...")
        admin_permissions = [
            Permission(id=uuid4(), role_id=admin_role.id, resource="organizations", action="create"),
            Permission(id=uuid4(), role_id=admin_role.id, resource="organizations", action="read"),
            Permission(id=uuid4(), role_id=admin_role.id, resource="organizations", action="update"),
            Permission(id=uuid4(), role_id=admin_role.id, resource="organizations", action="delete"),
            Permission(id=uuid4(), role_id=admin_role.id, resource="users", action="create"),
            Permission(id=uuid4(), role_id=admin_role.id, resource="users", action="read"),
            Permission(id=uuid4(), role_id=admin_role.id, resource="users", action="update"),
            Permission(id=uuid4(), role_id=admin_role.id, resource="users", action="delete"),
            Permission(id=uuid4(), role_id=admin_role.id, resource="teams", action="create"),
            Permission(id=uuid4(), role_id=admin_role.id, resource="teams", action="read"),
            Permission(id=uuid4(), role_id=admin_role.id, resource="teams", action="update"),
            Permission(id=uuid4(), role_id=admin_role.id, resource="teams", action="delete"),
        ]

        member_permissions = [
            Permission(id=uuid4(), role_id=member_role.id, resource="users", action="read"),
            Permission(id=uuid4(), role_id=member_role.id, resource="teams", action="read"),
            Permission(id=uuid4(), role_id=member_role.id, resource="organizations", action="read"),
        ]

        viewer_permissions = [
            Permission(id=uuid4(), role_id=viewer_role.id, resource="users", action="read"),
            Permission(id=uuid4(), role_id=viewer_role.id, resource="teams", action="read"),
        ]

        db.add_all(admin_permissions + member_permissions + viewer_permissions)
        await db.commit()
        print(f"  ✅ Created {len(admin_permissions)} admin permissions")
        print(f"  ✅ Created {len(member_permissions)} member permissions")
        print(f"  ✅ Created {len(viewer_permissions)} viewer permissions")

        # Create Users
        print("\n👤 Creating users...")

        # Acme Corp users
        acme_admin = EnterpriseUser(
            id=uuid4(),
            organization_id=acme.id,
            team_id=acme_engineering.id,
            email="admin@acme.com",
            full_name="John Doe",
            hashed_password=hash_password("password123"),
            is_active=True,
            is_verified=True
        )

        acme_user = EnterpriseUser(
            id=uuid4(),
            organization_id=acme.id,
            team_id=acme_sales.id,
            email="sales@acme.com",
            full_name="Bob Johnson",
            hashed_password=hash_password("password123"),
            is_active=True,
            is_verified=True
        )

        # TechStart users
        techstart_admin = EnterpriseUser(
            id=uuid4(),
            organization_id=techstart.id,
            team_id=techstart_dev.id,
            email="admin@techstart.io",
            full_name="Jane Smith",
            hashed_password=hash_password("password123"),
            is_active=True,
            is_verified=True
        )

        # Enterprise Co users (SSO user - no password)
        enterprise_sso_user = EnterpriseUser(
            id=uuid4(),
            organization_id=enterprise_co.id,
            team_id=enterprise_platform.id,
            email="alice@enterprise.co",
            full_name="Alice Johnson",
            hashed_password=None,  # SSO-only user
            is_active=True,
            is_verified=True,
            sso_provider="saml",
            sso_subject_id="alice.johnson@enterprise.co"
        )

        db.add_all([acme_admin, acme_user, techstart_admin, enterprise_sso_user])
        await db.commit()
        print(f"  ✅ Created {acme_admin.email} (Acme Admin)")
        print(f"  ✅ Created {acme_user.email} (Acme Sales)")
        print(f"  ✅ Created {techstart_admin.email} (TechStart Admin)")
        print(f"  ✅ Created {enterprise_sso_user.email} (Enterprise SSO)")

        # Assign Roles to Users
        print("\n🎭 Assigning roles...")
        user_roles = [
            UserRole(id=uuid4(), user_id=acme_admin.id, role_id=admin_role.id),
            UserRole(id=uuid4(), user_id=acme_user.id, role_id=member_role.id),
            UserRole(id=uuid4(), user_id=techstart_admin.id, role_id=admin_role.id),
            UserRole(id=uuid4(), user_id=enterprise_sso_user.id, role_id=admin_role.id),
        ]

        db.add_all(user_roles)
        await db.commit()
        print(f"  ✅ Assigned roles to {len(user_roles)} users")

        # Create SSO Configuration for Enterprise Co
        print("\n🔒 Creating SSO configuration...")
        sso_config = SSOConfiguration(
            id=uuid4(),
            organization_id=enterprise_co.id,
            provider_type="saml",
            provider_name="Okta Enterprise",
            is_enabled=True,
            saml_entity_id="https://enterprise.okta.com/metadata",
            saml_sso_url="https://enterprise.okta.com/sso/saml",
            saml_slo_url="https://enterprise.okta.com/slo/saml",
            saml_x509_cert="MIIDXTCCAkWgAwIBAgIJAKZ...EXAMPLE_CERT",
            saml_name_id_format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            attribute_mapping={
                "email": "emailAddress",
                "full_name": "displayName",
                "first_name": "firstName",
                "last_name": "lastName"
            },
            auto_create_users=True,
            default_role_id=member_role.id
        )

        db.add(sso_config)
        await db.commit()
        print(f"  ✅ Created SSO config for {enterprise_co.name}")

    print("\n✅ Database seeded successfully!")
    print("\n📊 Summary:")
    print(f"  - 3 organizations")
    print(f"  - 4 teams")
    print(f"  - 4 users (3 with password, 1 SSO)")
    print(f"  - 3 system roles")
    print(f"  - 27 permissions")
    print(f"  - 1 SSO configuration")
    print("\n🔑 Test Credentials:")
    print("  - admin@acme.com / password123")
    print("  - sales@acme.com / password123")
    print("  - admin@techstart.io / password123")
    print("  - alice@enterprise.co (SSO only)")


async def main():
    """Main entry point."""
    # Initialize database schema
    print("🔧 Initializing database schema...")
    await init_db()
    print("✅ Database schema created")

    # Seed data
    await seed_database()


if __name__ == "__main__":
    asyncio.run(main())
