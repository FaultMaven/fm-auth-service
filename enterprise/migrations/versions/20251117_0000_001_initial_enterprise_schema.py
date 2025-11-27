"""Initial enterprise schema

Revision ID: 001
Revises:
Create Date: 2025-11-17 00:00:00.000000

Creates the initial PostgreSQL schema for FaultMaven Enterprise multi-tenant SaaS:
- Organizations (tenants)
- Teams (sub-organization groups)
- Users (with org/team relationships)
- Roles & Permissions (RBAC)
- Audit Logs (compliance)
- SSO Configurations (SAML/OAuth/OIDC)
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create organizations table
    op.create_table(
        "organizations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("slug", sa.String(100), nullable=False, unique=True),
        sa.Column("plan", sa.String(50), nullable=False, server_default="trial"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("max_users", sa.Integer(), nullable=False, server_default="10"),
        sa.Column("max_teams", sa.Integer(), nullable=False, server_default="5"),
        sa.Column("contact_email", sa.String(255), nullable=True),
        sa.Column("contact_name", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.Column("deleted_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_organizations_name", "organizations", ["name"])
    op.create_index("ix_organizations_slug", "organizations", ["slug"])
    op.create_index("ix_organizations_is_active", "organizations", ["is_active"])

    # Create teams table
    op.create_table(
        "teams",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("slug", sa.String(100), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.Column("deleted_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_teams_organization_id", "teams", ["organization_id"])

    # Create users table
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("team_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("email", sa.String(255), nullable=False, unique=True),
        sa.Column("hashed_password", sa.String(255), nullable=True),  # None for SSO-only
        sa.Column("full_name", sa.String(255), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("is_verified", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("sso_provider", sa.String(50), nullable=True),
        sa.Column("sso_subject_id", sa.String(255), nullable=True),
        sa.Column("last_login_at", sa.DateTime(), nullable=True),
        sa.Column("password_changed_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.Column("deleted_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["team_id"], ["teams.id"], ondelete="SET NULL"),
    )
    op.create_index("ix_users_email", "users", ["email"])
    op.create_index("ix_users_organization_id", "users", ["organization_id"])
    op.create_index("ix_users_team_id", "users", ["team_id"])
    op.create_index("ix_users_is_active", "users", ["is_active"])
    op.create_index("ix_users_sso_subject_id", "users", ["sso_subject_id"])

    # Create roles table
    op.create_table(
        "roles",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("slug", sa.String(100), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("is_system_role", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("organization_id", "slug", name="uq_org_role_slug"),
    )
    op.create_index("ix_roles_organization_id", "roles", ["organization_id"])

    # Create permissions table
    op.create_table(
        "permissions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("role_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("resource", sa.String(100), nullable=False),
        sa.Column("action", sa.String(50), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["role_id"], ["roles.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("role_id", "resource", "action", name="uq_role_resource_action"),
    )
    op.create_index("ix_permissions_role_id", "permissions", ["role_id"])

    # Create user_roles table
    op.create_table(
        "user_roles",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("role_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("assigned_at", sa.DateTime(), nullable=False),
        sa.Column("assigned_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["role_id"], ["roles.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("user_id", "role_id", name="uq_user_role"),
    )
    op.create_index("ix_user_roles_user_id", "user_roles", ["user_id"])
    op.create_index("ix_user_roles_role_id", "user_roles", ["role_id"])

    # Create audit_logs table
    op.create_table(
        "audit_logs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("event_type", sa.String(100), nullable=False),
        sa.Column("action", sa.String(50), nullable=False),
        sa.Column("resource", sa.String(100), nullable=True),
        sa.Column("resource_id", sa.String(255), nullable=True),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("request_id", sa.String(100), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="success"),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("context_data", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="SET NULL"),
    )
    op.create_index("ix_audit_logs_organization_id", "audit_logs", ["organization_id"])
    op.create_index("ix_audit_logs_user_id", "audit_logs", ["user_id"])
    op.create_index("ix_audit_logs_event_type", "audit_logs", ["event_type"])
    op.create_index("ix_audit_logs_request_id", "audit_logs", ["request_id"])
    op.create_index("ix_audit_logs_created_at", "audit_logs", ["created_at"])

    # Create sso_configurations table
    op.create_table(
        "sso_configurations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("provider_type", sa.String(50), nullable=False),
        sa.Column("provider_name", sa.String(255), nullable=False),
        sa.Column("is_enabled", sa.Boolean(), nullable=False, server_default="true"),
        # SAML fields
        sa.Column("saml_entity_id", sa.Text(), nullable=True),
        sa.Column("saml_sso_url", sa.Text(), nullable=True),
        sa.Column("saml_slo_url", sa.Text(), nullable=True),
        sa.Column("saml_x509_cert", sa.Text(), nullable=True),
        sa.Column("saml_name_id_format", sa.String(255), nullable=True),
        # OAuth/OIDC fields
        sa.Column("oauth_client_id", sa.String(255), nullable=True),
        sa.Column("oauth_client_secret", sa.String(500), nullable=True),
        sa.Column("oauth_authorization_url", sa.Text(), nullable=True),
        sa.Column("oauth_token_url", sa.Text(), nullable=True),
        sa.Column("oauth_userinfo_url", sa.Text(), nullable=True),
        sa.Column("oauth_scopes", sa.String(500), nullable=True),
        sa.Column("oidc_issuer", sa.Text(), nullable=True),
        sa.Column("oidc_jwks_uri", sa.Text(), nullable=True),
        # Configuration
        sa.Column("attribute_mapping", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("auto_create_users", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("default_role_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
    )
    op.create_index(
        "ix_sso_configurations_organization_id", "sso_configurations", ["organization_id"]
    )


def downgrade() -> None:
    # Drop tables in reverse order (respecting foreign keys)
    op.drop_table("sso_configurations")
    op.drop_table("audit_logs")
    op.drop_table("user_roles")
    op.drop_table("permissions")
    op.drop_table("roles")
    op.drop_table("users")
    op.drop_table("teams")
    op.drop_table("organizations")
