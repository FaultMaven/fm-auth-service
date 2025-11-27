"""
Enterprise API routes.

Provides REST API endpoints for:
- Authentication (login, register, token refresh)
- Organization management
- Team management
- User management (within organizations)
- SSO configuration
"""

from enterprise.api.auth import router as auth_router
from enterprise.api.organizations import router as organizations_router
from enterprise.api.sso import router as sso_router
from enterprise.api.teams import router as teams_router
from enterprise.api.users import router as users_router

__all__ = [
    "auth_router",
    "organizations_router",
    "teams_router",
    "users_router",
    "sso_router",
]
