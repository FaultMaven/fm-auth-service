"""
FaultMaven Auth Service - Enterprise Edition

This package extends the PUBLIC fm-auth-service foundation with enterprise features:
- PostgreSQL database support
- Multi-tenancy (organizations and teams)
- SSO integration (SAML, OAuth, OIDC)
- Advanced role-based access control (RBAC)
- Audit logging
- Enterprise monitoring and analytics
"""

__version__ = "1.0.0"
__edition__ = "enterprise"

# Import enterprise components
from enterprise.config import EnterpriseConfig

__all__ = ["EnterpriseConfig"]
