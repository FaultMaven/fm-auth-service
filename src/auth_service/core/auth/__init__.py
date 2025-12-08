"""Authentication provider abstraction layer.

Supports multiple authentication methods via pluggable providers:
- local: Username/password with JWT (self-hosted default)
- oidc: OpenID Connect (Google, Okta, Azure AD)
- saml: SAML 2.0 (enterprise SSO)
"""

from .provider import AuthProvider, UserIdentity
from .factory import get_auth_provider

__all__ = [
    "AuthProvider",
    "UserIdentity",
    "get_auth_provider",
]
