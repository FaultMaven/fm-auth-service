"""Domain models for Auth Service"""

from auth_service.domain.models.api_auth import (
    AuthenticationRequiredError,
    AuthError,
    AuthTokenResponse,
    DevLoginRequest,
    LogoutResponse,
    TokenValidationError,
    UserInfoResponse,
    UserProfile,
)
from auth_service.domain.models.auth import (
    AuthToken,
    DevUser,
    TokenStatus,
    TokenValidationResult,
    parse_utc_timestamp,
    to_json_compatible,
)

__all__ = [
    # Auth models
    "DevUser",
    "AuthToken",
    "TokenStatus",
    "TokenValidationResult",
    "parse_utc_timestamp",
    "to_json_compatible",
    # API models
    "DevLoginRequest",
    "AuthTokenResponse",
    "UserProfile",
    "LogoutResponse",
    "AuthError",
    "TokenValidationError",
    "AuthenticationRequiredError",
    "UserInfoResponse",
]
