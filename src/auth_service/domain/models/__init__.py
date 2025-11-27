"""Domain models for Auth Service"""

from auth_service.domain.models.auth import (
    DevUser,
    AuthToken,
    TokenStatus,
    TokenValidationResult,
    parse_utc_timestamp,
    to_json_compatible,
)
from auth_service.domain.models.api_auth import (
    DevLoginRequest,
    AuthTokenResponse,
    UserProfile,
    LogoutResponse,
    AuthError,
    TokenValidationError,
    AuthenticationRequiredError,
    UserInfoResponse,
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
