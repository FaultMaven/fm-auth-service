"""Service Authentication API Routes

Provides endpoints for service-to-service authentication.
"""

import logging
from typing import List

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from auth_service.domain.services.service_token_manager import get_service_token_manager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/service-auth", tags=["service-auth"])


# ============================================================================
# Request/Response Models
# ============================================================================


class ServiceTokenRequest(BaseModel):
    """Request body for service token creation."""

    service_id: str = Field(..., description="Service identifier (e.g., fm-agent-service)")
    audience: List[str] = Field(
        ..., description="List of services this token can access"
    )
    ttl_seconds: int = Field(
        default=3600,
        ge=60,
        le=86400,
        description="Token TTL in seconds (min: 60, max: 86400)",
    )


class ServiceTokenResponse(BaseModel):
    """Response containing service token."""

    token: str = Field(..., description="JWT service token")
    expires_at: str = Field(..., description="Token expiration time (ISO 8601)")
    expires_in: int = Field(..., description="Token TTL in seconds")


# ============================================================================
# Endpoints
# ============================================================================


@router.post("/service-token", response_model=ServiceTokenResponse)
async def create_service_token(request: ServiceTokenRequest):
    """Create a service authentication token.

    This endpoint issues JWT tokens for service-to-service authentication.
    Services use these tokens to authenticate themselves when calling other services.

    **Token Structure**:
    - Algorithm: RS256 (asymmetric)
    - Issuer: fm-auth-service
    - Subject: service_id
    - Audience: List of services token can access
    - Custom claims: service_id, permissions

    **Example Request**:
    ```json
    {
      "service_id": "fm-agent-service",
      "audience": ["fm-case-service", "fm-knowledge-service"],
      "ttl_seconds": 3600
    }
    ```

    **Example Response**:
    ```json
    {
      "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
      "expires_at": "2025-11-27T15:30:00Z",
      "expires_in": 3600
    }
    ```

    Args:
        request: Service token request

    Returns:
        ServiceTokenResponse with JWT token

    Raises:
        HTTPException: If service_id not found in permissions config
    """
    try:
        token_manager = get_service_token_manager()

        # Create service token
        token_data = token_manager.create_service_token(
            service_id=request.service_id,
            audience=request.audience,
            ttl_seconds=request.ttl_seconds,
        )

        logger.info(
            f"Issued service token for {request.service_id}, "
            f"audience={request.audience}, ttl={request.ttl_seconds}s"
        )

        return ServiceTokenResponse(**token_data)

    except ValueError as e:
        logger.warning(f"Invalid service token request: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)
        )
    except Exception as e:
        logger.error(f"Failed to create service token: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create service token",
        )


@router.get("/service-auth-health")
async def service_auth_health():
    """Health check endpoint for service authentication.

    Returns:
        Health status
    """
    try:
        token_manager = get_service_token_manager()
        return {
            "status": "healthy",
            "service": "service-auth",
            "issuer": token_manager.token_issuer,
            "services_configured": len(token_manager.permissions_map),
        }
    except Exception as e:
        logger.error(f"Service auth health check failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service authentication not available",
        )
