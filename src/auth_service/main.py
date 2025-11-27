"""FaultMaven Auth Service

Main FastAPI application entry point.
Extracted from FaultMaven monolith - Phase 1 microservice.
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from auth_service.config.settings import get_settings
from auth_service.api.routes import auth, service_auth
from auth_service.infrastructure.redis.client import get_redis_client, close_redis_client
from auth_service.domain.services.service_token_manager import initialize_service_token_manager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events"""
    settings = get_settings()

    # Startup
    logger.info(f"Starting {settings.service_name} v{settings.service_version}")
    logger.info(f"Environment: {settings.environment}")

    # Initialize Redis
    try:
        redis_client = await get_redis_client()
        logger.info("Redis connection established")
    except Exception as e:
        logger.error(f"Failed to connect to Redis: {e}")
        raise

    # Initialize Service Token Manager
    try:
        initialize_service_token_manager(
            private_key_path=settings.service_private_key_path,
            permissions_config_path=settings.service_permissions_config_path,
            token_issuer=settings.service_token_issuer,
            default_ttl_seconds=settings.service_token_ttl_seconds,
        )
        logger.info("Service token manager initialized")
    except Exception as e:
        logger.warning(f"Failed to initialize service token manager: {e}")
        logger.warning("Service-to-service authentication will not be available")

    yield

    # Shutdown
    logger.info("Shutting down Auth Service")
    await close_redis_client()
    logger.info("Redis connection closed")


# Create FastAPI application
settings = get_settings()
app = FastAPI(
    title="FaultMaven Auth Service",
    version=settings.service_version,
    description="Authentication and user management service extracted from FaultMaven monolith",
    lifespan=lifespan
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=settings.cors_allow_credentials,
    allow_methods=settings.cors_allow_methods,
    allow_headers=settings.cors_allow_headers,
)


# Health check endpoint
@app.get("/health")
async def root_health_check():
    """Root health check endpoint"""
    return {
        "status": "healthy",
        "service": settings.service_name,
        "version": settings.service_version,
        "environment": settings.environment
    }


@app.get("/")
async def root():
    """Root endpoint with service information"""
    return {
        "service": settings.service_name,
        "version": settings.service_version,
        "description": "FaultMaven Authentication Service",
        "docs": "/docs",
        "health": "/health"
    }


# Include routers (auth.router already has /api/v1/auth prefix)
app.include_router(auth.router, tags=["authentication"])
app.include_router(service_auth.router, tags=["service-authentication"])


# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Global exception handler for unhandled errors"""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": "internal_server_error",
            "message": "An unexpected error occurred. Please try again later."
        }
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "auth_service.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
        log_level=settings.log_level.lower()
    )
