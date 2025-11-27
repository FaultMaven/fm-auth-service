"""
Enterprise FastAPI application.

Extends the PUBLIC base application with enterprise routes.
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from enterprise.api import auth_router, organizations_router, teams_router, users_router, sso_router
from enterprise.database import close_db
from enterprise.config.settings import get_settings

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events."""
    # Startup
    logger.info("FaultMaven Auth Service - Enterprise Edition starting...")
    logger.info("API Documentation: http://localhost:8001/enterprise/docs")

    yield

    # Shutdown
    logger.info("Shutting down...")
    await close_db()


# Create FastAPI app
app = FastAPI(
    title="FaultMaven Auth Service - Enterprise Edition",
    description="Multi-tenant SaaS authentication service with JWT authentication",
    version="1.0.0",
    docs_url="/enterprise/docs",
    redoc_url="/enterprise/redoc",
    lifespan=lifespan,
)

# CORS middleware
# WARNING: allow_origins=["*"] with allow_credentials=True is insecure for production.
# Configure specific allowed origins in production environments.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # TODO: Configure specific origins for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include enterprise routers
# Note: auth_router must be first (no authentication required for login/register)
app.include_router(auth_router)
app.include_router(organizations_router)
app.include_router(teams_router)
app.include_router(users_router)
app.include_router(sso_router)


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "service": "FaultMaven Auth Service",
        "edition": "enterprise",
        "version": "1.0.0",
        "status": "running"
    }


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy", "edition": "enterprise"}
