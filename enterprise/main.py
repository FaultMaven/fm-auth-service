"""
Enterprise FastAPI application.

Extends the PUBLIC base application with enterprise routes.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from enterprise.api import organizations_router, teams_router, users_router, sso_router
from enterprise.database import close_db

# Create FastAPI app
app = FastAPI(
    title="FaultMaven Auth Service - Enterprise Edition",
    description="Multi-tenant SaaS authentication service",
    version="1.0.0",
    docs_url="/enterprise/docs",
    redoc_url="/enterprise/redoc",
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure properly in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include enterprise routers
app.include_router(organizations_router)
app.include_router(teams_router)
app.include_router(users_router)
app.include_router(sso_router)


@app.on_event("startup")
async def startup():
    """Startup event handler."""
    print("🚀 FaultMaven Auth Service - Enterprise Edition starting...")
    print("📊 API Documentation: http://localhost:8001/enterprise/docs")


@app.on_event("shutdown")
async def shutdown():
    """Shutdown event handler."""
    print("👋 Shutting down...")
    await close_db()


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
