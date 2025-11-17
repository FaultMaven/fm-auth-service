"""
FaultMaven Auth Service - Enterprise Edition

Enterprise extensions for the FaultMaven authentication microservice.
Extends the PUBLIC open-source foundation with enterprise features.
"""

from setuptools import setup, find_packages

setup(
    name="fm-auth-service-enterprise",
    version="1.0.0",
    description="FaultMaven Auth Service - Enterprise Edition",
    author="FaultMaven",
    packages=find_packages(),
    python_requires=">=3.11",
    install_requires=[
        # PostgreSQL support
        "psycopg2-binary>=2.9.9",
        "asyncpg>=0.29.0",
        "sqlalchemy-utils>=0.41.1",

        # Database migrations
        "alembic>=1.13.0",

        # SSO/SAML support
        "python3-saml>=1.16.0",

        # Multi-tenancy (custom implementation)
        # Custom multi-tenancy implementation - no external package needed

        # Additional security
        "python-jose[cryptography]>=3.3.0",
        "bcrypt>=4.1.0",

        # Monitoring and observability
        "sentry-sdk[fastapi]>=1.39.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.1.0",
            "black>=23.10.0",
            "flake8>=6.1.0",
            "mypy>=1.7.0",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3.11",
        "License :: Other/Proprietary License",
    ],
)
