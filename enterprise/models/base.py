"""
SQLAlchemy declarative base for enterprise models.

The PUBLIC foundation uses Pydantic models with SQLite.
Enterprise uses SQLAlchemy ORM with PostgreSQL for multi-tenancy.
"""

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """
    Base class for all enterprise SQLAlchemy models.

    All enterprise models inherit from this base to enable:
    - PostgreSQL-specific features
    - Multi-tenancy with foreign keys
    - Advanced querying and relationships
    """

    pass
