# FaultMaven Auth Service - Enterprise Edition
# Extends the PUBLIC open-source foundation with enterprise features

# Start with PUBLIC foundation from Docker Hub
FROM faultmaven/fm-auth-service:latest AS base

# Set working directory
WORKDIR /app

# Install enterprise-specific system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    postgresql-client \
    libxml2-dev \
    libxmlsec1-dev \
    libxmlsec1-openssl \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy enterprise requirements
COPY requirements.txt /app/enterprise-requirements.txt

# Install enterprise dependencies
RUN pip install --no-cache-dir -r /app/enterprise-requirements.txt

# Copy enterprise code
COPY enterprise/ /app/enterprise/
COPY alembic/ /app/alembic/
COPY alembic.ini /app/alembic.ini

# Create non-root user for security
RUN useradd -m -u 1000 authservice && \
    chown -R authservice:authservice /app

# Switch to non-root user
USER authservice

# Set enterprise environment variables
ENV ENTERPRISE_MODE=true
ENV FAULTMAVEN_EDITION=enterprise
ENV PYTHONPATH=/app

# Expose port 8000 (internal container port)
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run database migrations and start server
CMD ["sh", "-c", "alembic upgrade head && uvicorn enterprise.main:app --host 0.0.0.0 --port 8000"]
