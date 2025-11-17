# FaultMaven Auth Service - Enterprise Edition
# Extends the PUBLIC open-source foundation with enterprise features

# Start with PUBLIC foundation from Docker Hub
FROM faultmaven/fm-auth-service:latest

# Set working directory
WORKDIR /app

# Install enterprise-specific system dependencies
RUN apt-get update && apt-get install -y \
    postgresql-client \
    libxml2-dev \
    libxmlsec1-dev \
    libxmlsec1-openssl \
    && rm -rf /var/lib/apt/lists/*

# Copy enterprise requirements
COPY enterprise/requirements.txt /app/enterprise/requirements.txt

# Install enterprise dependencies
RUN pip install --no-cache-dir -r /app/enterprise/requirements.txt

# Copy enterprise code
COPY enterprise/ /app/enterprise/

# Install enterprise package in development mode
RUN pip install --no-cache-dir -e /app/enterprise

# Set enterprise environment variables
ENV ENTERPRISE_MODE=true
ENV FAULTMAVEN_EDITION=enterprise

# Expose same port as PUBLIC (8001)
EXPOSE 8001

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8001/health', timeout=2)"

# Use same entrypoint as PUBLIC
# Enterprise features activated via environment variables and enterprise package
CMD ["python", "-m", "uvicorn", "auth_service.main:app", "--host", "0.0.0.0", "--port", "8001"]
