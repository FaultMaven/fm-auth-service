# Enterprise Development Guide

Quick start guide for local enterprise development.

## Prerequisites

- Docker & Docker Compose
- Python 3.11+ (for local development)
- PostgreSQL client tools (optional, for CLI access)

## Quick Start

### 1. Start Enterprise Stack

```bash
# Start PostgreSQL, Redis, and Auth Service
docker-compose -f docker-compose.enterprise.yml up -d

# Watch logs
docker-compose -f docker-compose.enterprise.yml logs -f auth-enterprise

# Stop everything
docker-compose -f docker-compose.enterprise.yml down
```

### 2. Verify Services

```bash
# Check all services are healthy
docker-compose -f docker-compose.enterprise.yml ps

# Test database connection
docker exec -it fm-auth-postgres psql -U faultmaven -d faultmaven_enterprise -c '\dt'

# Test Redis connection
docker exec -it fm-auth-redis redis-cli ping
```

### 3. Run Database Migrations

Migrations run automatically on container start, but you can run them manually:

```bash
# Run migrations
docker exec -it fm-auth-enterprise sh -c "cd /app/enterprise && alembic upgrade head"

# Check migration status
docker exec -it fm-auth-enterprise sh -c "cd /app/enterprise && alembic current"

# Rollback one migration
docker exec -it fm-auth-enterprise sh -c "cd /app/enterprise && alembic downgrade -1"
```

### 4. Access Services

- **Auth API**: http://localhost:8001
- **API Docs**: http://localhost:8001/docs
- **PostgreSQL**: localhost:5432 (user: faultmaven, db: faultmaven_enterprise)
- **Redis**: localhost:6379
- **pgAdmin** (optional): http://localhost:5050 (start with `--profile tools`)

## Development Workflow

### Local Python Development

```bash
# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # or `.venv\Scripts\activate` on Windows

# Install dependencies
pip install -r requirements.txt
pip install -e enterprise/

# Set environment variables
export DATABASE_URL="postgresql://faultmaven:dev_password_change_in_production@localhost:5432/faultmaven_enterprise"
export REDIS_URL="redis://localhost:6379"
export ENTERPRISE_MODE=true

# Run migrations
cd enterprise
alembic upgrade head

# Start development server with hot-reload
cd ..
uvicorn auth_service.main:app --reload --host 0.0.0.0 --port 8001
```

### Creating New Migrations

```bash
# Auto-generate migration from model changes
cd enterprise
alembic revision --autogenerate -m "Add new feature"

# Create empty migration
alembic revision -m "Custom migration"

# Edit the generated file in migrations/versions/
# Then apply it
alembic upgrade head
```

### Database Management

```bash
# Connect to PostgreSQL
docker exec -it fm-auth-postgres psql -U faultmaven -d faultmaven_enterprise

# Useful SQL commands
\dt                    # List tables
\d organizations       # Describe table
SELECT * FROM organizations LIMIT 10;

# Backup database
docker exec fm-auth-postgres pg_dump -U faultmaven faultmaven_enterprise > backup.sql

# Restore database
docker exec -i fm-auth-postgres psql -U faultmaven faultmaven_enterprise < backup.sql
```

### Testing API Endpoints

```bash
# Create organization
curl -X POST http://localhost:8001/api/v1/enterprise/organizations \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Acme Corp",
    "slug": "acme-corp",
    "plan": "professional",
    "contact_email": "admin@acme.com"
  }'

# List organizations
curl http://localhost:8001/api/v1/enterprise/organizations

# Create team
curl -X POST http://localhost:8001/api/v1/enterprise/teams \
  -H "Content-Type: application/json" \
  -d '{
    "organization_id": "org-uuid-here",
    "name": "Engineering",
    "slug": "engineering"
  }'
```

## Troubleshooting

### Container won't start

```bash
# Check logs
docker-compose -f docker-compose.enterprise.yml logs auth-enterprise

# Rebuild image
docker-compose -f docker-compose.enterprise.yml build --no-cache

# Remove volumes and start fresh
docker-compose -f docker-compose.enterprise.yml down -v
docker-compose -f docker-compose.enterprise.yml up -d
```

### Database connection errors

```bash
# Verify PostgreSQL is running
docker-compose -f docker-compose.enterprise.yml ps postgres

# Check PostgreSQL logs
docker-compose -f docker-compose.enterprise.yml logs postgres

# Test connection
docker exec -it fm-auth-postgres psql -U faultmaven -d faultmaven_enterprise -c 'SELECT 1'
```

### Migration errors

```bash
# Check current migration version
docker exec -it fm-auth-enterprise sh -c "cd /app/enterprise && alembic current"

# View migration history
docker exec -it fm-auth-enterprise sh -c "cd /app/enterprise && alembic history"

# Force migration to specific version
docker exec -it fm-auth-enterprise sh -c "cd /app/enterprise && alembic upgrade <revision>"
```

## Optional Tools

### Start pgAdmin

```bash
# Start with tools profile
docker-compose -f docker-compose.enterprise.yml --profile tools up -d

# Access: http://localhost:5050
# Login: admin@faultmaven.local / admin

# Add server in pgAdmin:
# Host: postgres
# Port: 5432
# Database: faultmaven_enterprise
# Username: faultmaven
# Password: dev_password_change_in_production
```

### Reset Everything

```bash
# Stop all containers and remove volumes
docker-compose -f docker-compose.enterprise.yml down -v

# Remove enterprise images
docker images | grep fm-auth-service-enterprise | awk '{print $3}' | xargs docker rmi -f

# Start fresh
docker-compose -f docker-compose.enterprise.yml up -d
```

## Production Deployment

For production deployment:

1. **Change all passwords** in environment variables
2. **Set strong JWT_SECRET** (use `openssl rand -hex 32`)
3. **Configure Sentry DSN** for error tracking
4. **Enable SSL/TLS** for PostgreSQL connections
5. **Use secrets management** (Kubernetes secrets, AWS Secrets Manager, etc.)
6. **Configure proper CORS origins**
7. **Set up database backups**
8. **Enable audit logging**
9. **Configure SSO providers** for each organization

See main [README.md](README.md) for full production deployment guide.
