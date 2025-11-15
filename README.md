# FaultMaven Auth Service

Authentication and user management microservice extracted from the FaultMaven monolith (Phase 1, Days 8-9).

## Overview

This service provides authentication and user management capabilities for the FaultMaven ecosystem. It was extracted from the monolith as the first microservice in the enterprise migration strategy.

### Features

- User registration and login (development mode)
- JWT token generation and validation
- Token revocation and management
- User profile management
- Redis-based session storage
- Health check endpoints

### Technology Stack

- **Framework**: FastAPI 0.104+
- **Python**: 3.11+
- **Storage**: Redis (tokens), PostgreSQL (users - future)
- **Authentication**: JWT tokens (HS256 → RS256 in Phase 2)

## Quick Start

### Prerequisites

- Python 3.11+
- Poetry
- Redis
- Docker & Docker Compose (optional)

### Local Development

1. **Clone and setup**:
```bash
cd /home/swhouse/projects/fm-auth-service
cp .env.example .env
# Edit .env with your configuration
```

2. **Install dependencies**:
```bash
poetry install
```

3. **Start Redis** (if not using Docker):
```bash
# Option 1: Local Redis
redis-server

# Option 2: Docker Redis
docker run -d -p 6379:6379 redis:7-alpine
```

4. **Run the service**:
```bash
poetry run uvicorn auth_service.main:app --reload --port 8000
```

5. **Access the API**:
- API Docs: http://localhost:8000/docs
- Health Check: http://localhost:8000/health
- Auth Health: http://localhost:8000/api/v1/auth/health

### Docker Compose (Recommended)

```bash
# Start all services (Postgres, Redis, Auth Service)
docker-compose up -d

# View logs
docker-compose logs -f auth-service

# Stop services
docker-compose down
```

## API Endpoints

### Authentication

- `POST /api/v1/auth/dev-register` - Register new user
- `POST /api/v1/auth/dev-login` - Login user
- `POST /api/v1/auth/logout` - Logout (revoke token)
- `GET /api/v1/auth/me` - Get current user profile
- `GET /api/v1/auth/health` - Authentication system health

### Example: Register and Login

```bash
# Register new user
curl -X POST http://localhost:8000/api/v1/auth/dev-register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john.doe",
    "email": "john@example.com",
    "display_name": "John Doe"
  }'

# Login
curl -X POST http://localhost:8000/api/v1/auth/dev-login \
  -H "Content-Type: application/json" \
  -d '{"username": "john.doe"}'

# Get user profile (use token from login response)
curl -X GET http://localhost:8000/api/v1/auth/me \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

## Testing

```bash
# Run all tests
poetry run pytest

# Run with coverage
poetry run pytest --cov=auth_service --cov-report=html

# Run specific test file
poetry run pytest tests/unit/test_auth_routes.py -v
```

## Project Structure

```
fm-auth-service/
├── src/auth_service/
│   ├── api/
│   │   └── routes/
│   │       └── auth.py          # Auth API endpoints
│   ├── domain/
│   │   ├── models/
│   │   │   ├── auth.py          # Domain models (User, Token)
│   │   │   └── api_auth.py      # API request/response models
│   │   └── services/            # Business logic (future)
│   ├── infrastructure/
│   │   ├── auth/
│   │   │   ├── token_manager.py # JWT token management
│   │   │   └── user_store.py    # User storage (Redis)
│   │   ├── redis/
│   │   │   └── client.py        # Redis connection
│   │   └── persistence/         # Database (future)
│   ├── config/
│   │   └── settings.py          # Configuration management
│   └── main.py                  # FastAPI application
├── tests/
│   ├── unit/                    # Unit tests
│   ├── integration/             # Integration tests
│   └── contract/                # Contract tests
├── docker-compose.yml           # Local development stack
├── Dockerfile                   # Container image
├── pyproject.toml              # Dependencies
└── README.md
```

## Deployment

### Environment Variables

See `.env.example` for all configuration options.

Key variables:
- `REDIS_HOST`, `REDIS_PORT` - Redis connection
- `DATABASE_URL` - PostgreSQL (Phase 2)
- `JWT_SECRET_KEY` - Token signing (HS256)
- `LOG_LEVEL` - Logging verbosity

### Database Migrations (Phase 2)

```bash
# Create migration
poetry run alembic revision -m "description"

# Run migrations
poetry run alembic upgrade head

# Rollback
poetry run alembic downgrade -1
```

## Migration Status

### ✅ Phase 1 (Days 8-9) - COMPLETED

- [x] Extract auth routes from monolith
- [x] Extract domain models (User, Token)
- [x] Extract infrastructure (TokenManager, UserStore)
- [x] Implement FastAPI application
- [x] Redis integration for token storage
- [x] Basic unit tests
- [x] Docker containerization
- [x] Health check endpoints

### 🔄 Phase 2 (Future)

- [ ] PostgreSQL database integration
- [ ] Alembic migrations for user tables
- [ ] RS256 JWT tokens with key pairs
- [ ] Token blacklist in Redis
- [ ] Organization and team management
- [ ] RBAC (roles and permissions)
- [ ] Event publishing (user.created, etc.)
- [ ] Contract tests with Pact
- [ ] Production observability (metrics, tracing)

## Contributing

This is part of the FaultMaven enterprise microservices migration. See the main repository's `ENTERPRISE_MICROSERVICES_MIGRATION_PLAN.md` for the overall strategy.

## License

Copyright FaultMaven Team. Internal use only.
