# FaultMaven Auth Service - Enterprise Edition

**Proprietary enterprise extensions for the FaultMaven authentication microservice.**

This package extends the open-source PUBLIC foundation (`faultmaven/fm-auth-service`) with enterprise features.

---

## Architecture

```
┌─────────────────────────────────────────┐
│   Enterprise Docker Image (PRIVATE)    │
│                                         │
│  ┌───────────────────────────────────┐ │
│  │  Enterprise Package               │ │
│  │  - PostgreSQL models              │ │
│  │  - Multi-tenancy (organizations)  │ │
│  │  - SSO (SAML, OAuth)              │ │
│  │  - RBAC & audit logging           │ │
│  └───────────────────────────────────┘ │
│              ▲                          │
│              │ Extends                  │
│  ┌───────────┴───────────────────────┐ │
│  │  PUBLIC Foundation                │ │
│  │  FROM faultmaven/fm-auth-service  │ │
│  │  - SQLite database                │ │
│  │  - JWT authentication             │ │
│  │  - Single-user mode               │ │
│  └───────────────────────────────────┘ │
└─────────────────────────────────────────┘
```

---

## Enterprise Features

### Multi-Tenancy
- **Organizations**: Top-level tenant isolation
- **Teams**: Sub-organization grouping
- **User Management**: Org-scoped user administration
- **Data Isolation**: PostgreSQL row-level security

### SSO Integration
- **SAML 2.0**: Enterprise identity providers
- **OAuth 2.0**: Modern authentication flows
- **OIDC**: OpenID Connect support
- **Multi-Provider**: Support multiple IDPs per organization

### Advanced RBAC
- **Roles**: Admin, Member, Viewer, Custom
- **Permissions**: Fine-grained access control
- **Organization-level**: Permissions scoped to orgs
- **Team-level**: Additional team-based permissions

### Audit Logging
- **Complete Audit Trail**: All authentication events
- **Compliance**: SOC2, GDPR, HIPAA ready
- **Separate Storage**: Dedicated audit log database
- **Retention Policies**: Configurable retention

### Enterprise Monitoring
- **Sentry Integration**: Error tracking and alerting
- **Metrics**: Prometheus-compatible metrics
- **Distributed Tracing**: OpenTelemetry support
- **Health Checks**: Enhanced health monitoring

---

## Installation

### Docker (Recommended)

```bash
# Pull from GitHub Container Registry
docker pull ghcr.io/faultmaven/fm-auth-service-enterprise:latest

# Run with PostgreSQL
docker run -d \
  -e DATABASE_URL=postgresql://user:pass@postgres:5432/faultmaven \
  -e REDIS_URL=redis://redis:6379 \
  -e ENTERPRISE_MODE=true \
  -e ENABLE_MULTITENANCY=true \
  -p 8001:8001 \
  ghcr.io/faultmaven/fm-auth-service-enterprise:latest
```

### Development

```bash
# Clone enterprise repository
git clone git@github.com:FaultMaven/fm-auth-service-enterprise.git
cd fm-auth-service-enterprise

# Build enterprise image (extends PUBLIC base)
docker build -t fm-auth-service-enterprise:dev .

# Run development environment
docker-compose up -d
```

---

## Configuration

### Required Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | `postgresql://user:pass@host:5432/db` |
| `REDIS_URL` | Redis connection string | `redis://host:6379` |
| `ENTERPRISE_MODE` | Enable enterprise features | `true` |
| `ENABLE_MULTITENANCY` | Enable multi-tenant mode | `true` |

### Optional SSO Configuration

| Variable | Description |
|----------|-------------|
| `ENTERPRISE_SAML_IDP_ENTITY_ID` | SAML Identity Provider Entity ID |
| `ENTERPRISE_SAML_IDP_SSO_URL` | SAML SSO URL |
| `ENTERPRISE_SAML_IDP_X509_CERT` | SAML X509 Certificate |
| `ENTERPRISE_ENABLE_OAUTH` | Enable OAuth 2.0 |
| `ENTERPRISE_OAUTH_CLIENT_ID` | OAuth Client ID |
| `ENTERPRISE_OAUTH_CLIENT_SECRET` | OAuth Client Secret |

### Optional Monitoring

| Variable | Description |
|----------|-------------|
| `ENTERPRISE_SENTRY_DSN` | Sentry error tracking DSN |
| `ENTERPRISE_ENABLE_METRICS` | Enable Prometheus metrics |
| `ENTERPRISE_ENABLE_TRACING` | Enable distributed tracing |

---

## Database Setup

### Initialize PostgreSQL

```sql
-- Create database
CREATE DATABASE faultmaven_enterprise;

-- Create audit log database (optional)
CREATE DATABASE faultmaven_audit;

-- Run migrations
alembic upgrade head
```

### Run Migrations

```bash
# Inside container or development environment
cd /app/enterprise
alembic upgrade head
```

---

## API Endpoints

### Organization Management

- `POST /api/v1/enterprise/organizations` - Create organization
- `GET /api/v1/enterprise/organizations` - List organizations
- `GET /api/v1/enterprise/organizations/{org_id}` - Get organization
- `PUT /api/v1/enterprise/organizations/{org_id}` - Update organization
- `DELETE /api/v1/enterprise/organizations/{org_id}` - Delete organization

### User Management

- `POST /api/v1/enterprise/organizations/{org_id}/users` - Add user to org
- `GET /api/v1/enterprise/organizations/{org_id}/users` - List org users
- `PUT /api/v1/enterprise/users/{user_id}/role` - Update user role
- `DELETE /api/v1/enterprise/organizations/{org_id}/users/{user_id}` - Remove user

### SSO

- `POST /api/v1/enterprise/sso/saml/login` - SAML login
- `POST /api/v1/enterprise/sso/saml/acs` - SAML assertion consumer
- `GET /api/v1/enterprise/sso/saml/metadata` - SAML metadata

---

## Development

### Project Structure

```
enterprise/
├── __init__.py           # Package initialization
├── setup.py              # Enterprise package setup
├── requirements.txt      # Enterprise dependencies
├── models/               # PostgreSQL models
│   ├── organization.py
│   ├── team.py
│   └── user.py
├── api/                  # Enterprise API routes
│   ├── organizations.py
│   ├── teams.py
│   └── sso.py
├── auth/                 # SSO authentication
│   ├── saml.py
│   ├── oauth.py
│   └── oidc.py
├── migrations/           # Alembic migrations
│   └── versions/
├── config/               # Enterprise configuration
│   └── settings.py
└── tests/                # Enterprise tests
    ├── test_organizations.py
    ├── test_sso.py
    └── test_rbac.py
```

### Running Tests

```bash
# Unit tests
pytest enterprise/tests/

# Integration tests
pytest enterprise/tests/ -m integration

# Coverage report
pytest --cov=enterprise --cov-report=html
```

---

## Deployment

### Docker Compose (Development)

```yaml
version: '3.8'

services:
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: faultmaven_enterprise
      POSTGRES_USER: faultmaven
      POSTGRES_PASSWORD: changeme

  redis:
    image: redis:7-alpine

  auth-enterprise:
    image: ghcr.io/faultmaven/fm-auth-service-enterprise:latest
    ports:
      - "8001:8001"
    environment:
      DATABASE_URL: postgresql://faultmaven:changeme@postgres:5432/faultmaven_enterprise
      REDIS_URL: redis://redis:6379
      ENTERPRISE_MODE: "true"
      ENABLE_MULTITENANCY: "true"
    depends_on:
      - postgres
      - redis
```

### Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: fm-auth-service-enterprise
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: auth-enterprise
        image: ghcr.io/faultmaven/fm-auth-service-enterprise:latest
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: database-credentials
              key: url
        - name: ENTERPRISE_MODE
          value: "true"
```

---

## License

**Proprietary** - FaultMaven Enterprise Edition

This software is licensed for use only by customers with a valid FaultMaven Enterprise license.

For licensing inquiries: sales@faultmaven.ai

---

## Support

- **Documentation**: https://docs.faultmaven.ai/enterprise
- **Support Portal**: https://support.faultmaven.ai
- **Enterprise Support**: enterprise-support@faultmaven.ai
- **Sales**: sales@faultmaven.ai

---

**FaultMaven Enterprise** - Making troubleshooting faster, smarter, and more collaborative at scale.
