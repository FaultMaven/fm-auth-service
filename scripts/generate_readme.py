#!/usr/bin/env python3
"""Auto-generate README.md from OpenAPI specifications.

This script reads BOTH OpenAPI specs (main and enterprise) generated from FastAPI
and creates a comprehensive README with endpoint documentation for both apps.
"""

import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Set, Any


def load_openapi_spec(filename: str) -> Dict[str, Any]:
    """Load OpenAPI spec from docs/api/"""
    spec_path = Path(__file__).parent.parent / "docs" / "api" / filename

    if not spec_path.exists():
        raise FileNotFoundError(
            f"OpenAPI spec not found at {spec_path}. "
            "Run the workflow to generate it first."
        )

    with open(spec_path, 'r') as f:
        return json.load(f)


def generate_endpoint_table(spec: Dict[str, Any], app_name: str = "") -> str:
    """Generate markdown table of endpoints"""
    endpoints = []

    for path, methods in spec.get('paths', {}).items():
        for method, details in methods.items():
            if method.lower() in ['get', 'post', 'put', 'delete', 'patch']:
                # Extract summary or use path as fallback
                summary = details.get('summary', path)

                endpoints.append({
                    'method': method.upper(),
                    'path': path,
                    'summary': summary
                })

    # Sort endpoints: health first, then by path
    def sort_key(e):
        if e['path'] == '/health' or e['path'] == '/':
            return (0, e['path'])
        return (1, e['path'])

    endpoints.sort(key=sort_key)

    # Build markdown table
    table = "| Method | Endpoint | Description |\n"
    table += "|--------|----------|-------------|\n"

    for endpoint in endpoints:
        table += f"| {endpoint['method']} | `{endpoint['path']}` | {endpoint['summary']} |\n"

    return table


def count_endpoints(spec: Dict[str, Any]) -> int:
    """Count total number of endpoints"""
    count = 0
    for path, methods in spec.get('paths', {}).items():
        for method in methods.keys():
            if method.lower() in ['get', 'post', 'put', 'delete', 'patch']:
                count += 1
    return count


def main():
    """Generate README.md from OpenAPI specifications"""
    print("🚀 Generating README.md from OpenAPI specifications...")

    # Load both specs
    main_spec = load_openapi_spec("openapi-main.json")
    enterprise_spec = load_openapi_spec("openapi-enterprise.json")

    # Extract metadata from main spec
    main_info = main_spec.get('info', {})
    main_title = main_info.get('title', 'FaultMaven Auth Service')
    main_version = main_info.get('version', '1.0.0')
    main_description = main_info.get('description', 'Authentication service')

    # Extract metadata from enterprise spec
    enterprise_info = enterprise_spec.get('info', {})
    enterprise_title = enterprise_info.get('title', 'FaultMaven Auth Service - Enterprise Edition')
    enterprise_version = enterprise_info.get('version', '1.0.0')

    # Generate sections
    main_endpoint_table = generate_endpoint_table(main_spec, "Main")
    enterprise_endpoint_table = generate_endpoint_table(enterprise_spec, "Enterprise")

    main_endpoints = count_endpoints(main_spec)
    enterprise_endpoints = count_endpoints(enterprise_spec)
    total_endpoints = main_endpoints + enterprise_endpoints

    timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')

    # Build README content
    readme_content = f"""# {main_title}

> **🤖 This README is auto-generated** from code on every commit.
> Last updated: **{timestamp}** | Total endpoints: **{total_endpoints}** ({main_endpoints} main + {enterprise_endpoints} enterprise)

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](https://hub.docker.com/r/faultmaven/fm-auth-service)
[![Auto-Docs](https://img.shields.io/badge/docs-auto--generated-success.svg)](.github/workflows/generate-docs.yml)

## Overview

**{main_description}** - Part of the FaultMaven troubleshooting platform.

This service provides TWO FastAPI applications:
- **Main Application**: Standard authentication and user management ({main_endpoints} endpoints)
- **Enterprise Edition**: Multi-tenant SaaS with organizations, teams, and SSO ({enterprise_endpoints} endpoints)

**Key Features:**

**Main Application:**
- User registration and login
- JWT token authentication
- Password reset flow
- User profile management
- Session management with Redis
- API key management for service-to-service auth

**Enterprise Edition:**
- Multi-tenant organization management
- Team-based access control
- SSO integration (SAML, OAuth2)
- Enterprise user provisioning
- Role-based permissions
- Organization-level settings

## Quick Start

### Main Application (Standard Auth)

```bash
# Using Docker
docker run -p 8000:8000 -e REDIS_URL=redis://localhost:6379 \\
  faultmaven/fm-auth-service:latest

# Using uvicorn (development)
uvicorn auth_service.main:app --reload --port 8000
```

The service will be available at `http://localhost:8000`.

### Enterprise Edition

```bash
# Using Docker
docker run -p 8001:8001 -e DATABASE_URL=postgresql://... \\
  faultmaven/fm-auth-service:enterprise

# Using uvicorn (development)
uvicorn enterprise.main:app --reload --port 8001
```

The enterprise service will be available at `http://localhost:8001/enterprise/docs`.

### Development Setup

```bash
# Clone repository
git clone https://github.com/FaultMaven/fm-auth-service.git
cd fm-auth-service

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\\Scripts\\activate

# Install dependencies
pip install -e .

# Run main application
uvicorn auth_service.main:app --reload --port 8000

# Run enterprise application (in another terminal)
uvicorn enterprise.main:app --reload --port 8001
```

## API Endpoints

### Main Application ({main_endpoints} endpoints)

{main_endpoint_table}

**OpenAPI Documentation**:
- Interactive docs: `http://localhost:8000/docs`
- Spec: [docs/api/openapi-main.json](docs/api/openapi-main.json)

### Enterprise Edition ({enterprise_endpoints} endpoints)

{enterprise_endpoint_table}

**OpenAPI Documentation**:
- Interactive docs: `http://localhost:8001/enterprise/docs`
- Spec: [docs/api/openapi-enterprise.json](docs/api/openapi-enterprise.json)

## Configuration

### Main Application

Configuration via environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `SERVICE_NAME` | Service identifier | `fm-auth-service` |
| `ENVIRONMENT` | Deployment environment | `development` |
| `PORT` | Service port | `8000` |
| `REDIS_URL` | Redis connection string | `redis://localhost:6379` |
| `JWT_SECRET_KEY` | Secret key for JWT tokens | (required) |
| `JWT_ALGORITHM` | JWT signing algorithm | `HS256` |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | Token expiration time | `30` |
| `CORS_ORIGINS` | Allowed CORS origins (comma-separated) | `*` |
| `LOG_LEVEL` | Logging level | `INFO` |

Example `.env` file:

```env
ENVIRONMENT=production
PORT=8000
REDIS_URL=redis://redis:6379
JWT_SECRET_KEY=your-secret-key-here
ACCESS_TOKEN_EXPIRE_MINUTES=30
LOG_LEVEL=INFO
CORS_ORIGINS=https://app.faultmaven.com
```

### Enterprise Edition

Additional configuration for enterprise features:

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | (required) |
| `SAML_ENTITY_ID` | SAML entity identifier | (optional) |
| `OAUTH2_CLIENT_ID` | OAuth2 client ID | (optional) |
| `OAUTH2_CLIENT_SECRET` | OAuth2 client secret | (optional) |

## Authentication

### Main Application

**JWT Authentication**: Standard Bearer token authentication

```bash
# Login to get access token
curl -X POST http://localhost:8000/api/v1/auth/login \\
  -H "Content-Type: application/json" \\
  -d '{{"email": "user@example.com", "password": "password"}}'

# Use token in subsequent requests
curl http://localhost:8000/api/v1/auth/me \\
  -H "Authorization: Bearer <access_token>"
```

### Enterprise Edition

**Multi-tenant JWT**: Tokens include organization and team context

```bash
# Login to enterprise
curl -X POST http://localhost:8001/api/v1/enterprise/auth/login \\
  -H "Content-Type: application/json" \\
  -d '{{"email": "user@company.com", "password": "password"}}'

# Token includes: user_id, org_id, team_ids, roles
```

## Architecture

```
┌─────────────────────────────────┐
│  Client Applications            │
│  (Web, Mobile, Browser Ext)     │
└────────┬────────────────────────┘
         │
         ↓
┌─────────────────────────────────┐
│  FaultMaven API Gateway         │  Routes to appropriate auth app
│  (Port 8000)                    │  Main vs Enterprise
└────────┬────────────────────────┘
         │
    ┌────┴────┐
    ↓         ↓
┌──────┐  ┌──────────┐
│ Main │  │Enterprise│
│ Auth │  │  Auth    │
│(8000)│  │  (8001)  │
└──┬───┘  └────┬─────┘
   │           │
   ↓           ↓
┌─────┐   ┌──────────┐
│Redis│   │PostgreSQL│
└─────┘   └──────────┘
```

**Related Services:**
- fm-session-service (8001) - Investigation sessions
- fm-case-service (8003) - Case management
- fm-knowledge-service (8002) - Knowledge base

## Testing

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run all tests
pytest

# Run with coverage report
pytest --cov=auth_service --cov=enterprise --cov-report=html --cov-report=term

# Run specific test file
pytest tests/test_auth.py -v

# Run with debug output
pytest -vv -s
```

**Test Coverage Goals:**
- Unit tests: Core business logic
- Integration tests: Database and Redis operations
- API tests: Endpoint behavior and validation
- Target coverage: >80%

## Development Workflow

```bash
# Format code with black
black src/ enterprise/ tests/

# Lint with flake8
flake8 src/ enterprise/ tests/

# Type check with mypy
mypy src/ enterprise/

# Run all quality checks
black src/ enterprise/ tests/ && flake8 src/ enterprise/ tests/ && mypy src/ enterprise/ && pytest
```

## Related Projects

- [faultmaven](https://github.com/FaultMaven/faultmaven) - Main backend with API Gateway
- [faultmaven-copilot](https://github.com/FaultMaven/faultmaven-copilot) - Browser extension UI
- [faultmaven-deploy](https://github.com/FaultMaven/faultmaven-deploy) - Docker Compose deployments
- [fm-session-service](https://github.com/FaultMaven/fm-session-service) - Session management
- [fm-case-service](https://github.com/FaultMaven/fm-case-service) - Case management
- [fm-knowledge-service](https://github.com/FaultMaven/fm-knowledge-service) - Knowledge base

## CI/CD

This repository uses **GitHub Actions** for automated documentation generation:

**Trigger**: Every push to `main` or `develop` branches

**Process**:
1. Generate OpenAPI specs for BOTH applications (main + enterprise)
2. Validate documentation completeness (min 100 char descriptions)
3. Auto-generate this README from code
4. Create PR with documentation updates (if changes detected)

See [.github/workflows/generate-docs.yml](.github/workflows/generate-docs.yml) for implementation details.

**Documentation Guarantee**: This README is always in sync with the actual code. Any endpoint changes automatically trigger documentation updates.

## License

Apache 2.0 - See [LICENSE](LICENSE) for details.

## Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests and quality checks (`pytest && black . && flake8`)
5. Commit with clear messages (`git commit -m 'feat: Add amazing feature'`)
6. Push to your fork (`git push origin feature/amazing-feature`)
7. Open a Pull Request

**Code Style**: Black formatting, flake8 linting, mypy type checking
**Commit Convention**: Conventional Commits (feat/fix/docs/refactor/test/chore)

---

**📊 Documentation Statistics**
- Main application: {main_endpoints} endpoints
- Enterprise edition: {enterprise_endpoints} endpoints
- Total endpoints: {total_endpoints}
- Last generated: {timestamp}
- OpenAPI spec versions: Main v{main_version}, Enterprise v{enterprise_version}
- Generator: scripts/generate_readme.py
- CI/CD: GitHub Actions

*This README is automatically updated on every commit to ensure zero documentation drift.*
"""

    # Write README
    readme_path = Path(__file__).parent.parent / "README.md"
    with open(readme_path, 'w', encoding='utf-8') as f:
        f.write(readme_content)

    print(f"✅ README.md generated successfully")
    print(f"   Location: {readme_path}")
    print(f"   Main endpoints: {main_endpoints}")
    print(f"   Enterprise endpoints: {enterprise_endpoints}")
    print(f"   Total endpoints: {total_endpoints}")
    print(f"   Timestamp: {timestamp}")


if __name__ == "__main__":
    main()
