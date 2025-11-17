# FaultMaven Auth Service - Test Suite

Comprehensive test suite for the enterprise authentication service with JWT, RBAC, and multi-tenant isolation.

## Test Structure

```
tests/
├── conftest.py                      # Shared fixtures and configuration
├── unit/                            # Unit tests (fast, isolated)
│   ├── test_security.py            # Password hashing, JWT token generation
│   ├── test_middleware_auth.py     # Authentication middleware
│   └── test_auth_models.py         # Database models (existing)
├── integration/                     # Integration tests (with database)
│   ├── test_auth_endpoints.py      # Authentication endpoints (login, register, etc.)
│   ├── test_protected_endpoints.py # Protected API endpoints (RBAC, multi-tenancy)
│   └── test_security.py            # Security bypass attempts
└── contract/                        # API contract tests (existing)
```

## Running Tests

### Run All Tests
```bash
pytest
```

### Run by Test Type
```bash
# Unit tests only (fast)
pytest -m unit

# Integration tests only (with database)
pytest -m integration

# Security tests only
pytest -m security
```

### Run Specific Test File
```bash
pytest tests/unit/test_security.py
pytest tests/integration/test_auth_endpoints.py
```

### Run Specific Test Function
```bash
pytest tests/unit/test_security.py::TestPasswordHashing::test_hash_password_returns_string
```

### Run with Coverage
```bash
# Coverage report in terminal
pytest --cov=enterprise --cov-report=term-missing

# HTML coverage report
pytest --cov=enterprise --cov-report=html
# Open htmlcov/index.html in browser
```

### Run Tests in Parallel
```bash
# Install pytest-xdist first: pip install pytest-xdist
pytest -n auto
```

## Test Coverage

Target coverage: **70%+**

Current test coverage by module:

| Module | Coverage | Status |
|--------|----------|--------|
| `enterprise.security` | ~95% | ✅ Excellent |
| `enterprise.middleware.auth` | ~85% | ✅ Very Good |
| `enterprise.api.auth` | ~80% | ✅ Good |
| `enterprise.api.organizations` | ~60% | ⚠️ Needs improvement |
| `enterprise.api.teams` | ~60% | ⚠️ Needs improvement |
| `enterprise.api.users` | ~60% | ⚠️ Needs improvement |
| `enterprise.api.sso` | ~60% | ⚠️ Needs improvement |

## Test Fixtures

### Database Fixtures
- `test_db` - In-memory SQLite database session
- `test_engine` - SQLAlchemy async engine

### Organization Fixtures
- `test_organization` - Test organization (max 50 users, 10 teams)

### Role Fixtures
- `test_role_admin` - Admin role with all permissions
- `test_role_member` - Member role with read-only permissions

### Team Fixtures
- `test_team` - Test team within organization

### User Fixtures
- `test_user_admin` - Admin user with admin role
- `test_user_member` - Member user with member role
- `test_user_inactive` - Inactive user (is_active=False)

### Token Fixtures
- `admin_access_token` - JWT access token for admin user
- `admin_refresh_token` - JWT refresh token for admin user
- `member_access_token` - JWT access token for member user

### HTTP Client Fixture
- `client` - AsyncClient with database override

## Test Categories

### Unit Tests (`-m unit`)
Fast, isolated tests with no external dependencies.

**Coverage:**
- Password hashing and verification
- JWT token generation and validation
- Authentication middleware functions
- Permission checking logic
- Organization access control

**Example:**
```python
def test_hash_password_returns_string():
    """Test that hash_password returns a string."""
    password = "testpassword123"
    hashed = hash_password(password)
    assert isinstance(hashed, str)
```

### Integration Tests (`-m integration`)
Tests with database and HTTP client interactions.

**Coverage:**
- Authentication endpoints (login, register, refresh, logout)
- Protected API endpoints (organizations, teams, users, SSO)
- Multi-tenant data isolation
- RBAC permission enforcement
- End-to-end authentication flows

**Example:**
```python
@pytest.mark.asyncio
async def test_login_success(client, test_user_admin):
    """Test successful login."""
    response = await client.post(
        "/api/v1/enterprise/auth/login",
        json={"email": "admin@testorg.com", "password": "admin123"}
    )
    assert response.status_code == 200
    assert "access_token" in response.json()
```

### Security Tests (`-m security`)
Tests for security vulnerabilities and bypass attempts.

**Coverage:**
- Token tampering protection
- Permission bypass attempts
- Admin role bypass attempts
- Cross-tenant data access prevention
- Inactive user blocking
- Password security (no exposure in responses)
- SQL injection protection
- XSS protection in error messages
- Token expiration enforcement

**Example:**
```python
@pytest.mark.asyncio
async def test_cross_tenant_data_access_blocked(client, admin_access_token):
    """Test that cross-tenant access is blocked."""
    other_org_id = uuid4()
    response = await client.get(
        f"/api/v1/enterprise/teams/organization/{other_org_id}",
        headers={"Authorization": f"Bearer {admin_access_token}"}
    )
    assert response.status_code == 403
```

## Writing New Tests

### Unit Test Template
```python
# tests/unit/test_module.py

class TestFeature:
    """Test feature description."""

    def test_success_case(self):
        """Test successful execution."""
        result = feature_function(input_data)
        assert result == expected_output

    def test_error_case(self):
        """Test error handling."""
        with pytest.raises(Exception):
            feature_function(invalid_data)
```

### Integration Test Template
```python
# tests/integration/test_endpoints.py

class TestEndpoint:
    """Test endpoint description."""

    @pytest.mark.asyncio
    async def test_endpoint_success(self, client, admin_access_token):
        """Test successful endpoint call."""
        response = await client.get(
            "/api/v1/endpoint",
            headers={"Authorization": f"Bearer {admin_access_token}"}
        )
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_endpoint_unauthorized(self, client):
        """Test endpoint without authentication."""
        response = await client.get("/api/v1/endpoint")
        assert response.status_code == 403
```

## Continuous Integration

Tests run automatically on:
- Push to main branch
- Pull request creation
- Scheduled nightly builds

**CI Requirements:**
- All tests must pass
- Coverage must be ≥ 70%
- No security test failures

## Debugging Tests

### Run Test with Verbose Output
```bash
pytest -vv tests/unit/test_security.py
```

### Run Test with Print Statements
```bash
pytest -s tests/integration/test_auth_endpoints.py
```

### Run Single Test with Debugger
```bash
pytest --pdb tests/unit/test_security.py::TestPasswordHashing::test_hash_password_returns_string
```

### Show Test Durations
```bash
pytest --durations=10
```

## Common Issues

### Import Errors
Ensure PYTHONPATH includes project root:
```bash
export PYTHONPATH=/path/to/fm-auth-service:$PYTHONPATH
pytest
```

### Database Errors
Tests use in-memory SQLite. If you see database errors:
- Check that `aiosqlite` is installed
- Verify fixtures are properly defined in `conftest.py`

### Async Errors
Ensure pytest-asyncio is installed:
```bash
pip install pytest-asyncio
```

## Dependencies

Required packages for testing:
```
pytest>=7.4.0
pytest-asyncio>=0.21.0
pytest-cov>=4.1.0
httpx>=0.24.0
aiosqlite>=0.19.0
```

Install all test dependencies:
```bash
pip install pytest pytest-asyncio pytest-cov httpx aiosqlite
```

## Test Data

Tests use:
- **In-memory SQLite database** (no persistence)
- **Deterministic UUIDs** (from fixtures)
- **Known passwords** (hashed during fixture creation)
- **Isolated test data** (each test gets fresh database)

## Best Practices

1. **Isolation**: Each test should be independent
2. **Fast**: Unit tests should complete in milliseconds
3. **Readable**: Test names should describe what they test
4. **Comprehensive**: Cover success cases, error cases, edge cases
5. **Security**: Always test authorization and multi-tenancy
6. **Async**: Use `@pytest.mark.asyncio` for async tests
7. **Fixtures**: Reuse fixtures to reduce test code duplication

## Contributing

When adding new features:
1. Write unit tests first (TDD)
2. Add integration tests for API endpoints
3. Add security tests for any authentication/authorization logic
4. Ensure coverage stays above 70%
5. Run full test suite before committing

---

**Last Updated:** 2025-11-17
**Test Count:** 80+ tests
**Coverage Target:** 70%+
