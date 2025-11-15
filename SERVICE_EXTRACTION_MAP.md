# Auth Service Extraction Map

## Source Files (from FaultMaven monolith)

| Monolith File | Destination | Action |
|---------------|-------------|--------|
| faultmaven/api/v1/routes/auth.py | src/auth_service/api/routes/auth.py | Extract authentication endpoints |
| faultmaven/infrastructure/auth/token_manager.py | src/auth_service/infrastructure/auth/token_manager.py | Extract JWT management |
| faultmaven/infrastructure/auth/user_store.py | src/auth_service/infrastructure/auth/user_store.py | Extract user storage |
| faultmaven/infrastructure/persistence/user_repository.py | src/auth_service/infrastructure/persistence/user_repository.py | Extract user data access |
| faultmaven/models/auth.py | src/auth_service/domain/models/auth.py | Extract auth models |
| faultmaven/models/api_auth.py | src/auth_service/domain/models/api_auth.py | Extract API auth models |

## Database Tables (exclusive ownership)

| Table Name | Source Schema | Action |
|------------|---------------|--------|
| users | 001_initial_hybrid_schema.sql | MIGRATE to fm_auth database |
| organizations | 001_initial_hybrid_schema.sql | MIGRATE to fm_auth database |
| organization_members | 001_initial_hybrid_schema.sql | MIGRATE to fm_auth database |
| teams | 001_initial_hybrid_schema.sql | MIGRATE to fm_auth database |
| team_members | 001_initial_hybrid_schema.sql | MIGRATE to fm_auth database |
| roles | 001_initial_hybrid_schema.sql | MIGRATE to fm_auth database |
| permissions | 001_initial_hybrid_schema.sql | MIGRATE to fm_auth database |
| role_permissions | 001_initial_hybrid_schema.sql | MIGRATE to fm_auth database |
| user_audit_log | 001_initial_hybrid_schema.sql | MIGRATE to fm_auth database |

## Events Published

| Event Name | AsyncAPI Schema | Trigger |
|------------|-----------------|---------|
| auth.user.created.v1 | contracts/asyncapi/auth-events.yaml | POST /v1/auth/register |
| auth.user.updated.v1 | contracts/asyncapi/auth-events.yaml | PUT /v1/auth/me |
| auth.user.deleted.v1 | contracts/asyncapi/auth-events.yaml | DELETE /v1/users/{id} |
| auth.organization.created.v1 | contracts/asyncapi/auth-events.yaml | POST /v1/organizations |
| auth.team.created.v1 | contracts/asyncapi/auth-events.yaml | POST /v1/teams |
| auth.role.assigned.v1 | contracts/asyncapi/auth-events.yaml | POST /v1/organizations/{id}/members |

## Events Consumed

| Event Name | Source Service | Action |
|------------|----------------|--------|
| None | N/A | Auth service is foundational |

## API Dependencies

| Dependency | Purpose | Fallback Strategy |
|------------|---------|-------------------|
| None | Auth is foundational service | N/A |

## Migration Checklist

- [ ] Extract domain models (User, Organization, Team, Role, Permission)
- [ ] Extract business logic (authentication, authorization, RBAC)
- [ ] Extract API routes (login, register, user/org/team management)
- [ ] Extract repository (PostgreSQL data access)
- [ ] Create database migration scripts (001_initial_schema.sql)
- [ ] Implement event publishing (outbox pattern)
- [ ] Add Redis for token blacklist and caching
- [ ] Write unit tests (80%+ coverage)
- [ ] Write integration tests (DB + Redis)
- [ ] Write contract tests (provider verification)
