# FaultMaven Auth Service - Enterprise Edition Architecture

## Table of Contents

- [Overview](#overview)
- [Design Principles](#design-principles)
- [Technology Stack](#technology-stack)
- [Architecture Diagrams](#architecture-diagrams)
  - [1. System Context Diagram](#1-system-context-diagram)
  - [2. Component Architecture](#2-component-architecture)
  - [3. Database Schema](#3-database-schema)
  - [4. Authentication Flow](#4-authentication-flow)
  - [5. Multi-Tenant Isolation](#5-multi-tenant-isolation)
  - [6. RBAC Authorization](#6-rbac-authorization)
  - [7. Deployment Architecture](#7-deployment-architecture)
- [Security Architecture](#security-architecture)
- [Scalability & Performance](#scalability--performance)
- [Data Model Details](#data-model-details)
- [API Layer Design](#api-layer-design)
- [Future Enhancements](#future-enhancements)

---

## Overview

The FaultMaven Auth Service Enterprise Edition is a production-grade, multi-tenant SaaS authentication and authorization service. It provides enterprise features including:

- **Multi-tenant data isolation** at the organization level
- **JWT-based authentication** with access and refresh tokens
- **Role-Based Access Control (RBAC)** with fine-grained permissions
- **SSO integration** supporting SAML, OAuth 2.0, and OIDC
- **Comprehensive audit logging** for compliance
- **Team-based user organization** within tenants
- **Async-first architecture** for high performance

The service extends a PUBLIC base model from Docker Hub, adding enterprise capabilities while maintaining clean separation of concerns.

---

## Design Principles

### 1. Multi-Tenancy First
Every data model includes organization-level isolation. All queries are automatically scoped to the authenticated user's organization, preventing cross-tenant data leakage.

### 2. Security by Default
- All passwords are hashed using bcrypt
- JWT tokens use HS256 algorithm with configurable expiration
- Middleware enforces authentication and authorization at every layer
- Comprehensive audit logging tracks all security events

### 3. Async Performance
Built entirely on async/await patterns using:
- FastAPI for async HTTP handling
- SQLAlchemy async engine and sessions
- asyncpg for non-blocking PostgreSQL operations

### 4. Scalability Through Statelessness
- JWT tokens eliminate server-side session storage
- Redis used only for caching and optional token blacklisting
- Database connections pooled and reused efficiently
- Horizontal scaling supported out of the box

### 5. Extensibility
- Clean separation between routers, middleware, services, and data models
- Pluggable authentication providers (password, SAML, OAuth, OIDC)
- Custom role and permission definitions per organization
- JSONB fields for flexible metadata storage

---

## Technology Stack

### Core Framework
- **FastAPI 0.100+**: Modern async web framework with automatic OpenAPI documentation
- **Python 3.11+**: Latest Python features with improved performance
- **Pydantic 2.0+**: Data validation and serialization

### Database Layer
- **PostgreSQL 15+**: Primary data store with JSONB support
- **SQLAlchemy 2.0+**: Async ORM with modern typing
- **Asyncpg**: High-performance PostgreSQL driver
- **Alembic**: Database migrations (recommended for production)

### Authentication & Security
- **python-jose**: JWT token creation and validation
- **passlib + bcrypt**: Password hashing
- **python-multipart**: Form data parsing

### Caching & Sessions
- **Redis 7+**: Distributed caching and session storage
- **aioredis**: Async Redis client

### Development & Testing
- **Uvicorn**: ASGI server with hot-reload
- **pytest**: Testing framework
- **httpx**: Async HTTP client for testing

---

## Architecture Diagrams

### 1. System Context Diagram

This diagram shows the high-level view of the Auth Service and its interactions with external actors and systems.

```mermaid
graph TB
    subgraph External Actors
        User[User/Client Application]
        Admin[System Administrator]
        ExtIdP[External Identity Provider<br/>SAML/OAuth/OIDC]
    end

    subgraph FaultMaven Auth Service
        API[FastAPI Application]
    end

    subgraph External Systems
        DB[(PostgreSQL<br/>Primary Database)]
        Redis[(Redis<br/>Cache & Sessions)]
        Email[Email Service<br/>SMTP]
    end

    User -->|HTTP/JSON API| API
    Admin -->|Admin API Calls| API
    ExtIdP -->|SSO Callback| API

    API -->|SSO Redirect| ExtIdP
    API -->|SQL Queries| DB
    API -->|Cache Operations| Redis
    API -->|Send Verification| Email

    style API fill:#4CAF50,stroke:#2E7D32,color:#fff
    style DB fill:#2196F3,stroke:#1565C0,color:#fff
    style Redis fill:#F44336,stroke:#C62828,color:#fff
    style Email fill:#FF9800,stroke:#E65100,color:#fff
```

**Key Elements:**

- **External Actors**: End users, administrators, and external identity providers
- **Auth Service**: Central FastAPI application handling all authentication/authorization
- **External Systems**: PostgreSQL for persistence, Redis for caching, SMTP for notifications

**Design Decisions:**

- RESTful HTTP/JSON API for broad client compatibility
- Stateless JWT tokens reduce dependency on Redis
- External IdP integration enables enterprise SSO requirements
- Email service decoupled for flexible provider choice

**Security Considerations:**

- All external communications over HTTPS in production
- JWT tokens contain minimal PII (user_id, email, org_id)
- Redis connections secured with authentication
- Database credentials stored in environment variables

---

### 2. Component Architecture

This diagram illustrates the internal layered architecture of the Auth Service.

```mermaid
graph TB
    subgraph API Layer
        AuthRouter[Auth Router<br/>Login/Register/Logout]
        OrgRouter[Organizations Router]
        TeamRouter[Teams Router]
        UserRouter[Users Router]
        SSORouter[SSO Router]
    end

    subgraph Middleware Layer
        CORS[CORS Middleware]
        JWTAuth[JWT Authentication<br/>get_current_user]
        RBAC[RBAC Authorization<br/>require_permissions]
        OrgIsolation[Organization Isolation<br/>require_org_access]
    end

    subgraph Service Layer
        AuthService[Authentication Service<br/>Password verification<br/>Token generation]
        UserService[User Management Service]
        RoleService[Role & Permission Service]
        AuditService[Audit Logging Service]
    end

    subgraph Data Access Layer
        Models[SQLAlchemy Models<br/>Organization, Team, User<br/>Role, Permission, AuditLog]
        DB[Database Session<br/>get_db dependency]
    end

    subgraph Infrastructure Layer
        PostgreSQL[(PostgreSQL)]
        RedisCache[(Redis)]
    end

    AuthRouter --> JWTAuth
    OrgRouter --> JWTAuth
    TeamRouter --> JWTAuth
    UserRouter --> JWTAuth
    SSORouter --> JWTAuth

    JWTAuth --> RBAC
    RBAC --> OrgIsolation

    OrgIsolation --> AuthService
    OrgIsolation --> UserService
    OrgIsolation --> RoleService
    OrgIsolation --> AuditService

    AuthService --> Models
    UserService --> Models
    RoleService --> Models
    AuditService --> Models

    Models --> DB
    DB --> PostgreSQL

    AuthService --> RedisCache
    RoleService --> RedisCache

    style AuthRouter fill:#4CAF50,stroke:#2E7D32,color:#fff
    style JWTAuth fill:#FF9800,stroke:#E65100,color:#fff
    style AuthService fill:#2196F3,stroke:#1565C0,color:#fff
    style Models fill:#9C27B0,stroke:#6A1B9A,color:#fff
    style PostgreSQL fill:#2196F3,stroke:#1565C0,color:#fff
    style RedisCache fill:#F44336,stroke:#C62828,color:#fff
```

**Key Elements:**

- **API Layer**: FastAPI routers handling HTTP requests and responses
- **Middleware Layer**: Cross-cutting concerns (auth, authz, tenant isolation)
- **Service Layer**: Business logic and orchestration
- **Data Access Layer**: SQLAlchemy models and database sessions
- **Infrastructure Layer**: External data stores

**Component Relationships:**

- Routers use middleware dependencies for authentication/authorization
- Middleware extracts user context and validates access
- Services implement business logic using data models
- Models map to database tables via SQLAlchemy ORM

**Design Decisions:**

- Clear separation of concerns enables independent testing
- Middleware pattern provides declarative security
- Service layer abstracts business logic from HTTP concerns
- Async all the way through the stack for maximum performance

**Scalability Notes:**

- Routers are stateless and can scale horizontally
- Services can be extracted to separate microservices if needed
- Database connection pooling handles concurrent requests
- Redis caching reduces database load for repeated queries

---

### 3. Database Schema

This diagram shows the entity relationships and data model structure.

```mermaid
erDiagram
    Organization ||--o{ Team : contains
    Organization ||--o{ EnterpriseUser : employs
    Organization ||--o{ SSOConfiguration : configures
    Organization ||--o{ Role : defines
    Organization ||--o{ AuditLog : tracks

    Team ||--o{ EnterpriseUser : includes

    EnterpriseUser ||--o{ UserRole : has
    EnterpriseUser ||--o{ AuditLog : performs

    Role ||--o{ UserRole : assigned_to
    Role ||--o{ Permission : grants

    Organization {
        uuid id PK
        string name
        string slug UK
        string plan
        boolean is_active
        int max_users
        int max_teams
        string contact_email
        string contact_name
        timestamp created_at
        timestamp updated_at
        timestamp deleted_at
    }

    Team {
        uuid id PK
        uuid organization_id FK
        string name
        string slug
        text description
        timestamp created_at
        timestamp updated_at
        timestamp deleted_at
    }

    EnterpriseUser {
        uuid id PK
        uuid organization_id FK
        uuid team_id FK
        string email UK
        string hashed_password
        string full_name
        boolean is_active
        boolean is_verified
        string sso_provider
        string sso_subject_id
        timestamp last_login_at
        timestamp password_changed_at
        timestamp created_at
        timestamp updated_at
        timestamp deleted_at
    }

    Role {
        uuid id PK
        uuid organization_id FK
        string name
        string slug
        text description
        boolean is_system_role
        timestamp created_at
        timestamp updated_at
    }

    Permission {
        uuid id PK
        uuid role_id FK
        string resource
        string action
        timestamp created_at
    }

    UserRole {
        uuid id PK
        uuid user_id FK
        uuid role_id FK
        timestamp assigned_at
        uuid assigned_by
    }

    SSOConfiguration {
        uuid id PK
        uuid organization_id FK
        string provider_type
        string provider_name
        boolean is_enabled
        string saml_entity_id
        string saml_sso_url
        string oauth_client_id
        jsonb attribute_mapping
        boolean auto_create_users
        uuid default_role_id
        timestamp created_at
        timestamp updated_at
    }

    AuditLog {
        uuid id PK
        uuid organization_id FK
        uuid user_id FK
        string event_type
        string action
        string resource
        string resource_id
        string ip_address
        string user_agent
        string request_id
        string status
        text error_message
        jsonb context_data
        timestamp created_at
    }
```

**Key Relationships:**

1. **Organization (1:N) → Team**: Organizations contain multiple teams
2. **Organization (1:N) → User**: Organizations employ multiple users
3. **Team (1:N) → User**: Teams include multiple users (optional assignment)
4. **User (M:N) → Role**: Users have multiple roles via UserRole junction
5. **Role (1:N) → Permission**: Roles grant multiple permissions
6. **Organization (1:N) → SSO**: Organizations configure multiple SSO providers

**Cardinality:**

- Every User MUST belong to exactly one Organization (1:1 mandatory)
- Every User MAY belong to at most one Team (1:0..1 optional)
- Every Role MAY belong to one Organization OR be a system role (1:0..1)
- Every Permission MUST belong to exactly one Role (N:1 mandatory)

**Design Decisions:**

- UUIDs for all primary keys ensure global uniqueness
- Soft deletes (deleted_at) allow data recovery and audit history
- JSONB fields (attribute_mapping, context_data) provide schema flexibility
- Composite unique constraints prevent duplicate role assignments
- Timestamps track creation/modification for compliance

**Security Considerations:**

- organization_id indexed on all tenant tables for query performance
- Unique constraint on email prevents account enumeration attacks
- hashed_password nullable to support SSO-only users
- Audit logs immutable (no update/delete operations)

---

### 4. Authentication Flow

This sequence diagram shows the end-to-end authentication process.

```mermaid
sequenceDiagram
    actor User
    participant Client as Client Application
    participant API as Auth API
    participant Middleware as JWT Middleware
    participant DB as PostgreSQL
    participant Redis as Redis Cache

    Note over User,Redis: Initial Login Flow

    User->>Client: Enter email & password
    Client->>API: POST /api/v1/enterprise/auth/login
    activate API

    API->>DB: SELECT user WHERE email = ?
    activate DB
    DB-->>API: User record
    deactivate DB

    API->>API: verify_password(input, hashed)

    alt Password Valid
        API->>API: create_access_token(user_id, org_id, email)
        API->>API: create_refresh_token(user_id)
        API->>Redis: Cache user session (optional)
        API-->>Client: 200 OK {access_token, refresh_token}
        Client->>Client: Store tokens in local storage
        Client-->>User: Login successful
    else Password Invalid
        API-->>Client: 401 Unauthorized
        Client-->>User: Invalid credentials
    end

    deactivate API

    Note over User,Redis: Authenticated Request Flow

    User->>Client: Access protected resource
    Client->>API: GET /api/v1/enterprise/orgs/{id}<br/>Authorization: Bearer {access_token}
    activate API

    API->>Middleware: Validate JWT token
    activate Middleware

    Middleware->>Middleware: jwt.decode(token, secret, HS256)

    alt Token Valid
        Middleware->>DB: SELECT user WHERE id = token.sub
        activate DB
        DB->>DB: JOIN roles, permissions
        DB-->>Middleware: User with roles & permissions
        deactivate DB

        Middleware->>Middleware: Check user.is_active
        Middleware-->>API: Current user object
        deactivate Middleware

        API->>API: Verify org_id matches path
        API->>DB: Execute business logic
        API-->>Client: 200 OK {resource data}
    else Token Invalid/Expired
        Middleware-->>API: Raise 401 Unauthorized
        deactivate Middleware
        API-->>Client: 401 Unauthorized
        Client->>Client: Clear tokens
        Client-->>User: Redirect to login
    end

    deactivate API

    Note over User,Redis: Token Refresh Flow

    Client->>API: POST /api/v1/enterprise/auth/refresh<br/>{refresh_token}
    activate API

    API->>API: verify_token(refresh_token)
    API->>DB: SELECT user WHERE id = token.sub
    DB-->>API: User record
    API->>API: create_access_token(user_id, org_id, email)
    API->>API: create_refresh_token(user_id)
    API-->>Client: 200 OK {new_access_token, new_refresh_token}
    Client->>Client: Update stored tokens

    deactivate API
```

**Key Elements:**

1. **Login Flow**: Password verification → Token generation → Client storage
2. **Authenticated Request**: Token validation → User lookup → Permission check → Business logic
3. **Token Refresh**: Old refresh token → New access + refresh tokens

**Design Decisions:**

- Access tokens short-lived (15-60 minutes) limit exposure window
- Refresh tokens longer-lived (7-30 days) reduce login friction
- JWT tokens stateless for horizontal scalability
- User roles/permissions eagerly loaded with user for single query

**Security Considerations:**

- Passwords never returned in API responses
- Tokens transmitted only over HTTPS
- JWT secret stored securely in environment variables
- Failed login attempts could trigger rate limiting (future enhancement)
- Token expiration enforced at middleware layer

**Performance Optimizations:**

- Redis caching for user sessions reduces database queries
- Eager loading of relationships (selectinload) prevents N+1 queries
- JWT validation happens in-memory before database access
- Connection pooling reuses database connections

---

### 5. Multi-Tenant Isolation

This diagram illustrates how data isolation is enforced at the organization level.

```mermaid
graph TB
    subgraph Request Flow
        Request[HTTP Request<br/>Authorization: Bearer token]
    end

    subgraph JWT Token Payload
        Token[JWT Payload<br/>sub: user_id<br/>org_id: organization_id<br/>email: user@example.com]
    end

    subgraph Middleware Validation
        DecodeJWT[Decode JWT Token<br/>Extract user_id]
        FetchUser[Fetch User from DB<br/>SELECT * FROM users WHERE id = user_id]
        UserContext[User Context<br/>user.organization_id = ABC123<br/>user.roles = Admin, Member<br/>user.permissions = users:read, users:write]
    end

    subgraph Tenant Isolation Enforcement
        PathOrgID[Extract organization_id<br/>from path parameter]
        CompareOrg{Does user.organization_id<br/>match path org_id?}
        ScopeQuery[Scope Database Query<br/>WHERE organization_id = ABC123]
    end

    subgraph Database Layer
        OrgA[(Organization ABC123<br/>- Teams 1,2,3<br/>- Users A,B,C<br/>- Data 1,2,3)]
        OrgB[(Organization XYZ789<br/>- Teams 4,5,6<br/>- Users D,E,F<br/>- Data 4,5,6)]
    end

    Request --> Token
    Token --> DecodeJWT
    DecodeJWT --> FetchUser
    FetchUser --> UserContext
    UserContext --> PathOrgID
    PathOrgID --> CompareOrg

    CompareOrg -->|Yes - Access Granted| ScopeQuery
    CompareOrg -->|No - Access Denied| Forbidden[403 Forbidden]

    ScopeQuery --> OrgA
    ScopeQuery -.X.- OrgB

    style Request fill:#4CAF50,stroke:#2E7D32,color:#fff
    style UserContext fill:#2196F3,stroke:#1565C0,color:#fff
    style CompareOrg fill:#FF9800,stroke:#E65100,color:#fff
    style Forbidden fill:#F44336,stroke:#C62828,color:#fff
    style OrgA fill:#2196F3,stroke:#1565C0,color:#fff
    style OrgB fill:#9E9E9E,stroke:#616161,color:#fff
```

**Isolation Strategy:**

1. **JWT Token Binding**: User's organization_id embedded in token claims
2. **Path Parameter Validation**: URL organization_id must match token org_id
3. **Query Scoping**: All database queries automatically filtered by organization_id
4. **Relationship Traversal**: Foreign keys enforce referential integrity

**Implementation Details:**

```python
# OrganizationAccessChecker middleware
def __call__(
    self,
    organization_id: UUID,
    current_user: EnterpriseUser = Depends(get_current_active_user)
) -> EnterpriseUser:
    if current_user.organization_id != organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: You do not belong to this organization"
        )
    return current_user

# Example scoped query
stmt = select(Team).where(
    Team.organization_id == current_user.organization_id,
    Team.deleted_at.is_(None)
)
```

**Design Decisions:**

- Organization ID required in JWT payload for stateless validation
- Path parameter organization_id makes tenant context explicit
- Middleware enforcement prevents accidental cross-tenant queries
- Database foreign keys provide defense in depth

**Security Considerations:**

- No shared data between organizations
- Admin users cannot access other organizations
- System roles (if any) scoped to specific organizations
- Audit logs track all cross-organization access attempts

**Scalability Notes:**

- organization_id indexed on all tenant tables
- Query scoping happens at ORM level (no application filtering)
- Database partitioning possible on organization_id for very large scale
- Each organization's data can be migrated to separate databases

---

### 6. RBAC Authorization

This diagram shows how role-based access control determines permissions.

```mermaid
graph TB
    subgraph User Context
        User[Authenticated User<br/>user_id: 123<br/>organization_id: ABC123]
    end

    subgraph Role Assignment
        UserRoles[(UserRole Table<br/>user_id=123 → role_id=R1<br/>user_id=123 → role_id=R2)]
    end

    subgraph Roles
        Role1[Role: Admin<br/>role_id: R1<br/>name: Admin<br/>org_id: ABC123]
        Role2[Role: Member<br/>role_id: R2<br/>name: Member<br/>org_id: ABC123]
    end

    subgraph Permissions
        Perm1[users:create<br/>users:read<br/>users:update<br/>users:delete]
        Perm2[teams:read<br/>cases:read<br/>cases:write]
    end

    subgraph Permission Aggregation
        AllPerms[Aggregated Permissions<br/>users:create, users:read,<br/>users:update, users:delete,<br/>teams:read, cases:read, cases:write]
    end

    subgraph Endpoint Protection
        Endpoint[API Endpoint<br/>@require_permissions<br/>users:delete]
        Check{Does user have<br/>users:delete?}
    end

    User --> UserRoles
    UserRoles --> Role1
    UserRoles --> Role2
    Role1 --> Perm1
    Role2 --> Perm2
    Perm1 --> AllPerms
    Perm2 --> AllPerms
    AllPerms --> Endpoint
    Endpoint --> Check

    Check -->|Yes| Execute[Execute Endpoint Logic]
    Check -->|No| Deny[403 Forbidden<br/>Permission denied:<br/>users:delete required]

    style User fill:#4CAF50,stroke:#2E7D32,color:#fff
    style AllPerms fill:#2196F3,stroke:#1565C0,color:#fff
    style Check fill:#FF9800,stroke:#E65100,color:#fff
    style Execute fill:#4CAF50,stroke:#2E7D32,color:#fff
    style Deny fill:#F44336,stroke:#C62828,color:#fff
```

**Permission Model:**

- **Resource**: Entity type (users, teams, organizations, cases)
- **Action**: Operation (create, read, update, delete, admin)
- **Permission Name**: Formatted as `resource:action` (e.g., `users:delete`)

**Authorization Flow:**

1. User authenticated via JWT token
2. User's roles fetched from database (eager loaded)
3. Permissions aggregated from all assigned roles
4. Endpoint decorator specifies required permission(s)
5. Middleware checks if user has ALL required permissions
6. Request proceeds if authorized, else 403 Forbidden

**Implementation Example:**

```python
# Endpoint with permission requirement
@router.delete(
    "/users/{user_id}",
    dependencies=[Depends(require_permissions("users:delete"))]
)
async def delete_user(user_id: UUID):
    # Only users with "users:delete" permission reach here
    ...

# Permission checking logic
async def permission_checker(
    current_user: EnterpriseUser = Depends(get_current_active_user)
):
    user_permissions = set()
    for role in current_user.roles:
        for permission in role.permissions:
            user_permissions.add(permission.name)

    for required_permission in permission_names:
        if required_permission not in user_permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: {required_permission} required"
            )
    return current_user
```

**Design Decisions:**

- Users can have multiple roles for flexibility
- Permissions additive (union of all role permissions)
- System roles (Admin, Member, Viewer) predefined
- Custom roles can be created per organization
- Permission format (`resource:action`) enables fine-grained control

**Security Considerations:**

- Permissions checked on every protected endpoint
- No implicit admin bypass (must have explicit permission)
- Audit logs record all permission denials
- Role changes take effect on next token refresh

**Scalability Notes:**

- Permissions cached in user context (single query per request)
- Eager loading prevents N+1 query problems
- Permission checks happen in-memory (no database access)
- Redis caching possible for role/permission lookups

---

### 7. Deployment Architecture

This diagram shows the production deployment topology.

```mermaid
graph TB
    subgraph Internet
        Clients[Clients<br/>Web, Mobile, API]
    end

    subgraph Load Balancer
        LB[NGINX / AWS ALB<br/>SSL Termination<br/>TLS 1.3]
    end

    subgraph Application Tier
        App1[Auth Service Instance 1<br/>FastAPI + Uvicorn<br/>Async workers]
        App2[Auth Service Instance 2<br/>FastAPI + Uvicorn<br/>Async workers]
        App3[Auth Service Instance 3<br/>FastAPI + Uvicorn<br/>Async workers]
    end

    subgraph Database Tier
        PGPrimary[(PostgreSQL Primary<br/>Read/Write<br/>Streaming Replication)]
        PGReplica1[(PostgreSQL Replica 1<br/>Read-Only)]
        PGReplica2[(PostgreSQL Replica 2<br/>Read-Only)]
    end

    subgraph Cache Tier
        RedisMaster[(Redis Master<br/>Sessions & Cache)]
        RedisSentinel1[Redis Sentinel 1]
        RedisSentinel2[Redis Sentinel 2]
        RedisReplica[(Redis Replica<br/>Failover)]
    end

    subgraph Monitoring & Logging
        Prometheus[Prometheus<br/>Metrics Collection]
        Grafana[Grafana<br/>Dashboards]
        ELK[ELK Stack<br/>Log Aggregation]
    end

    subgraph External Services
        Email[Email Provider<br/>SendGrid/SES]
        SSO[External IdP<br/>Okta/Azure AD]
    end

    Clients -->|HTTPS| LB
    LB -->|HTTP/2| App1
    LB -->|HTTP/2| App2
    LB -->|HTTP/2| App3

    App1 -->|SQL Write| PGPrimary
    App2 -->|SQL Write| PGPrimary
    App3 -->|SQL Write| PGPrimary

    App1 -.->|SQL Read| PGReplica1
    App2 -.->|SQL Read| PGReplica1
    App3 -.->|SQL Read| PGReplica2

    PGPrimary -->|Replication| PGReplica1
    PGPrimary -->|Replication| PGReplica2

    App1 <-->|Redis Protocol| RedisMaster
    App2 <-->|Redis Protocol| RedisMaster
    App3 <-->|Redis Protocol| RedisMaster

    RedisMaster -->|Replication| RedisReplica
    RedisSentinel1 -.->|Monitor| RedisMaster
    RedisSentinel2 -.->|Monitor| RedisMaster
    RedisSentinel1 -.->|Monitor| RedisReplica
    RedisSentinel2 -.->|Monitor| RedisReplica

    App1 -.->|Metrics| Prometheus
    App2 -.->|Metrics| Prometheus
    App3 -.->|Metrics| Prometheus

    Prometheus --> Grafana

    App1 -.->|Logs| ELK
    App2 -.->|Logs| ELK
    App3 -.->|Logs| ELK

    App1 -.->|SMTP| Email
    App2 -.->|SAML/OAuth| SSO

    style Clients fill:#4CAF50,stroke:#2E7D32,color:#fff
    style LB fill:#FF9800,stroke:#E65100,color:#fff
    style App1 fill:#2196F3,stroke:#1565C0,color:#fff
    style App2 fill:#2196F3,stroke:#1565C0,color:#fff
    style App3 fill:#2196F3,stroke:#1565C0,color:#fff
    style PGPrimary fill:#9C27B0,stroke:#6A1B9A,color:#fff
    style RedisMaster fill:#F44336,stroke:#C62828,color:#fff
    style Prometheus fill:#FF5722,stroke:#D84315,color:#fff
```

**Deployment Topology:**

1. **Load Balancer Layer**: SSL termination, request distribution, health checks
2. **Application Tier**: Stateless FastAPI instances (3+ for HA)
3. **Database Tier**: PostgreSQL primary + read replicas
4. **Cache Tier**: Redis with Sentinel for automatic failover
5. **Monitoring**: Prometheus metrics + Grafana dashboards + ELK logs

**High Availability Features:**

- Multiple application instances behind load balancer
- PostgreSQL streaming replication for data redundancy
- Redis Sentinel for automatic master failover
- Health check endpoints for load balancer monitoring
- Graceful shutdown handling in application

**Network Boundaries:**

- **Public**: Load balancer only
- **Application**: FastAPI instances
- **Data**: PostgreSQL and Redis (private subnet)
- **Management**: Monitoring tools (restricted access)

**Deployment Configuration:**

```yaml
# Docker Compose / Kubernetes example
services:
  auth-service:
    image: faultmaven/auth-service:enterprise
    replicas: 3
    environment:
      - DATABASE_URL=postgresql+asyncpg://user:pass@postgres-primary:5432/authdb
      - REDIS_URL=redis://redis-master:6379/0
      - JWT_SECRET_KEY=${JWT_SECRET_KEY}
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8001/health"]
      interval: 30s
      timeout: 10s
      retries: 3
```

**Design Decisions:**

- Stateless application tier enables horizontal scaling
- Read replicas reduce load on primary database
- Redis Sentinel provides automatic failover without manual intervention
- Prometheus pull-based metrics avoid application coupling

**Security Considerations:**

- TLS 1.3 at load balancer for modern cipher suites
- Application tier in private subnet (no direct internet access)
- Database tier in isolated subnet with firewall rules
- Secrets managed via environment variables or secret managers (AWS Secrets Manager, HashiCorp Vault)
- Regular security updates applied to all components

**Scalability Notes:**

- Application tier scales horizontally (add more instances)
- Database scales via read replicas (read-heavy workloads)
- Connection pooling prevents database connection exhaustion
- Redis cluster mode available for cache scaling
- Global distribution possible via CDN + regional deployments

**Disaster Recovery:**

- PostgreSQL point-in-time recovery (PITR) with WAL archiving
- Daily automated backups to S3/GCS
- Cross-region replication for geographic redundancy
- RPO (Recovery Point Objective): < 5 minutes
- RTO (Recovery Time Objective): < 15 minutes

---

## Security Architecture

### Authentication Mechanisms

1. **Password-Based Authentication**
   - Bcrypt hashing with configurable work factor (default: 12 rounds)
   - Password complexity requirements enforced at API layer
   - Rate limiting on login attempts (future: Redis-based)
   - Account lockout after N failed attempts (future enhancement)

2. **SSO Integration**
   - SAML 2.0 for enterprise identity providers
   - OAuth 2.0 for social login providers
   - OIDC for modern OpenID Connect providers
   - Automatic user provisioning with role assignment
   - Attribute mapping for custom claims

3. **JWT Token Strategy**
   - Access tokens: Short-lived (15-60 minutes)
   - Refresh tokens: Long-lived (7-30 days)
   - HS256 algorithm (symmetric signing)
   - Token blacklisting via Redis for logout/revocation
   - Token rotation on refresh

### Authorization Model

- **RBAC Implementation**: Role-based with permission aggregation
- **Resource-Level Permissions**: Fine-grained control per resource type
- **Organization Scoping**: All permissions scoped to organization
- **Implicit Deny**: No access unless explicitly granted
- **Audit Trail**: All authorization decisions logged

### Data Protection

- **Encryption at Rest**: PostgreSQL Transparent Data Encryption (TDE)
- **Encryption in Transit**: TLS 1.3 for all external communications
- **Password Storage**: Bcrypt with per-password salt
- **Sensitive Data**: SSO secrets encrypted before storage
- **PII Handling**: Minimal PII in JWT tokens

### Compliance

- **Audit Logging**: Comprehensive event tracking
- **Data Retention**: Configurable per organization
- **Right to Deletion**: Soft delete with data purging
- **Access Logging**: All data access tracked with IP/user agent
- **SOC 2 Readiness**: Audit log immutability and retention

---

## Scalability & Performance

### Performance Targets

- **Authentication Latency**: < 100ms (p95)
- **Authorization Check**: < 10ms (p95)
- **API Response Time**: < 200ms (p95)
- **Throughput**: 10,000+ requests/second per instance
- **Database Connections**: 50-100 per instance

### Scaling Strategies

1. **Horizontal Application Scaling**
   - Stateless design enables unlimited instances
   - Load balancer distributes requests evenly
   - Auto-scaling based on CPU/memory metrics

2. **Database Optimization**
   - Read replicas for read-heavy endpoints
   - Connection pooling (20-50 connections per instance)
   - Query optimization with EXPLAIN ANALYZE
   - Indexing on foreign keys and query filters

3. **Caching Strategy**
   - Redis for user sessions and frequently accessed data
   - Permission lookups cached for 5 minutes
   - Organization metadata cached for 15 minutes
   - Cache invalidation on data mutations

4. **Async Architecture**
   - Non-blocking I/O throughout the stack
   - Async database queries with asyncpg
   - Async Redis operations with aioredis
   - Connection reuse and pooling

### Performance Optimizations

- **Eager Loading**: Relationships loaded in single query (selectinload)
- **Bulk Operations**: Batch inserts/updates for admin operations
- **Database Indexes**: Strategic indexing on high-cardinality columns
- **Query Result Caching**: Redis caching for repeated queries
- **HTTP/2**: Multiplexing and header compression

---

## Data Model Details

### Organization Model

**Purpose**: Top-level tenant entity representing a customer/company.

**Key Fields**:
- `plan`: Subscription tier (trial, starter, professional, enterprise)
- `max_users`: Quota enforcement field
- `max_teams`: Team limit per plan
- `slug`: Human-readable unique identifier for URLs

**Relationships**:
- 1:N with Teams, Users, SSO Configurations, Roles

**Lifecycle**:
- Soft delete preserves historical data
- Active organizations can downgrade/upgrade plans
- Deleted organizations retain data for compliance period

### User Model (EnterpriseUser)

**Purpose**: Represents authenticated users within an organization.

**Key Fields**:
- `organization_id`: Tenant isolation key
- `team_id`: Optional team membership
- `sso_provider`: Tracks authentication method
- `last_login_at`: Security audit field
- `password_changed_at`: Password age tracking

**Authentication Modes**:
- **Password**: Local authentication with bcrypt hash
- **SSO**: External IdP authentication (password nullable)
- **Hybrid**: Both methods enabled

**Security Fields**:
- `is_active`: Account status (can be disabled)
- `is_verified`: Email verification status
- `deleted_at`: Soft delete timestamp

### Role & Permission Models

**Role Types**:
1. **System Roles**: Predefined (Admin, Member, Viewer)
2. **Custom Roles**: Organization-specific definitions

**Permission Format**:
- Resource: Entity type (users, teams, organizations, cases)
- Action: Operation (create, read, update, delete, admin)
- Combined: `{resource}:{action}` (e.g., `users:delete`)

**Permission Inheritance**:
- Users can have multiple roles
- Permissions are union of all roles
- No negative permissions (deny rules)

### Audit Log Model

**Purpose**: Immutable event log for compliance and security.

**Event Types**:
- `login_success`, `login_failed`, `logout`
- `role_assigned`, `role_removed`
- `permission_denied`, `unauthorized_access`
- `user_created`, `user_updated`, `user_deleted`
- `organization_created`, `team_created`

**Context Data**:
- IP address, user agent for forensics
- Request ID for distributed tracing
- JSONB context_data for event-specific details

**Retention**:
- Never deleted (append-only)
- Indexed by organization_id, event_type, created_at
- Archived to cold storage after 90 days

---

## API Layer Design

### API Versioning

- **URL Prefix**: `/api/v1/enterprise/`
- **Versioning Strategy**: URL-based for clarity
- **Backward Compatibility**: v1 maintained for 12 months after v2 release

### Endpoint Structure

```
/api/v1/enterprise/
├── auth/
│   ├── POST /login              # Authenticate and get tokens
│   ├── POST /refresh            # Refresh access token
│   ├── POST /logout             # Invalidate tokens
│   ├── POST /register           # Create new user
│   └── GET  /me                 # Get current user info
├── organizations/
│   ├── GET    /                 # List organizations (admin only)
│   ├── POST   /                 # Create organization (system admin)
│   ├── GET    /{org_id}         # Get organization details
│   ├── PATCH  /{org_id}         # Update organization
│   └── DELETE /{org_id}         # Delete organization (soft)
├── teams/
│   ├── GET    /                 # List teams in user's org
│   ├── POST   /                 # Create team
│   ├── GET    /{team_id}        # Get team details
│   ├── PATCH  /{team_id}        # Update team
│   └── DELETE /{team_id}        # Delete team (soft)
├── users/
│   ├── GET    /                 # List users in org
│   ├── POST   /                 # Create user (admin)
│   ├── GET    /{user_id}        # Get user details
│   ├── PATCH  /{user_id}        # Update user
│   ├── DELETE /{user_id}        # Delete user (soft)
│   └── POST   /{user_id}/roles  # Assign role to user
└── sso/
    ├── GET    /configurations   # List SSO configs
    ├── POST   /configurations   # Create SSO config (admin)
    ├── PATCH  /configurations/{id}  # Update SSO config
    └── POST   /saml/callback    # SAML assertion consumer
```

### Request/Response Patterns

**Standard Response Format**:
```json
{
  "data": { ... },
  "meta": {
    "request_id": "req_123abc",
    "timestamp": "2025-11-18T10:30:00Z"
  }
}
```

**Error Response Format**:
```json
{
  "error": {
    "code": "PERMISSION_DENIED",
    "message": "Permission denied: users:delete required",
    "details": {
      "required_permission": "users:delete",
      "user_permissions": ["users:read", "users:update"]
    }
  },
  "meta": {
    "request_id": "req_123abc",
    "timestamp": "2025-11-18T10:30:00Z"
  }
}
```

### HTTP Status Codes

- `200 OK`: Successful GET/PATCH/DELETE
- `201 Created`: Successful POST (resource created)
- `204 No Content`: Successful DELETE (no response body)
- `400 Bad Request`: Invalid request data
- `401 Unauthorized`: Missing or invalid authentication
- `403 Forbidden`: Authenticated but insufficient permissions
- `404 Not Found`: Resource does not exist
- `409 Conflict`: Resource already exists (e.g., duplicate email)
- `422 Unprocessable Entity`: Validation errors
- `500 Internal Server Error`: Unexpected server error

### Rate Limiting

- **Default**: 1000 requests/hour per user
- **Authentication**: 10 login attempts/hour per IP
- **Headers**: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`
- **Implementation**: Redis-based sliding window

---

## Future Enhancements

### Near-Term (Q1 2026)

1. **Email Verification**
   - Send verification emails on registration
   - Email verification flow with token
   - Resend verification email endpoint

2. **Password Reset**
   - Forgot password flow
   - Secure reset tokens (time-limited)
   - Password reset email templates

3. **Token Blacklisting**
   - Redis-based token revocation
   - Logout invalidates tokens server-side
   - Compromised token revocation API

4. **Rate Limiting**
   - Redis-based rate limiter
   - Configurable limits per endpoint
   - Burst allowance for legitimate traffic

5. **API Key Authentication**
   - Service account API keys
   - Scoped permissions for API keys
   - Key rotation and expiration

### Mid-Term (Q2-Q3 2026)

1. **Multi-Factor Authentication (MFA)**
   - TOTP (Time-based One-Time Password)
   - SMS verification (via Twilio)
   - Backup codes for account recovery
   - MFA enforcement per organization

2. **Advanced Audit Logging**
   - Elasticsearch integration for log search
   - Real-time audit event streaming
   - Anomaly detection on audit logs
   - Compliance report generation

3. **Session Management**
   - Active session tracking
   - Device fingerprinting
   - Session revocation (kill other sessions)
   - Concurrent session limits

4. **Advanced RBAC**
   - Attribute-Based Access Control (ABAC)
   - Conditional permissions (time-based, IP-based)
   - Role hierarchies and inheritance
   - Permission delegation

5. **WebAuthn/FIDO2 Support**
   - Passwordless authentication
   - Hardware security key support
   - Biometric authentication

### Long-Term (Q4 2026+)

1. **Identity Federation**
   - SCIM 2.0 for user provisioning
   - Cross-organization SSO
   - Identity broker for multiple IdPs
   - Just-in-Time (JIT) user provisioning

2. **Advanced Threat Detection**
   - Machine learning for anomaly detection
   - Impossible travel detection
   - Brute force protection
   - Account takeover prevention

3. **Compliance Certifications**
   - SOC 2 Type II certification
   - GDPR compliance tools
   - HIPAA compliance features
   - Data residency controls

4. **Global Distribution**
   - Multi-region deployment
   - Geo-fencing and data residency
   - Global load balancing
   - Edge authentication

5. **Developer Platform**
   - OAuth 2.0 authorization server
   - Developer portal for third-party apps
   - Webhook event notifications
   - GraphQL API alternative

---

## Conclusion

The FaultMaven Auth Service Enterprise Edition provides a robust, scalable, and secure authentication and authorization platform for multi-tenant SaaS applications. Built on modern async Python technologies, it delivers:

- **Enterprise-Grade Security**: JWT authentication, RBAC, SSO, audit logging
- **True Multi-Tenancy**: Organization-level data isolation with zero cross-tenant leakage
- **High Performance**: Async architecture supporting 10,000+ req/sec per instance
- **Production Ready**: HA deployment, monitoring, and operational excellence

The architecture balances simplicity with extensibility, enabling rapid feature development while maintaining security and compliance standards. The clear separation of concerns across API, middleware, service, and data layers ensures maintainability and testability.

---

**Document Version**: 1.0
**Last Updated**: 2025-11-18
**Maintained By**: FaultMaven Platform Team
