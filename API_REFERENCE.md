# FaultMaven Auth Service API Reference

Enterprise Edition API documentation for multi-tenant SaaS authentication and authorization.

## Table of Contents

- [Introduction](#introduction)
- [Base URL and Versioning](#base-url-and-versioning)
- [Authentication](#authentication)
- [Authentication Endpoints](#authentication-endpoints)
- [Organization Management](#organization-management)
- [Team Management](#team-management)
- [User Management](#user-management)
- [SSO Configuration](#sso-configuration)
- [Error Codes Reference](#error-codes-reference)
- [Rate Limiting](#rate-limiting)
- [Complete Workflow Examples](#complete-workflow-examples)
- [Postman Collection](#postman-collection)

---

## Introduction

The FaultMaven Auth Service provides enterprise-grade authentication and authorization for multi-tenant SaaS applications. It supports:

- **JWT-based authentication** with access and refresh tokens
- **Multi-tenant architecture** with strict organization isolation
- **Role-Based Access Control (RBAC)** with fine-grained permissions
- **SSO integration** via SAML, OAuth 2.0, and OpenID Connect
- **Team-based organization** for granular access control
- **Soft deletion** for data recovery and audit trails

This API follows RESTful principles and returns JSON responses.

---

## Base URL and Versioning

**Base URL:** `https://auth.faultmaven.com`

**API Version:** `v1`

All endpoints are prefixed with `/api/v1/enterprise/`

**Example:** `https://auth.faultmaven.com/api/v1/enterprise/auth/login`

---

## Authentication

### Overview

The API uses **Bearer token authentication** with JWT (JSON Web Tokens).

### Token Types

1. **Access Token** - Short-lived token (default: 30 minutes) for API requests
2. **Refresh Token** - Long-lived token (default: 7 days) for obtaining new access tokens

### How to Authenticate

1. **Obtain tokens** by logging in via `POST /api/v1/enterprise/auth/login`
2. **Include access token** in the `Authorization` header for all authenticated requests:
   ```
   Authorization: Bearer <access_token>
   ```
3. **Refresh tokens** when access token expires via `POST /api/v1/enterprise/auth/refresh`

### Token Structure

Access tokens include the following claims:
- `sub` - User ID (UUID)
- `organization_id` - Organization ID (UUID)
- `email` - User email address
- `type` - Token type ("access")
- `exp` - Expiration timestamp
- `iat` - Issued at timestamp

### Public Endpoints (No Authentication Required)

- `POST /api/v1/enterprise/auth/login`
- `POST /api/v1/enterprise/auth/register`
- `POST /api/v1/enterprise/auth/refresh`

---

## Authentication Endpoints

### `POST /api/v1/enterprise/auth/login`

Authenticate user and obtain JWT tokens.

**Authentication:** Public (no token required)

#### Request

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!"
}
```

**Schema:**
- `email` (string, required): Valid email address
- `password` (string, required): Minimum 8 characters

#### Response

**Success (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 1800
}
```

**Error Responses:**
- `401 Unauthorized`: Incorrect email or password
- `403 Forbidden`: Account is disabled

#### Example

```bash
curl -X POST https://auth.faultmaven.com/api/v1/enterprise/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePassword123!"
  }'
```

---

### `POST /api/v1/enterprise/auth/refresh`

Refresh access token using a refresh token.

**Authentication:** Public (refresh token required in body)

#### Request

**Request Body:**
```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Schema:**
- `refresh_token` (string, required): Valid refresh token

#### Response

**Success (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 1800
}
```

**Error Responses:**
- `401 Unauthorized`: Invalid or expired refresh token
- `403 Forbidden`: Account is disabled

#### Example

```bash
curl -X POST https://auth.faultmaven.com/api/v1/enterprise/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }'
```

---

### `POST /api/v1/enterprise/auth/logout`

Logout user (client-side token invalidation).

**Authentication:** Bearer token required

**Note:** JWT tokens are stateless. Logout is handled client-side by discarding tokens. For server-side revocation, implement a token blacklist using Redis.

#### Request

No request body required.

#### Response

**Success (200 OK):**
```json
{
  "message": "Logged out successfully. Please discard your tokens."
}
```

**Error Responses:**
- `401 Unauthorized`: Missing or invalid token

#### Example

```bash
curl -X POST https://auth.faultmaven.com/api/v1/enterprise/auth/logout \
  -H "Authorization: Bearer <access_token>"
```

---

### `POST /api/v1/enterprise/auth/register`

Register a new user in an organization.

**Authentication:** Public (no token required)

#### Request

**Request Body:**
```json
{
  "organization_id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "newuser@example.com",
  "full_name": "Jane Smith",
  "password": "SecurePassword123!",
  "team_id": "650e8400-e29b-41d4-a716-446655440000"
}
```

**Schema:**
- `organization_id` (UUID, required): Organization to join
- `email` (string, required): Valid email address
- `full_name` (string, required): User's full name (1-255 characters)
- `password` (string, required): Minimum 8 characters
- `team_id` (UUID, optional): Team to join within organization

#### Response

**Success (201 Created):**
```json
{
  "id": "750e8400-e29b-41d4-a716-446655440000",
  "email": "newuser@example.com",
  "full_name": "Jane Smith",
  "organization_id": "550e8400-e29b-41d4-a716-446655440000",
  "message": "User registered successfully. You can now login."
}
```

**Error Responses:**
- `404 Not Found`: Organization not found
- `409 Conflict`: User with email already exists
- `403 Forbidden`: Organization has reached maximum users limit

#### Example

```bash
curl -X POST https://auth.faultmaven.com/api/v1/enterprise/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "organization_id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "newuser@example.com",
    "full_name": "Jane Smith",
    "password": "SecurePassword123!"
  }'
```

---

### `GET /api/v1/enterprise/auth/me`

Get current authenticated user information.

**Authentication:** Bearer token required

#### Request

No request body or parameters required.

#### Response

**Success (200 OK):**
```json
{
  "id": "750e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com",
  "full_name": "Jane Smith",
  "organization_id": "550e8400-e29b-41d4-a716-446655440000",
  "team_id": "650e8400-e29b-41d4-a716-446655440000",
  "is_active": true,
  "is_verified": true,
  "sso_provider": null,
  "roles": [
    {
      "id": "850e8400-e29b-41d4-a716-446655440000",
      "name": "admin",
      "description": "Organization administrator"
    }
  ],
  "permissions": [
    "organizations:create",
    "organizations:read",
    "organizations:update",
    "teams:create",
    "teams:read",
    "users:create",
    "users:read"
  ]
}
```

**Error Responses:**
- `401 Unauthorized`: Missing or invalid token

#### Example

```bash
curl -X GET https://auth.faultmaven.com/api/v1/enterprise/auth/me \
  -H "Authorization: Bearer <access_token>"
```

---

## Organization Management

### `POST /api/v1/enterprise/organizations`

Create a new organization (tenant).

**Authentication:** Bearer token required
**Permissions:** `organizations:create`

#### Request

**Request Body:**
```json
{
  "name": "Acme Corporation",
  "slug": "acme-corp",
  "plan": "professional",
  "contact_email": "admin@acme.com",
  "contact_name": "John Doe",
  "max_users": 50,
  "max_teams": 10
}
```

**Schema:**
- `name` (string, required): Organization name (1-255 characters)
- `slug` (string, required): URL-friendly identifier (lowercase, alphanumeric, hyphens only)
- `plan` (string, optional): Plan type - `trial`, `starter`, `professional`, or `enterprise` (default: `trial`)
- `contact_email` (string, optional): Primary contact email
- `contact_name` (string, optional): Primary contact name
- `max_users` (integer, optional): Maximum number of users (default: 10, minimum: 1)
- `max_teams` (integer, optional): Maximum number of teams (default: 5, minimum: 1)

#### Response

**Success (201 Created):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "Acme Corporation",
  "slug": "acme-corp",
  "plan": "professional",
  "is_active": true,
  "max_users": 50,
  "max_teams": 10,
  "contact_email": "admin@acme.com",
  "contact_name": "John Doe"
}
```

**Error Responses:**
- `401 Unauthorized`: Missing or invalid token
- `403 Forbidden`: Insufficient permissions
- `409 Conflict`: Organization with slug already exists

#### Example

```bash
curl -X POST https://auth.faultmaven.com/api/v1/enterprise/organizations \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Acme Corporation",
    "slug": "acme-corp",
    "plan": "professional",
    "max_users": 50
  }'
```

---

### `GET /api/v1/enterprise/organizations`

List organizations (returns user's organization only due to multi-tenant isolation).

**Authentication:** Bearer token required

#### Request

**Query Parameters:**
- `skip` (integer, optional): Number of records to skip for pagination (default: 0)
- `limit` (integer, optional): Maximum number of records to return (default: 100)
- `is_active` (boolean, optional): Filter by active status

#### Response

**Success (200 OK):**
```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "Acme Corporation",
    "slug": "acme-corp",
    "plan": "professional",
    "is_active": true,
    "max_users": 50,
    "max_teams": 10,
    "contact_email": "admin@acme.com",
    "contact_name": "John Doe"
  }
]
```

**Error Responses:**
- `401 Unauthorized`: Missing or invalid token

#### Example

```bash
curl -X GET "https://auth.faultmaven.com/api/v1/enterprise/organizations?is_active=true" \
  -H "Authorization: Bearer <access_token>"
```

---

### `GET /api/v1/enterprise/organizations/{organization_id}`

Get organization by ID.

**Authentication:** Bearer token required
**Access Control:** User must belong to the organization

#### Request

**Path Parameters:**
- `organization_id` (UUID, required): Organization UUID

#### Response

**Success (200 OK):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "Acme Corporation",
  "slug": "acme-corp",
  "plan": "professional",
  "is_active": true,
  "max_users": 50,
  "max_teams": 10,
  "contact_email": "admin@acme.com",
  "contact_name": "John Doe"
}
```

**Error Responses:**
- `401 Unauthorized`: Missing or invalid token
- `403 Forbidden`: User does not belong to organization
- `404 Not Found`: Organization not found

#### Example

```bash
curl -X GET https://auth.faultmaven.com/api/v1/enterprise/organizations/550e8400-e29b-41d4-a716-446655440000 \
  -H "Authorization: Bearer <access_token>"
```

---

### `PUT /api/v1/enterprise/organizations/{organization_id}`

Update organization.

**Authentication:** Bearer token required
**Access Control:** Organization admin role required

#### Request

**Path Parameters:**
- `organization_id` (UUID, required): Organization UUID

**Request Body:**
```json
{
  "name": "Acme Corporation Inc.",
  "plan": "enterprise",
  "max_users": 100,
  "is_active": true
}
```

**Schema (all fields optional):**
- `name` (string): Organization name (1-255 characters)
- `plan` (string): Plan type - `trial`, `starter`, `professional`, or `enterprise`
- `contact_email` (string): Primary contact email
- `contact_name` (string): Primary contact name
- `max_users` (integer): Maximum number of users (minimum: 1)
- `max_teams` (integer): Maximum number of teams (minimum: 1)
- `is_active` (boolean): Active status

#### Response

**Success (200 OK):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "Acme Corporation Inc.",
  "slug": "acme-corp",
  "plan": "enterprise",
  "is_active": true,
  "max_users": 100,
  "max_teams": 10,
  "contact_email": "admin@acme.com",
  "contact_name": "John Doe"
}
```

**Error Responses:**
- `401 Unauthorized`: Missing or invalid token
- `403 Forbidden`: User is not organization admin or does not belong to organization
- `404 Not Found`: Organization not found

#### Example

```bash
curl -X PUT https://auth.faultmaven.com/api/v1/enterprise/organizations/550e8400-e29b-41d4-a716-446655440000 \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "plan": "enterprise",
    "max_users": 100
  }'
```

---

### `DELETE /api/v1/enterprise/organizations/{organization_id}`

Soft delete organization.

**Authentication:** Bearer token required
**Access Control:** Organization admin role required

**Note:** This is a soft delete - the organization is marked as deleted but not removed from the database.

#### Request

**Path Parameters:**
- `organization_id` (UUID, required): Organization UUID

#### Response

**Success (204 No Content):**

No response body.

**Error Responses:**
- `401 Unauthorized`: Missing or invalid token
- `403 Forbidden`: User is not organization admin or does not belong to organization
- `404 Not Found`: Organization not found

#### Example

```bash
curl -X DELETE https://auth.faultmaven.com/api/v1/enterprise/organizations/550e8400-e29b-41d4-a716-446655440000 \
  -H "Authorization: Bearer <access_token>"
```

---

## Team Management

### `POST /api/v1/enterprise/teams`

Create a new team within an organization.

**Authentication:** Bearer token required
**Permissions:** `teams:create`

#### Request

**Request Body:**
```json
{
  "organization_id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "Engineering",
  "slug": "engineering",
  "description": "Engineering and development team"
}
```

**Schema:**
- `organization_id` (UUID, required): Organization UUID
- `name` (string, required): Team name (1-255 characters)
- `slug` (string, required): URL-friendly identifier (lowercase, alphanumeric, hyphens only)
- `description` (string, optional): Team description

#### Response

**Success (201 Created):**
```json
{
  "id": "650e8400-e29b-41d4-a716-446655440000",
  "organization_id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "Engineering",
  "slug": "engineering",
  "description": "Engineering and development team"
}
```

**Error Responses:**
- `401 Unauthorized`: Missing or invalid token
- `403 Forbidden`: Insufficient permissions, access denied, or organization reached max teams limit
- `404 Not Found`: Organization not found
- `409 Conflict`: Team with slug already exists in organization

#### Example

```bash
curl -X POST https://auth.faultmaven.com/api/v1/enterprise/teams \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "organization_id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "Engineering",
    "slug": "engineering"
  }'
```

---

### `GET /api/v1/enterprise/teams/organization/{organization_id}`

List teams for an organization.

**Authentication:** Bearer token required
**Access Control:** User must belong to the organization

#### Request

**Path Parameters:**
- `organization_id` (UUID, required): Organization UUID

**Query Parameters:**
- `skip` (integer, optional): Number of records to skip for pagination (default: 0)
- `limit` (integer, optional): Maximum number of records to return (default: 100)

#### Response

**Success (200 OK):**
```json
[
  {
    "id": "650e8400-e29b-41d4-a716-446655440000",
    "organization_id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "Engineering",
    "slug": "engineering",
    "description": "Engineering and development team"
  },
  {
    "id": "660e8400-e29b-41d4-a716-446655440000",
    "organization_id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "Product",
    "slug": "product",
    "description": "Product management team"
  }
]
```

**Error Responses:**
- `401 Unauthorized`: Missing or invalid token
- `403 Forbidden`: User does not belong to organization

#### Example

```bash
curl -X GET "https://auth.faultmaven.com/api/v1/enterprise/teams/organization/550e8400-e29b-41d4-a716-446655440000?limit=50" \
  -H "Authorization: Bearer <access_token>"
```

---

### `GET /api/v1/enterprise/teams/{team_id}`

Get team by ID.

**Authentication:** Bearer token required
**Access Control:** User must belong to the team's organization

#### Request

**Path Parameters:**
- `team_id` (UUID, required): Team UUID

#### Response

**Success (200 OK):**
```json
{
  "id": "650e8400-e29b-41d4-a716-446655440000",
  "organization_id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "Engineering",
  "slug": "engineering",
  "description": "Engineering and development team"
}
```

**Error Responses:**
- `401 Unauthorized`: Missing or invalid token
- `403 Forbidden`: User does not belong to team's organization
- `404 Not Found`: Team not found

#### Example

```bash
curl -X GET https://auth.faultmaven.com/api/v1/enterprise/teams/650e8400-e29b-41d4-a716-446655440000 \
  -H "Authorization: Bearer <access_token>"
```

---

### `PUT /api/v1/enterprise/teams/{team_id}`

Update team.

**Authentication:** Bearer token required
**Permissions:** `teams:update`

#### Request

**Path Parameters:**
- `team_id` (UUID, required): Team UUID

**Request Body:**
```json
{
  "name": "Engineering & DevOps",
  "description": "Combined engineering and DevOps team"
}
```

**Schema (all fields optional):**
- `name` (string): Team name (1-255 characters)
- `slug` (string): URL-friendly identifier (lowercase, alphanumeric, hyphens only)
- `description` (string): Team description

#### Response

**Success (200 OK):**
```json
{
  "id": "650e8400-e29b-41d4-a716-446655440000",
  "organization_id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "Engineering & DevOps",
  "slug": "engineering",
  "description": "Combined engineering and DevOps team"
}
```

**Error Responses:**
- `401 Unauthorized`: Missing or invalid token
- `403 Forbidden`: Insufficient permissions or user does not belong to team's organization
- `404 Not Found`: Team not found
- `409 Conflict`: Team with slug already exists in organization

#### Example

```bash
curl -X PUT https://auth.faultmaven.com/api/v1/enterprise/teams/650e8400-e29b-41d4-a716-446655440000 \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Engineering & DevOps"
  }'
```

---

### `DELETE /api/v1/enterprise/teams/{team_id}`

Soft delete team.

**Authentication:** Bearer token required
**Permissions:** `teams:delete`

**Note:** This is a soft delete - the team is marked as deleted but not removed from the database.

#### Request

**Path Parameters:**
- `team_id` (UUID, required): Team UUID

#### Response

**Success (204 No Content):**

No response body.

**Error Responses:**
- `401 Unauthorized`: Missing or invalid token
- `403 Forbidden`: Insufficient permissions or user does not belong to team's organization
- `404 Not Found`: Team not found

#### Example

```bash
curl -X DELETE https://auth.faultmaven.com/api/v1/enterprise/teams/650e8400-e29b-41d4-a716-446655440000 \
  -H "Authorization: Bearer <access_token>"
```

---

## User Management

### `POST /api/v1/enterprise/users`

Create a new user in an organization.

**Authentication:** Bearer token required
**Permissions:** `users:create`

#### Request

**Request Body:**
```json
{
  "organization_id": "550e8400-e29b-41d4-a716-446655440000",
  "team_id": "650e8400-e29b-41d4-a716-446655440000",
  "email": "engineer@acme.com",
  "full_name": "Alice Johnson",
  "password": "SecurePassword123!"
}
```

**Schema:**
- `organization_id` (UUID, required): Organization UUID
- `team_id` (UUID, optional): Team UUID
- `email` (string, required): Valid email address (globally unique)
- `full_name` (string, required): User's full name (1-255 characters)
- `password` (string, optional): Minimum 8 characters (null for SSO-only users)

#### Response

**Success (201 Created):**
```json
{
  "id": "750e8400-e29b-41d4-a716-446655440000",
  "organization_id": "550e8400-e29b-41d4-a716-446655440000",
  "team_id": "650e8400-e29b-41d4-a716-446655440000",
  "email": "engineer@acme.com",
  "full_name": "Alice Johnson",
  "is_active": true,
  "is_verified": false,
  "sso_provider": null
}
```

**Error Responses:**
- `401 Unauthorized`: Missing or invalid token
- `403 Forbidden`: Insufficient permissions, access denied, or organization reached max users limit
- `404 Not Found`: Organization or team not found
- `409 Conflict`: User with email already exists

#### Example

```bash
curl -X POST https://auth.faultmaven.com/api/v1/enterprise/users \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "organization_id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "engineer@acme.com",
    "full_name": "Alice Johnson",
    "password": "SecurePassword123!"
  }'
```

---

### `GET /api/v1/enterprise/users/organization/{organization_id}`

List users in an organization.

**Authentication:** Bearer token required
**Access Control:** User must belong to the organization

#### Request

**Path Parameters:**
- `organization_id` (UUID, required): Organization UUID

**Query Parameters:**
- `team_id` (UUID, optional): Filter by team
- `is_active` (boolean, optional): Filter by active status
- `skip` (integer, optional): Number of records to skip for pagination (default: 0)
- `limit` (integer, optional): Maximum number of records to return (default: 100)

#### Response

**Success (200 OK):**
```json
[
  {
    "id": "750e8400-e29b-41d4-a716-446655440000",
    "organization_id": "550e8400-e29b-41d4-a716-446655440000",
    "team_id": "650e8400-e29b-41d4-a716-446655440000",
    "email": "engineer@acme.com",
    "full_name": "Alice Johnson",
    "is_active": true,
    "is_verified": true,
    "sso_provider": null
  },
  {
    "id": "760e8400-e29b-41d4-a716-446655440000",
    "organization_id": "550e8400-e29b-41d4-a716-446655440000",
    "team_id": "650e8400-e29b-41d4-a716-446655440000",
    "email": "developer@acme.com",
    "full_name": "Bob Smith",
    "is_active": true,
    "is_verified": true,
    "sso_provider": "okta"
  }
]
```

**Error Responses:**
- `401 Unauthorized`: Missing or invalid token
- `403 Forbidden`: User does not belong to organization

#### Example

```bash
curl -X GET "https://auth.faultmaven.com/api/v1/enterprise/users/organization/550e8400-e29b-41d4-a716-446655440000?is_active=true" \
  -H "Authorization: Bearer <access_token>"
```

---

### `GET /api/v1/enterprise/users/{user_id}`

Get user by ID.

**Authentication:** Bearer token required
**Access Control:** User must belong to the same organization

#### Request

**Path Parameters:**
- `user_id` (UUID, required): User UUID

#### Response

**Success (200 OK):**
```json
{
  "id": "750e8400-e29b-41d4-a716-446655440000",
  "organization_id": "550e8400-e29b-41d4-a716-446655440000",
  "team_id": "650e8400-e29b-41d4-a716-446655440000",
  "email": "engineer@acme.com",
  "full_name": "Alice Johnson",
  "is_active": true,
  "is_verified": true,
  "sso_provider": null
}
```

**Error Responses:**
- `401 Unauthorized`: Missing or invalid token
- `403 Forbidden`: User does not belong to same organization
- `404 Not Found`: User not found

#### Example

```bash
curl -X GET https://auth.faultmaven.com/api/v1/enterprise/users/750e8400-e29b-41d4-a716-446655440000 \
  -H "Authorization: Bearer <access_token>"
```

---

### `PUT /api/v1/enterprise/users/{user_id}`

Update user.

**Authentication:** Bearer token required
**Permissions:** `users:update`

#### Request

**Path Parameters:**
- `user_id` (UUID, required): User UUID

**Request Body:**
```json
{
  "full_name": "Alice Johnson-Smith",
  "team_id": "660e8400-e29b-41d4-a716-446655440000",
  "is_active": true
}
```

**Schema (all fields optional):**
- `team_id` (UUID): Team UUID
- `full_name` (string): User's full name (1-255 characters)
- `is_active` (boolean): Active status

#### Response

**Success (200 OK):**
```json
{
  "id": "750e8400-e29b-41d4-a716-446655440000",
  "organization_id": "550e8400-e29b-41d4-a716-446655440000",
  "team_id": "660e8400-e29b-41d4-a716-446655440000",
  "email": "engineer@acme.com",
  "full_name": "Alice Johnson-Smith",
  "is_active": true,
  "is_verified": true,
  "sso_provider": null
}
```

**Error Responses:**
- `401 Unauthorized`: Missing or invalid token
- `403 Forbidden`: Insufficient permissions or user does not belong to same organization
- `404 Not Found`: User or team not found

#### Example

```bash
curl -X PUT https://auth.faultmaven.com/api/v1/enterprise/users/750e8400-e29b-41d4-a716-446655440000 \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "full_name": "Alice Johnson-Smith"
  }'
```

---

### `DELETE /api/v1/enterprise/users/{user_id}`

Soft delete user.

**Authentication:** Bearer token required
**Permissions:** `users:delete`

**Note:** This is a soft delete - the user is marked as deleted but not removed from the database.

#### Request

**Path Parameters:**
- `user_id` (UUID, required): User UUID

#### Response

**Success (204 No Content):**

No response body.

**Error Responses:**
- `401 Unauthorized`: Missing or invalid token
- `403 Forbidden`: Insufficient permissions or user does not belong to same organization
- `404 Not Found`: User not found

#### Example

```bash
curl -X DELETE https://auth.faultmaven.com/api/v1/enterprise/users/750e8400-e29b-41d4-a716-446655440000 \
  -H "Authorization: Bearer <access_token>"
```

---

## SSO Configuration

### `POST /api/v1/enterprise/sso`

Create SSO configuration for an organization.

**Authentication:** Bearer token required
**Access Control:** Organization admin role required

#### Request

**Request Body (SAML example):**
```json
{
  "organization_id": "550e8400-e29b-41d4-a716-446655440000",
  "provider_type": "saml",
  "provider_name": "Okta SAML",
  "is_enabled": true,
  "saml_entity_id": "http://www.okta.com/exk1234567890",
  "saml_sso_url": "https://acme.okta.com/app/acme_faultmaven_1/exk1234567890/sso/saml",
  "saml_slo_url": "https://acme.okta.com/app/acme_faultmaven_1/exk1234567890/slo/saml",
  "saml_x509_cert": "-----BEGIN CERTIFICATE-----\nMIIDpDCCAoygAwIBAgIGAX...\n-----END CERTIFICATE-----",
  "saml_name_id_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
  "attribute_mapping": {
    "email": "email",
    "full_name": "displayName",
    "firstName": "firstName",
    "lastName": "lastName"
  },
  "auto_create_users": true
}
```

**Request Body (OAuth/OIDC example):**
```json
{
  "organization_id": "550e8400-e29b-41d4-a716-446655440000",
  "provider_type": "oidc",
  "provider_name": "Google OIDC",
  "is_enabled": true,
  "oauth_client_id": "1234567890-abcdefghijklmnop.apps.googleusercontent.com",
  "oauth_client_secret": "GOCSPX-abcdefghijklmnop",
  "oauth_authorization_url": "https://accounts.google.com/o/oauth2/v2/auth",
  "oauth_token_url": "https://oauth2.googleapis.com/token",
  "oauth_userinfo_url": "https://www.googleapis.com/oauth2/v3/userinfo",
  "oauth_scopes": "openid email profile",
  "oidc_issuer": "https://accounts.google.com",
  "oidc_jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
  "attribute_mapping": {
    "email": "email",
    "full_name": "name"
  },
  "auto_create_users": true
}
```

**Schema:**
- `organization_id` (UUID, required): Organization UUID
- `provider_type` (string, required): `saml`, `oauth`, or `oidc`
- `provider_name` (string, required): Display name (1-255 characters)
- `is_enabled` (boolean, optional): Enable/disable configuration (default: true)

**SAML-specific fields (required for SAML):**
- `saml_entity_id` (string): Identity provider entity ID
- `saml_sso_url` (string): Single sign-on URL
- `saml_slo_url` (string, optional): Single logout URL
- `saml_x509_cert` (string, optional): X.509 certificate
- `saml_name_id_format` (string, optional): Name ID format

**OAuth/OIDC-specific fields (required for oauth/oidc):**
- `oauth_client_id` (string): OAuth client ID
- `oauth_client_secret` (string): OAuth client secret
- `oauth_authorization_url` (string, optional): Authorization endpoint
- `oauth_token_url` (string, optional): Token endpoint
- `oauth_userinfo_url` (string, optional): User info endpoint
- `oauth_scopes` (string, optional): Requested scopes

**OIDC-specific fields:**
- `oidc_issuer` (string, optional): OIDC issuer URL
- `oidc_jwks_uri` (string, optional): JWKS URI for key verification

**Configuration:**
- `attribute_mapping` (object, optional): Map SSO attributes to user fields
- `auto_create_users` (boolean, optional): Auto-create users on first SSO login (default: true)
- `default_role_id` (UUID, optional): Default role for auto-created users

#### Response

**Success (201 Created):**
```json
{
  "id": "850e8400-e29b-41d4-a716-446655440000",
  "organization_id": "550e8400-e29b-41d4-a716-446655440000",
  "provider_type": "saml",
  "provider_name": "Okta SAML",
  "is_enabled": true,
  "auto_create_users": true,
  "saml_entity_id": "http://www.okta.com/exk1234567890",
  "saml_sso_url": "https://acme.okta.com/app/acme_faultmaven_1/exk1234567890/sso/saml",
  "oauth_client_id": null,
  "oauth_authorization_url": null,
  "oidc_issuer": null
}
```

**Error Responses:**
- `400 Bad Request`: Missing required fields for provider type
- `401 Unauthorized`: Missing or invalid token
- `403 Forbidden`: User is not organization admin or does not belong to organization
- `404 Not Found`: Organization not found

#### Example

```bash
curl -X POST https://auth.faultmaven.com/api/v1/enterprise/sso \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "organization_id": "550e8400-e29b-41d4-a716-446655440000",
    "provider_type": "saml",
    "provider_name": "Okta SAML",
    "saml_entity_id": "http://www.okta.com/exk1234567890",
    "saml_sso_url": "https://acme.okta.com/sso/saml"
  }'
```

---

### `GET /api/v1/enterprise/sso/organization/{organization_id}`

List SSO configurations for an organization.

**Authentication:** Bearer token required
**Access Control:** User must belong to the organization

#### Request

**Path Parameters:**
- `organization_id` (UUID, required): Organization UUID

**Query Parameters:**
- `provider_type` (string, optional): Filter by provider type (`saml`, `oauth`, `oidc`)

#### Response

**Success (200 OK):**
```json
[
  {
    "id": "850e8400-e29b-41d4-a716-446655440000",
    "organization_id": "550e8400-e29b-41d4-a716-446655440000",
    "provider_type": "saml",
    "provider_name": "Okta SAML",
    "is_enabled": true,
    "auto_create_users": true,
    "saml_entity_id": "http://www.okta.com/exk1234567890",
    "saml_sso_url": "https://acme.okta.com/sso/saml",
    "oauth_client_id": null,
    "oauth_authorization_url": null,
    "oidc_issuer": null
  }
]
```

**Error Responses:**
- `401 Unauthorized`: Missing or invalid token
- `403 Forbidden`: User does not belong to organization

#### Example

```bash
curl -X GET "https://auth.faultmaven.com/api/v1/enterprise/sso/organization/550e8400-e29b-41d4-a716-446655440000?provider_type=saml" \
  -H "Authorization: Bearer <access_token>"
```

---

### `GET /api/v1/enterprise/sso/{sso_config_id}`

Get SSO configuration by ID.

**Authentication:** Bearer token required
**Access Control:** User must belong to the configuration's organization

#### Request

**Path Parameters:**
- `sso_config_id` (UUID, required): SSO configuration UUID

#### Response

**Success (200 OK):**
```json
{
  "id": "850e8400-e29b-41d4-a716-446655440000",
  "organization_id": "550e8400-e29b-41d4-a716-446655440000",
  "provider_type": "saml",
  "provider_name": "Okta SAML",
  "is_enabled": true,
  "auto_create_users": true,
  "saml_entity_id": "http://www.okta.com/exk1234567890",
  "saml_sso_url": "https://acme.okta.com/sso/saml",
  "oauth_client_id": null,
  "oauth_authorization_url": null,
  "oidc_issuer": null
}
```

**Error Responses:**
- `401 Unauthorized`: Missing or invalid token
- `403 Forbidden`: User does not belong to configuration's organization
- `404 Not Found`: SSO configuration not found

#### Example

```bash
curl -X GET https://auth.faultmaven.com/api/v1/enterprise/sso/850e8400-e29b-41d4-a716-446655440000 \
  -H "Authorization: Bearer <access_token>"
```

---

### `PUT /api/v1/enterprise/sso/{sso_config_id}`

Update SSO configuration.

**Authentication:** Bearer token required
**Access Control:** Organization admin role required

#### Request

**Path Parameters:**
- `sso_config_id` (UUID, required): SSO configuration UUID

**Request Body:**
```json
{
  "provider_name": "Okta SAML (Updated)",
  "is_enabled": false,
  "saml_sso_url": "https://acme.okta.com/new-sso-url"
}
```

**Schema (all fields optional):**
- `provider_name` (string): Display name (1-255 characters)
- `is_enabled` (boolean): Enable/disable configuration
- `saml_entity_id` (string): Identity provider entity ID
- `saml_sso_url` (string): Single sign-on URL
- `saml_slo_url` (string): Single logout URL
- `saml_x509_cert` (string): X.509 certificate
- `oauth_client_id` (string): OAuth client ID
- `oauth_client_secret` (string): OAuth client secret
- `attribute_mapping` (object): Attribute mapping configuration
- `auto_create_users` (boolean): Auto-create users on SSO login

#### Response

**Success (200 OK):**
```json
{
  "id": "850e8400-e29b-41d4-a716-446655440000",
  "organization_id": "550e8400-e29b-41d4-a716-446655440000",
  "provider_type": "saml",
  "provider_name": "Okta SAML (Updated)",
  "is_enabled": false,
  "auto_create_users": true,
  "saml_entity_id": "http://www.okta.com/exk1234567890",
  "saml_sso_url": "https://acme.okta.com/new-sso-url",
  "oauth_client_id": null,
  "oauth_authorization_url": null,
  "oidc_issuer": null
}
```

**Error Responses:**
- `401 Unauthorized`: Missing or invalid token
- `403 Forbidden`: User is not organization admin or does not belong to configuration's organization
- `404 Not Found`: SSO configuration not found

#### Example

```bash
curl -X PUT https://auth.faultmaven.com/api/v1/enterprise/sso/850e8400-e29b-41d4-a716-446655440000 \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "is_enabled": false
  }'
```

---

### `DELETE /api/v1/enterprise/sso/{sso_config_id}`

Delete SSO configuration.

**Authentication:** Bearer token required
**Access Control:** Organization admin role required

**Note:** This is a hard delete - the SSO configuration is permanently removed.

#### Request

**Path Parameters:**
- `sso_config_id` (UUID, required): SSO configuration UUID

#### Response

**Success (204 No Content):**

No response body.

**Error Responses:**
- `401 Unauthorized`: Missing or invalid token
- `403 Forbidden`: User is not organization admin or does not belong to configuration's organization
- `404 Not Found`: SSO configuration not found

#### Example

```bash
curl -X DELETE https://auth.faultmaven.com/api/v1/enterprise/sso/850e8400-e29b-41d4-a716-446655440000 \
  -H "Authorization: Bearer <access_token>"
```

---

## Error Codes Reference

### HTTP Status Codes

The API uses standard HTTP status codes to indicate success or failure:

#### Success Codes

- **200 OK** - Request succeeded
- **201 Created** - Resource created successfully
- **204 No Content** - Request succeeded with no response body (typically for DELETE)

#### Client Error Codes

- **400 Bad Request** - Invalid request data or validation error
  ```json
  {
    "detail": "SAML configuration requires entity_id and sso_url"
  }
  ```

- **401 Unauthorized** - Missing, invalid, or expired authentication token
  ```json
  {
    "detail": "Invalid or expired token",
    "headers": {
      "WWW-Authenticate": "Bearer"
    }
  }
  ```

- **403 Forbidden** - Authenticated but insufficient permissions or access denied
  ```json
  {
    "detail": "Access denied: You do not belong to this organization"
  }
  ```

- **404 Not Found** - Resource not found
  ```json
  {
    "detail": "Organization 550e8400-e29b-41d4-a716-446655440000 not found"
  }
  ```

- **409 Conflict** - Resource conflict (e.g., duplicate email, slug)
  ```json
  {
    "detail": "User with email 'user@example.com' already exists"
  }
  ```

- **422 Unprocessable Entity** - Validation error (Pydantic validation)
  ```json
  {
    "detail": [
      {
        "loc": ["body", "email"],
        "msg": "value is not a valid email address",
        "type": "value_error.email"
      }
    ]
  }
  ```

#### Server Error Codes

- **500 Internal Server Error** - Unexpected server error
  ```json
  {
    "detail": "Internal server error"
  }
  ```

### Common Error Scenarios

#### Authentication Errors

**Invalid credentials:**
```json
{
  "detail": "Incorrect email or password"
}
```

**Account disabled:**
```json
{
  "detail": "Account is disabled"
}
```

**Token expired:**
```json
{
  "detail": "Token has expired"
}
```

#### Authorization Errors

**Insufficient permissions:**
```json
{
  "detail": "Insufficient permissions: requires 'users:create'"
}
```

**Multi-tenant violation:**
```json
{
  "detail": "Access denied: You do not belong to this organization"
}
```

#### Resource Limit Errors

**User limit reached:**
```json
{
  "detail": "Organization has reached maximum users limit (50)"
}
```

**Team limit reached:**
```json
{
  "detail": "Organization has reached maximum teams limit (10)"
}
```

---

## Rate Limiting

### Rate Limit Headers

All API responses include rate limit headers:

```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1640995200
```

- `X-RateLimit-Limit` - Maximum requests allowed per window
- `X-RateLimit-Remaining` - Remaining requests in current window
- `X-RateLimit-Reset` - Unix timestamp when the limit resets

### Rate Limits by Plan

| Plan | Requests per Minute | Burst |
|------|---------------------|-------|
| Trial | 60 | 10 |
| Starter | 300 | 50 |
| Professional | 1000 | 100 |
| Enterprise | 5000 | 500 |

### Rate Limit Exceeded Response

**Status:** 429 Too Many Requests

```json
{
  "detail": "Rate limit exceeded. Retry after 60 seconds.",
  "retry_after": 60
}
```

**Headers:**
```
Retry-After: 60
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1640995200
```

### Best Practices

1. **Respect rate limits** - Monitor `X-RateLimit-Remaining` header
2. **Implement exponential backoff** - Wait before retrying after 429 errors
3. **Cache responses** - Reduce redundant API calls
4. **Use webhooks** - For event-driven updates instead of polling

---

## Complete Workflow Examples

### Example 1: User Registration and Login

This example demonstrates the complete flow from user registration to authenticated API access.

#### Step 1: Register a new user

```bash
curl -X POST https://auth.faultmaven.com/api/v1/enterprise/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "organization_id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "newuser@acme.com",
    "full_name": "Sarah Connor",
    "password": "SecurePassword123!"
  }'
```

**Response:**
```json
{
  "id": "750e8400-e29b-41d4-a716-446655440000",
  "email": "newuser@acme.com",
  "full_name": "Sarah Connor",
  "organization_id": "550e8400-e29b-41d4-a716-446655440000",
  "message": "User registered successfully. You can now login."
}
```

#### Step 2: Login to obtain tokens

```bash
curl -X POST https://auth.faultmaven.com/api/v1/enterprise/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "newuser@acme.com",
    "password": "SecurePassword123!"
  }'
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI3NTBlODQwMC1lMjliLTQxZDQtYTcxNi00NDY2NTU0NDAwMDAiLCJvcmdhbml6YXRpb25faWQiOiI1NTBlODQwMC1lMjliLTQxZDQtYTcxNi00NDY2NTU0NDAwMDAiLCJlbWFpbCI6Im5ld3VzZXJAYWNtZS5jb20iLCJ0eXBlIjoiYWNjZXNzIiwiZXhwIjoxNzAwMDAwMDAwfQ.signature",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI3NTBlODQwMC1lMjliLTQxZDQtYTcxNi00NDY2NTU0NDAwMDAiLCJ0eXBlIjoicmVmcmVzaCIsImV4cCI6MTcwMDAwMDAwMH0.signature",
  "token_type": "bearer",
  "expires_in": 1800
}
```

#### Step 3: Use access token to get user info

```bash
curl -X GET https://auth.faultmaven.com/api/v1/enterprise/auth/me \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

**Response:**
```json
{
  "id": "750e8400-e29b-41d4-a716-446655440000",
  "email": "newuser@acme.com",
  "full_name": "Sarah Connor",
  "organization_id": "550e8400-e29b-41d4-a716-446655440000",
  "team_id": null,
  "is_active": true,
  "is_verified": false,
  "sso_provider": null,
  "roles": [],
  "permissions": []
}
```

#### Step 4: Refresh access token when it expires

```bash
curl -X POST https://auth.faultmaven.com/api/v1/enterprise/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }'
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.NEW_TOKEN...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.NEW_REFRESH...",
  "token_type": "bearer",
  "expires_in": 1800
}
```

---

### Example 2: Organization Setup Workflow

This example shows how an admin sets up a complete organization with teams and users.

#### Step 1: Create organization

```bash
curl -X POST https://auth.faultmaven.com/api/v1/enterprise/organizations \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Acme Corporation",
    "slug": "acme-corp",
    "plan": "professional",
    "max_users": 50,
    "max_teams": 10
  }'
```

**Response:**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "Acme Corporation",
  "slug": "acme-corp",
  "plan": "professional",
  "is_active": true,
  "max_users": 50,
  "max_teams": 10,
  "contact_email": null,
  "contact_name": null
}
```

#### Step 2: Create teams

**Engineering Team:**
```bash
curl -X POST https://auth.faultmaven.com/api/v1/enterprise/teams \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "organization_id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "Engineering",
    "slug": "engineering",
    "description": "Engineering and development team"
  }'
```

**Response:**
```json
{
  "id": "650e8400-e29b-41d4-a716-446655440000",
  "organization_id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "Engineering",
  "slug": "engineering",
  "description": "Engineering and development team"
}
```

**Product Team:**
```bash
curl -X POST https://auth.faultmaven.com/api/v1/enterprise/teams \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "organization_id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "Product",
    "slug": "product",
    "description": "Product management team"
  }'
```

**Response:**
```json
{
  "id": "660e8400-e29b-41d4-a716-446655440000",
  "organization_id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "Product",
  "slug": "product",
  "description": "Product management team"
}
```

#### Step 3: Create users

**Engineering User:**
```bash
curl -X POST https://auth.faultmaven.com/api/v1/enterprise/users \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "organization_id": "550e8400-e29b-41d4-a716-446655440000",
    "team_id": "650e8400-e29b-41d4-a716-446655440000",
    "email": "engineer@acme.com",
    "full_name": "Alice Johnson",
    "password": "EngineerPass123!"
  }'
```

**Product User:**
```bash
curl -X POST https://auth.faultmaven.com/api/v1/enterprise/users \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "organization_id": "550e8400-e29b-41d4-a716-446655440000",
    "team_id": "660e8400-e29b-41d4-a716-446655440000",
    "email": "product@acme.com",
    "full_name": "Bob Smith",
    "password": "ProductPass123!"
  }'
```

#### Step 4: List all organization users

```bash
curl -X GET https://auth.faultmaven.com/api/v1/enterprise/users/organization/550e8400-e29b-41d4-a716-446655440000 \
  -H "Authorization: Bearer <admin_token>"
```

**Response:**
```json
[
  {
    "id": "750e8400-e29b-41d4-a716-446655440000",
    "organization_id": "550e8400-e29b-41d4-a716-446655440000",
    "team_id": "650e8400-e29b-41d4-a716-446655440000",
    "email": "engineer@acme.com",
    "full_name": "Alice Johnson",
    "is_active": true,
    "is_verified": false,
    "sso_provider": null
  },
  {
    "id": "760e8400-e29b-41d4-a716-446655440000",
    "organization_id": "550e8400-e29b-41d4-a716-446655440000",
    "team_id": "660e8400-e29b-41d4-a716-446655440000",
    "email": "product@acme.com",
    "full_name": "Bob Smith",
    "is_active": true,
    "is_verified": false,
    "sso_provider": null
  }
]
```

---

### Example 3: SSO Configuration Workflow

This example demonstrates setting up SAML SSO with Okta.

#### Step 1: Create SAML SSO configuration

```bash
curl -X POST https://auth.faultmaven.com/api/v1/enterprise/sso \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "organization_id": "550e8400-e29b-41d4-a716-446655440000",
    "provider_type": "saml",
    "provider_name": "Okta SAML",
    "is_enabled": true,
    "saml_entity_id": "http://www.okta.com/exk1234567890",
    "saml_sso_url": "https://acme.okta.com/app/faultmaven/sso/saml",
    "saml_x509_cert": "-----BEGIN CERTIFICATE-----\nMIIDpDCCAoygAwIBAgIGAX...\n-----END CERTIFICATE-----",
    "attribute_mapping": {
      "email": "email",
      "full_name": "displayName"
    },
    "auto_create_users": true
  }'
```

**Response:**
```json
{
  "id": "850e8400-e29b-41d4-a716-446655440000",
  "organization_id": "550e8400-e29b-41d4-a716-446655440000",
  "provider_type": "saml",
  "provider_name": "Okta SAML",
  "is_enabled": true,
  "auto_create_users": true,
  "saml_entity_id": "http://www.okta.com/exk1234567890",
  "saml_sso_url": "https://acme.okta.com/app/faultmaven/sso/saml",
  "oauth_client_id": null,
  "oauth_authorization_url": null,
  "oidc_issuer": null
}
```

#### Step 2: Verify SSO configuration

```bash
curl -X GET https://auth.faultmaven.com/api/v1/enterprise/sso/850e8400-e29b-41d4-a716-446655440000 \
  -H "Authorization: Bearer <admin_token>"
```

#### Step 3: Update SSO configuration

```bash
curl -X PUT https://auth.faultmaven.com/api/v1/enterprise/sso/850e8400-e29b-41d4-a716-446655440000 \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "provider_name": "Okta SAML (Production)",
    "is_enabled": true
  }'
```

#### Step 4: List all SSO configurations

```bash
curl -X GET https://auth.faultmaven.com/api/v1/enterprise/sso/organization/550e8400-e29b-41d4-a716-446655440000 \
  -H "Authorization: Bearer <admin_token>"
```

---

### Example 4: Team Management Workflow

This example shows team-based user management.

#### Step 1: Create a team

```bash
curl -X POST https://auth.faultmaven.com/api/v1/enterprise/teams \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "organization_id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "DevOps",
    "slug": "devops",
    "description": "DevOps and infrastructure team"
  }'
```

**Response:**
```json
{
  "id": "670e8400-e29b-41d4-a716-446655440000",
  "organization_id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "DevOps",
  "slug": "devops",
  "description": "DevOps and infrastructure team"
}
```

#### Step 2: Add user to team

```bash
curl -X PUT https://auth.faultmaven.com/api/v1/enterprise/users/750e8400-e29b-41d4-a716-446655440000 \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "team_id": "670e8400-e29b-41d4-a716-446655440000"
  }'
```

#### Step 3: List team members

```bash
curl -X GET "https://auth.faultmaven.com/api/v1/enterprise/users/organization/550e8400-e29b-41d4-a716-446655440000?team_id=670e8400-e29b-41d4-a716-446655440000" \
  -H "Authorization: Bearer <admin_token>"
```

#### Step 4: Update team details

```bash
curl -X PUT https://auth.faultmaven.com/api/v1/enterprise/teams/670e8400-e29b-41d4-a716-446655440000 \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "DevOps & SRE",
    "description": "DevOps, infrastructure, and site reliability engineering"
  }'
```

---

## Postman Collection

### Importing the Collection

You can use this API with Postman by creating a collection with the following structure:

#### Environment Variables

Create a Postman environment with these variables:

```json
{
  "base_url": "https://auth.faultmaven.com",
  "access_token": "",
  "refresh_token": "",
  "organization_id": "",
  "team_id": "",
  "user_id": ""
}
```

#### Collection Structure

**FaultMaven Auth API**
- **Authentication**
  - POST Login
  - POST Refresh Token
  - POST Logout
  - POST Register
  - GET Me
- **Organizations**
  - POST Create Organization
  - GET List Organizations
  - GET Get Organization
  - PUT Update Organization
  - DELETE Delete Organization
- **Teams**
  - POST Create Team
  - GET List Organization Teams
  - GET Get Team
  - PUT Update Team
  - DELETE Delete Team
- **Users**
  - POST Create User
  - GET List Organization Users
  - GET Get User
  - PUT Update User
  - DELETE Delete User
- **SSO**
  - POST Create SSO Configuration
  - GET List Organization SSO Configs
  - GET Get SSO Configuration
  - PUT Update SSO Configuration
  - DELETE Delete SSO Configuration

#### Auto-Setting Tokens

Add this to the **Tests** tab of the Login and Refresh endpoints:

```javascript
// Save tokens to environment
var jsonData = pm.response.json();
pm.environment.set("access_token", jsonData.access_token);
pm.environment.set("refresh_token", jsonData.refresh_token);
```

#### Authorization Header

For all authenticated endpoints, use:

**Type:** Bearer Token
**Token:** `{{access_token}}`

Or manually set the header:
```
Authorization: Bearer {{access_token}}
```

### Sample Postman Request: Login

**Method:** POST
**URL:** `{{base_url}}/api/v1/enterprise/auth/login`

**Headers:**
```
Content-Type: application/json
```

**Body (raw JSON):**
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!"
}
```

**Tests:**
```javascript
pm.test("Status code is 200", function () {
    pm.response.to.have.status(200);
});

pm.test("Response has access_token", function () {
    var jsonData = pm.response.json();
    pm.expect(jsonData.access_token).to.be.a('string');
});

// Save tokens
var jsonData = pm.response.json();
pm.environment.set("access_token", jsonData.access_token);
pm.environment.set("refresh_token", jsonData.refresh_token);
```

---

## Summary

This API reference documents all 25 endpoints across 5 categories:

### Endpoint Count by Category

- **Authentication:** 5 endpoints (login, refresh, logout, register, me)
- **Organizations:** 5 endpoints (create, list, get, update, delete)
- **Teams:** 5 endpoints (create, list, get, update, delete)
- **Users:** 5 endpoints (create, list, get, update, delete)
- **SSO Configuration:** 5 endpoints (create, list, get, update, delete)

### Key Features

- Multi-tenant architecture with strict organization isolation
- JWT-based authentication with access and refresh tokens
- Role-Based Access Control (RBAC) with fine-grained permissions
- SSO support for SAML, OAuth 2.0, and OpenID Connect
- Soft deletion for data recovery and audit trails
- Comprehensive error handling and validation
- Rate limiting based on subscription plan

### Getting Started

1. Register a new user or login with existing credentials
2. Use the access token in the Authorization header for all authenticated requests
3. Refresh tokens before they expire to maintain session
4. Explore organization, team, and user management endpoints
5. Configure SSO for enterprise authentication

For questions or support, contact: support@faultmaven.com
