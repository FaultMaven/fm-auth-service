# Service-to-Service Authentication Design

> **⚠️ DEPRECATED**: This authentication system was removed on 2025-12-07
>
> **Reason**: The implementation was broken (services never received JWT tokens) and added unnecessary complexity. All services now trust X-User-* headers from the API Gateway, which already validates user JWTs and sanitizes incoming headers to prevent injection attacks.
>
> **Current Architecture**: See [API Gateway Authentication](../fm-api-gateway/README.md) for the simplified authentication model.

---

## Overview

This document describes the JWT-based service-to-service authentication system that was previously implemented for FaultMaven microservices to resolve 401 Unauthorized errors when services communicate with each other.

## Problem Statement

When `fm-agent-service` attempts to call `fm-case-service` APIs, it receives 401 Unauthorized errors because:
1. `fm-case-service` uses `ServiceAuthMiddleware` from `fm-core-lib` to validate incoming requests
2. The middleware requires valid JWT tokens with proper service permissions
3. `fm-agent-service` was not generating or sending these tokens

## Architecture

### Components

```
┌─────────────────────┐
│  fm-auth-service    │
│  (Token Issuer)     │
│                     │
│ • Issues Service    │
│   JWT Tokens        │
│ • Manages RSA Keys  │
│ • Defines Perms     │
└──────────┬──────────┘
           │
           │ 1. Request Token
           │    POST /api/v1/service-auth/token
           ↓
┌─────────────────────┐         2. Call API          ┌─────────────────────┐
│  fm-agent-service   │────────with JWT Token──────→│  fm-case-service    │
│  (Service Client)   │                              │  (Protected API)    │
│                     │                              │                     │
│ • Obtains tokens    │                              │ • Validates tokens  │
│ • Sends in headers  │                              │ • Checks perms      │
└─────────────────────┘                              └─────────────────────┘
```

### Token Flow

1. **Token Issuance** (fm-auth-service):
   - Generates JWT tokens signed with RSA-256 private key
   - Token contains: service_id, audience, permissions, expiry
   - Default TTL: 3600 seconds (1 hour)

2. **Token Validation** (fm-case-service):
   - Receives token in `Authorization: Bearer <token>` header
   - Validates using RSA-256 public key
   - Checks issuer, audience, expiry, and permissions

3. **Token Caching** (fm-agent-service):
   - Caches tokens until expiry
   - Auto-refreshes when expired
   - Reduces load on auth service

## Implementation Details

### 1. RSA Key Pair Generation

**Location**: `fm-auth-service/config/`

```bash
# Generate private key (2048-bit RSA)
openssl genrsa -out service-private-key.pem 2048

# Extract public key
openssl rsa -in service-private-key.pem -pubout -out service-public-key.pem
```

**Key Management**:
- Private key: Only on `fm-auth-service` (never shared)
- Public key: Distributed to all consuming services
- Keys mounted via Docker volumes to `/app/config/`

### 2. Service Permissions Configuration

**File**: `fm-auth-service/config/service-permissions.yml`

```yaml
services:
  fm-agent-service:
    - "case:read"
    - "case:write"
    - "case:delete"

  fm-api-gateway:
    - "case:read"
    - "session:read"
    - "session:write"
```

**Permission Format**: `resource:action`
- Resources: case, session, knowledge, evidence
- Actions: read, write, delete

### 3. Token Structure

**JWT Claims**:
```json
{
  "service_id": "fm-agent-service",
  "aud": ["faultmaven-api"],
  "iss": "fm-auth-service",
  "permissions": ["case:read", "case:write", "case:delete"],
  "iat": 1732704000,
  "exp": 1732707600
}
```

**Header**:
```json
{
  "alg": "RS256",
  "typ": "JWT"
}
```

### 4. API Endpoints

#### fm-auth-service

**POST /api/v1/service-auth/token**
- **Purpose**: Issue service JWT token
- **Request Body**:
  ```json
  {
    "service_id": "fm-agent-service",
    "audience": ["faultmaven-api"],
    "ttl_seconds": 3600
  }
  ```
- **Response**:
  ```json
  {
    "access_token": "eyJhbGc...",
    "token_type": "Bearer",
    "expires_in": 3600,
    "service_id": "fm-agent-service",
    "permissions": ["case:read", "case:write"]
  }
  ```

**GET /.well-known/jwks.json**
- **Purpose**: Public key discovery (JWKS format)
- **Response**:
  ```json
  {
    "keys": [{
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "n": "base64-encoded-modulus",
      "e": "AQAB"
    }]
  }
  ```

### 5. Client Integration (fm-agent-service)

**Authentication Setup**:
```python
from fm_core_lib.auth import ServiceAuthClient

# Initialize client
auth_client = ServiceAuthClient(
    auth_service_url="http://fm-auth-service:8001",
    service_id="fm-agent-service",
    audience=["faultmaven-api"]
)

# Get token (cached automatically)
token = await auth_client.get_token()

# Make authenticated request
headers = {"Authorization": f"Bearer {token}"}
response = await httpx.get("http://fm-case-service:8003/api/v1/cases", headers=headers)
```

### 6. Server Integration (fm-case-service)

**Middleware Setup**:
```python
from fm_core_lib.auth import ServiceAuthMiddleware
from pathlib import Path

# Load public key
with open("/app/config/service-public-key.pem", "r") as f:
    public_key = f.read()

# Add middleware
app.add_middleware(
    ServiceAuthMiddleware,
    public_key=public_key,
    jwt_algorithm="RS256",
    jwt_audience="faultmaven-api",
    jwt_issuer="fm-auth-service",
    skip_paths=["/health", "/docs", "/openapi.json"]
)
```

**Access Control**:
```python
from fm_core_lib.auth import require_permission

@router.post("/cases")
@require_permission("case:write")
async def create_case(request: Request, data: CaseCreate):
    # Middleware validates token and checks permission
    # If valid, service_context available in request.state
    service_id = request.state.service_context.service_id
    permissions = request.state.service_context.permissions

    # Create case...
```

## Security Considerations

### 1. Key Security
- **Private Key Protection**:
  - Never commit to version control
  - Mount via Docker secrets/volumes
  - Restrict file permissions (600)
  - Rotate periodically (recommend: 90 days)

- **Public Key Distribution**:
  - Can be publicly accessible
  - Serve via JWKS endpoint for auto-discovery
  - Version keys if rotation needed

### 2. Token Security
- **Short-lived tokens**: Default 1 hour TTL
- **Audience validation**: Prevents token reuse across systems
- **Issuer validation**: Ensures tokens from trusted source
- **Signature verification**: RS256 cryptographic validation

### 3. Permission Model
- **Principle of Least Privilege**: Grant minimum required permissions
- **Explicit Allow**: No default permissions
- **Deny by Default**: Missing permissions = 403 Forbidden

### 4. Transport Security
- **HTTPS Required**: In production, all service communication over TLS
- **Internal Network**: Services communicate within private network
- **No Token Logging**: Never log tokens in plaintext

## Deployment Configuration

### Docker Compose

**fm-auth-service**:
```yaml
services:
  fm-auth-service:
    volumes:
      - ./config/service-private-key.pem:/app/config/service-private-key.pem:ro
      - ./config/service-permissions.yml:/app/config/service-permissions.yml:ro
    environment:
      - SERVICE_PRIVATE_KEY_PATH=/app/config/service-private-key.pem
      - SERVICE_PERMISSIONS_CONFIG_PATH=/app/config/service-permissions.yml
      - SERVICE_TOKEN_ISSUER=fm-auth-service
      - SERVICE_TOKEN_TTL_SECONDS=3600
```

**fm-case-service**:
```yaml
services:
  fm-case-service:
    volumes:
      - ./config/service-public-key.pem:/app/config/service-public-key.pem:ro
    environment:
      - AUTH_SERVICE_URL=http://fm-auth-service:8001
```

**fm-agent-service**:
```yaml
services:
  fm-agent-service:
    environment:
      - AUTH_SERVICE_URL=http://fm-auth-service:8001
      - SERVICE_ID=fm-agent-service
```

## Testing

### 1. Token Issuance Test

```bash
# Request token
curl -X POST http://localhost:8001/api/v1/service-auth/token \
  -H "Content-Type: application/json" \
  -d '{
    "service_id": "fm-agent-service",
    "audience": ["faultmaven-api"]
  }'
```

### 2. Token Validation Test

```bash
# Use token to call protected endpoint
TOKEN="eyJhbGc..."
curl http://localhost:8003/api/v1/cases \
  -H "Authorization: Bearer $TOKEN"
```

### 3. Permission Validation Test

```bash
# Should succeed (has case:read permission)
curl http://localhost:8003/api/v1/cases \
  -H "Authorization: Bearer $TOKEN"

# Should fail 403 (lacks evidence:read permission)
curl http://localhost:8004/api/v1/evidence \
  -H "Authorization: Bearer $TOKEN"
```

## Troubleshooting

### Common Issues

#### 1. 401 Unauthorized
**Symptoms**: Service receives 401 when calling another service
**Causes**:
- No token in Authorization header
- Invalid token signature
- Expired token
- Wrong issuer/audience

**Solution**:
```python
# Enable debug logging
import logging
logging.getLogger("fm_core_lib.auth").setLevel(logging.DEBUG)

# Check token claims
import jwt
decoded = jwt.decode(token, options={"verify_signature": False})
print(decoded)
```

#### 2. 403 Forbidden
**Symptoms**: Token validates but request denied
**Causes**:
- Missing required permission
- Service not in permissions config

**Solution**:
1. Check service-permissions.yml
2. Verify service_id matches
3. Add required permission
4. Restart fm-auth-service

#### 3. Token Not Refreshing
**Symptoms**: Requests fail after 1 hour
**Causes**:
- Client not caching/refreshing token
- Auth service unavailable

**Solution**:
```python
# ServiceAuthClient auto-refreshes
# Check auth service connectivity
response = await httpx.get("http://fm-auth-service:8001/health")
print(response.json())
```

## Migration Path

### Phase 1: Authentication Service ✅
- [x] Generate RSA key pair
- [x] Implement token issuance endpoint
- [x] Implement JWKS endpoint
- [x] Configure service permissions
- [x] Deploy fm-auth-service

### Phase 2: Core Library Updates ✅
- [x] Implement ServiceAuthClient (token client)
- [x] Implement ServiceAuthMiddleware (validation)
- [x] Add permission decorators
- [x] Publish fm-core-lib v1.1.0

### Phase 3: Service Integration (In Progress)
- [x] Update fm-case-service with middleware
- [ ] Update fm-agent-service with client
- [ ] Update fm-session-service
- [ ] Update fm-knowledge-service
- [ ] Update fm-evidence-service
- [ ] Update fm-api-gateway

### Phase 4: Production Hardening (Pending)
- [ ] Implement key rotation
- [ ] Add token revocation
- [ ] Implement rate limiting
- [ ] Add audit logging
- [ ] Performance optimization

## Performance Considerations

### Token Caching
- **Client-side**: Tokens cached until expiry
- **Reduces**: Auth service load
- **Memory**: ~1KB per cached token

### Token Size
- **Typical Size**: 800-1200 bytes
- **Network Impact**: Minimal (<2KB per request)
- **Optimization**: Keep permissions list concise

### Validation Performance
- **Public Key Caching**: Key loaded once at startup
- **Signature Verification**: ~0.5ms per request
- **Permission Check**: ~0.01ms (in-memory)

## Future Enhancements

### 1. Token Revocation
- Implement revocation list (Redis)
- Check on validation
- Support immediate revocation

### 2. Key Rotation
- Support multiple public keys (kid claim)
- Gradual key rollover
- Automated rotation schedule

### 3. Advanced Permissions
- Resource-level permissions (e.g., case:123:read)
- Conditional permissions (time-based, IP-based)
- Permission inheritance

### 4. Observability
- Token issuance metrics
- Validation failure tracking
- Permission denial analytics
- Distributed tracing integration

## References

### Standards
- [RFC 7519](https://tools.ietf.org/html/rfc7519) - JSON Web Token (JWT)
- [RFC 7517](https://tools.ietf.org/html/rfc7517) - JSON Web Key (JWK)
- [RFC 7518](https://tools.ietf.org/html/rfc7518) - JSON Web Algorithms (JWA)

### Libraries
- `PyJWT` - JWT encoding/decoding
- `cryptography` - RSA key operations
- `fm-core-lib` - FaultMaven authentication library

### Documentation
- fm-core-lib: `/home/swhouse/product/fm-core-lib/README.md`
- fm-auth-service: `/home/swhouse/product/fm-auth-service/README.md`
- Service Auth API: `http://localhost:8001/docs`

---

**Document Version**: 1.0
**Last Updated**: 2025-11-27
**Author**: Claude (AI Assistant)
**Status**: Implementation Complete - Testing Pending
