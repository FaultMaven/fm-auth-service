# FaultMaven Auth Service - Enterprise Edition
## Monitoring & Logging Setup Guide

This guide provides comprehensive instructions for setting up monitoring, logging, and observability for the FaultMaven Auth Service in production environments.

---

## Table of Contents

- [Overview](#overview)
- [Observability Stack](#observability-stack)
- [Metrics](#metrics)
  - [Application Metrics](#application-metrics)
  - [Infrastructure Metrics](#infrastructure-metrics)
  - [Business Metrics](#business-metrics)
- [Logging](#logging)
  - [Log Levels](#log-levels)
  - [Structured Logging](#structured-logging)
  - [Log Aggregation](#log-aggregation)
- [Tracing](#tracing)
- [Alerting](#alerting)
- [Dashboards](#dashboards)
- [Health Checks](#health-checks)
- [Performance Monitoring](#performance-monitoring)
- [Security Monitoring](#security-monitoring)
- [Incident Response](#incident-response)

---

## Overview

### Observability Pillars

The three pillars of observability for the Auth Service:

1. **Metrics** - Time-series data for trends and alerting (Prometheus + Grafana)
2. **Logs** - Detailed event records for debugging (ELK/Loki)
3. **Traces** - Distributed request tracking (Jaeger/Tempo)

### Monitoring Goals

- **Availability**: 99.9% uptime SLA
- **Performance**: p95 latency < 200ms
- **Security**: Real-time threat detection
- **Business**: Authentication success rates, user activity

---

## Observability Stack

### Recommended Stack

```mermaid
graph TB
    A[Auth Service] --> B[Prometheus]
    A --> C[Loki/ELK]
    A --> D[Jaeger/Tempo]
    B --> E[Grafana]
    C --> E
    D --> E
    E --> F[AlertManager]
    F --> G[PagerDuty/Slack]
```

**Components:**

| Component | Purpose | Technology |
|-----------|---------|------------|
| Metrics Collection | Time-series data | Prometheus |
| Metrics Visualization | Dashboards & graphs | Grafana |
| Log Aggregation | Centralized logging | ELK Stack / Loki |
| Distributed Tracing | Request flow tracking | Jaeger / Tempo |
| Alerting | Incident notification | AlertManager + PagerDuty |

### Alternative Stacks

**Cloud-Native:**
- AWS: CloudWatch + X-Ray
- GCP: Cloud Monitoring + Cloud Trace
- Azure: Azure Monitor + Application Insights

**Commercial SaaS:**
- Datadog (all-in-one)
- New Relic (all-in-one)
- Sentry (error tracking)

---

## Metrics

### Application Metrics

#### FastAPI Metrics

Install Prometheus client:

```bash
pip install prometheus-fastapi-instrumentator
```

Add to `enterprise/main.py`:

```python
from prometheus_fastapi_instrumentator import Instrumentator

# Create app
app = FastAPI(...)

# Add Prometheus instrumentation
Instrumentator().instrument(app).expose(app)
```

**Automatic Metrics:**

```promql
# Request rate
rate(http_requests_total[5m])

# Request latency (p50, p95, p99)
histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))

# Error rate
rate(http_requests_total{status=~"5.."}[5m])

# Active requests
http_requests_inprogress
```

#### Custom Business Metrics

Add to `enterprise/observability/metrics.py`:

```python
from prometheus_client import Counter, Histogram, Gauge

# Authentication metrics
auth_attempts_total = Counter(
    'auth_attempts_total',
    'Total authentication attempts',
    ['method', 'status']  # labels: password/saml/oauth, success/failure
)

auth_duration_seconds = Histogram(
    'auth_duration_seconds',
    'Authentication request duration',
    ['method']
)

# Token metrics
tokens_generated_total = Counter(
    'tokens_generated_total',
    'Total JWT tokens generated',
    ['token_type']  # access/refresh
)

tokens_validated_total = Counter(
    'tokens_validated_total',
    'Total token validation attempts',
    ['status']  # success/failure/expired
)

# User metrics
active_users_gauge = Gauge(
    'active_users_total',
    'Number of active users',
    ['organization_id']
)

# Organization metrics
organizations_total = Gauge(
    'organizations_total',
    'Total number of organizations'
)

# SSO metrics
sso_attempts_total = Counter(
    'sso_attempts_total',
    'Total SSO authentication attempts',
    ['provider_type', 'status']
)
```

Usage in code:

```python
from enterprise.observability.metrics import auth_attempts_total, auth_duration_seconds

@router.post("/login")
async def login(login_data: LoginRequest):
    start_time = time.time()

    try:
        # Authenticate user
        user = await authenticate_user(login_data.email, login_data.password)

        # Generate tokens
        access_token = create_access_token(...)

        # Record success
        auth_attempts_total.labels(method='password', status='success').inc()

        return {"access_token": access_token}

    except AuthenticationError:
        auth_attempts_total.labels(method='password', status='failure').inc()
        raise HTTPException(status_code=401)

    finally:
        duration = time.time() - start_time
        auth_duration_seconds.labels(method='password').observe(duration)
```

#### Database Metrics

```python
from sqlalchemy import event
from prometheus_client import Counter, Histogram

db_queries_total = Counter('db_queries_total', 'Total database queries', ['operation'])
db_query_duration_seconds = Histogram('db_query_duration_seconds', 'Database query duration')

@event.listens_for(Engine, "before_cursor_execute")
def receive_before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
    context._query_start_time = time.time()

@event.listens_for(Engine, "after_cursor_execute")
def receive_after_cursor_execute(conn, cursor, statement, parameters, context, executemany):
    duration = time.time() - context._query_start_time
    db_query_duration_seconds.observe(duration)

    operation = statement.split()[0].upper()  # SELECT, INSERT, UPDATE, DELETE
    db_queries_total.labels(operation=operation).inc()
```

### Infrastructure Metrics

#### PostgreSQL Metrics

**Prometheus Postgres Exporter:**

```yaml
# docker-compose.yml
services:
  postgres-exporter:
    image: prometheuscommunity/postgres-exporter
    environment:
      DATA_SOURCE_NAME: "postgresql://user:password@postgres:5432/faultmaven_auth?sslmode=disable"
    ports:
      - "9187:9187"
```

**Key Metrics:**

```promql
# Connection pool usage
pg_stat_database_numbackends

# Active queries
pg_stat_activity_count

# Database size
pg_database_size_bytes

# Transaction rate
rate(pg_stat_database_xact_commit[5m])

# Cache hit ratio
pg_stat_database_blks_hit / (pg_stat_database_blks_hit + pg_stat_database_blks_read)

# Replication lag
pg_replication_lag_seconds
```

#### Redis Metrics

**Redis Exporter:**

```yaml
# docker-compose.yml
services:
  redis-exporter:
    image: oliver006/redis_exporter
    environment:
      REDIS_ADDR: "redis:6379"
      REDIS_PASSWORD: "${REDIS_PASSWORD}"
    ports:
      - "9121:9121"
```

**Key Metrics:**

```promql
# Memory usage
redis_memory_used_bytes / redis_memory_max_bytes

# Connected clients
redis_connected_clients

# Commands per second
rate(redis_commands_processed_total[1m])

# Hit rate
rate(redis_keyspace_hits_total[5m]) / (rate(redis_keyspace_hits_total[5m]) + rate(redis_keyspace_misses_total[5m]))

# Evicted keys
rate(redis_evicted_keys_total[5m])
```

#### Kubernetes Metrics (if applicable)

```promql
# Pod CPU usage
rate(container_cpu_usage_seconds_total{pod=~"auth-service-.*"}[5m])

# Pod memory usage
container_memory_working_set_bytes{pod=~"auth-service-.*"}

# Pod restarts
kube_pod_container_status_restarts_total{pod=~"auth-service-.*"}

# Pod availability
kube_pod_status_ready{pod=~"auth-service-.*"}
```

### Business Metrics

Track KPIs and business outcomes:

```python
# User growth
new_users_total = Counter('new_users_total', 'New user registrations', ['organization_id'])

# Authentication success rate
auth_success_rate = Gauge('auth_success_rate', 'Authentication success rate (last 5m)')

# Average session duration
session_duration_seconds = Histogram('session_duration_seconds', 'User session duration')

# Organization churn
organizations_deleted_total = Counter('organizations_deleted_total', 'Organizations deleted')

# API usage by endpoint
api_calls_by_endpoint = Counter('api_calls_by_endpoint', 'API calls by endpoint', ['endpoint', 'method'])
```

---

## Logging

### Log Levels

Use appropriate log levels:

- **DEBUG**: Detailed diagnostic information (disabled in production)
- **INFO**: General informational messages (user actions, API calls)
- **WARNING**: Warning messages (degraded performance, deprecated features)
- **ERROR**: Error messages (handled exceptions, failed operations)
- **CRITICAL**: Critical issues (system failures, data corruption)

### Structured Logging

Configure structured JSON logging in `enterprise/config/logging.py`:

```python
import logging
import json
import sys
from datetime import datetime
from typing import Any, Dict

class JSONFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging."""

    def format(self, record: logging.LogRecord) -> str:
        log_data: Dict[str, Any] = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "service": "fm-auth-service-enterprise",
            "environment": os.getenv("ENVIRONMENT", "development"),
        }

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = {
                "type": record.exc_info[0].__name__,
                "message": str(record.exc_info[1]),
                "traceback": self.formatException(record.exc_info)
            }

        # Add extra fields
        if hasattr(record, "user_id"):
            log_data["user_id"] = record.user_id
        if hasattr(record, "organization_id"):
            log_data["organization_id"] = record.organization_id
        if hasattr(record, "request_id"):
            log_data["request_id"] = record.request_id
        if hasattr(record, "endpoint"):
            log_data["endpoint"] = record.endpoint
        if hasattr(record, "method"):
            log_data["method"] = record.method
        if hasattr(record, "status_code"):
            log_data["status_code"] = record.status_code
        if hasattr(record, "duration_ms"):
            log_data["duration_ms"] = record.duration_ms

        return json.dumps(log_data)


def configure_logging():
    """Configure application logging."""
    log_level = os.getenv("LOG_LEVEL", "INFO")

    # Create handler
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JSONFormatter())

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    root_logger.addHandler(handler)

    # Set third-party library log levels
    logging.getLogger("uvicorn").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
```

### Request Logging Middleware

Add request/response logging middleware in `enterprise/middleware/logging.py`:

```python
import time
import uuid
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
import logging

logger = logging.getLogger(__name__)

class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware to log all HTTP requests and responses."""

    async def dispatch(self, request: Request, call_next):
        # Generate request ID
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id

        # Start timer
        start_time = time.time()

        # Log request
        logger.info(
            f"Request started: {request.method} {request.url.path}",
            extra={
                "request_id": request_id,
                "endpoint": request.url.path,
                "method": request.method,
                "client_ip": request.client.host if request.client else None,
                "user_agent": request.headers.get("user-agent"),
            }
        )

        # Process request
        response = await call_next(request)

        # Calculate duration
        duration_ms = (time.time() - start_time) * 1000

        # Log response
        logger.info(
            f"Request completed: {request.method} {request.url.path}",
            extra={
                "request_id": request_id,
                "endpoint": request.url.path,
                "method": request.method,
                "status_code": response.status_code,
                "duration_ms": round(duration_ms, 2),
            }
        )

        # Add request ID to response headers
        response.headers["X-Request-ID"] = request_id

        return response
```

Register middleware in `enterprise/main.py`:

```python
from enterprise.middleware.logging import RequestLoggingMiddleware

app.add_middleware(RequestLoggingMiddleware)
```

### Application Logging Examples

```python
import logging

logger = logging.getLogger(__name__)

# User login
logger.info(
    "User login successful",
    extra={
        "user_id": str(user.id),
        "organization_id": str(user.organization_id),
        "auth_method": "password"
    }
)

# Failed authentication
logger.warning(
    "Authentication failed - invalid credentials",
    extra={
        "email": login_data.email,
        "reason": "invalid_password"
    }
)

# Error handling
try:
    await db.commit()
except Exception as e:
    logger.error(
        "Database commit failed",
        exc_info=True,
        extra={
            "user_id": str(user.id),
            "operation": "user_creation"
        }
    )
    raise
```

### Log Aggregation

#### ELK Stack (Elasticsearch, Logstash, Kibana)

**Docker Compose:**

```yaml
version: '3.8'

services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.10.0
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
    ports:
      - "9200:9200"
    volumes:
      - es_data:/usr/share/elasticsearch/data

  logstash:
    image: docker.elastic.co/logstash/logstash:8.10.0
    volumes:
      - ./logstash/logstash.conf:/usr/share/logstash/pipeline/logstash.conf
    ports:
      - "5000:5000"
    depends_on:
      - elasticsearch

  kibana:
    image: docker.elastic.co/kibana/kibana:8.10.0
    ports:
      - "5601:5601"
    depends_on:
      - elasticsearch
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200

volumes:
  es_data:
```

**Logstash Configuration** (`logstash/logstash.conf`):

```conf
input {
  tcp {
    port => 5000
    codec => json_lines
  }
}

filter {
  # Parse JSON logs
  json {
    source => "message"
  }

  # Add geoip for client IPs
  if [client_ip] {
    geoip {
      source => "client_ip"
    }
  }
}

output {
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    index => "auth-service-%{+YYYY.MM.dd}"
  }
}
```

**Send logs to Logstash:**

```python
import logging
from logstash_async.handler import AsynchronousLogstashHandler

logstash_handler = AsynchronousLogstashHandler(
    host='logstash',
    port=5000,
    database_path='/tmp/logstash.db'
)

logger.addHandler(logstash_handler)
```

#### Grafana Loki (Alternative)

**Docker Compose:**

```yaml
services:
  loki:
    image: grafana/loki:2.9.0
    ports:
      - "3100:3100"
    volumes:
      - ./loki/loki-config.yaml:/etc/loki/local-config.yaml
    command: -config.file=/etc/loki/local-config.yaml

  promtail:
    image: grafana/promtail:2.9.0
    volumes:
      - /var/log:/var/log
      - ./promtail/promtail-config.yaml:/etc/promtail/config.yml
    command: -config.file=/etc/promtail/config.yml
```

---

## Tracing

### OpenTelemetry Setup

Install dependencies:

```bash
pip install opentelemetry-api opentelemetry-sdk opentelemetry-instrumentation-fastapi opentelemetry-exporter-jaeger
```

Configure tracing in `enterprise/observability/tracing.py`:

```python
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.jaeger.thrift import JaegerExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor

def configure_tracing(app: FastAPI):
    """Configure OpenTelemetry tracing."""

    # Create tracer provider
    trace.set_tracer_provider(TracerProvider())
    tracer = trace.get_tracer(__name__)

    # Configure Jaeger exporter
    jaeger_exporter = JaegerExporter(
        agent_host_name=os.getenv("JAEGER_HOST", "localhost"),
        agent_port=int(os.getenv("JAEGER_PORT", "6831")),
    )

    # Add span processor
    trace.get_tracer_provider().add_span_processor(
        BatchSpanProcessor(jaeger_exporter)
    )

    # Instrument FastAPI
    FastAPIInstrumentor.instrument_app(app)

    # Instrument SQLAlchemy
    SQLAlchemyInstrumentor().instrument()

    return tracer
```

Register in `enterprise/main.py`:

```python
from enterprise.observability.tracing import configure_tracing

tracer = configure_tracing(app)
```

**Custom Spans:**

```python
from opentelemetry import trace

tracer = trace.get_tracer(__name__)

async def authenticate_user(email: str, password: str):
    with tracer.start_as_current_span("authenticate_user") as span:
        span.set_attribute("email", email)

        # Find user
        with tracer.start_as_current_span("db_query_user"):
            user = await db.execute(...)

        # Verify password
        with tracer.start_as_current_span("verify_password"):
            is_valid = verify_password(password, user.hashed_password)

        span.set_attribute("auth_success", is_valid)
        return user if is_valid else None
```

---

## Alerting

### AlertManager Configuration

**Prometheus AlertManager** (`alertmanager.yml`):

```yaml
global:
  resolve_timeout: 5m

route:
  group_by: ['alertname', 'cluster', 'service']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 12h
  receiver: 'pagerduty'
  routes:
  - match:
      severity: critical
    receiver: pagerduty
  - match:
      severity: warning
    receiver: slack

receivers:
- name: 'pagerduty'
  pagerduty_configs:
  - service_key: '<PAGERDUTY_KEY>'

- name: 'slack'
  slack_configs:
  - api_url: '<SLACK_WEBHOOK_URL>'
    channel: '#auth-service-alerts'
    title: 'Auth Service Alert'
    text: '{{ range .Alerts }}{{ .Annotations.description }}{{ end }}'
```

### Alert Rules

**Prometheus Alert Rules** (`alerts.yml`):

```yaml
groups:
- name: auth_service_alerts
  interval: 30s
  rules:

  # High error rate
  - alert: HighErrorRate
    expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.05
    for: 5m
    labels:
      severity: critical
    annotations:
      summary: "High error rate detected"
      description: "Error rate is {{ $value | humanizePercentage }} (threshold: 5%)"

  # High latency
  - alert: HighLatency
    expr: histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m])) > 0.5
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High API latency"
      description: "p95 latency is {{ $value }}s (threshold: 0.5s)"

  # Service down
  - alert: ServiceDown
    expr: up{job="auth-service"} == 0
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: "Auth service is down"
      description: "Auth service has been down for more than 1 minute"

  # Database connection issues
  - alert: DatabaseConnectionFailure
    expr: pg_up == 0
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: "PostgreSQL is down"
      description: "Cannot connect to PostgreSQL database"

  # High authentication failure rate
  - alert: HighAuthFailureRate
    expr: rate(auth_attempts_total{status="failure"}[5m]) / rate(auth_attempts_total[5m]) > 0.3
    for: 10m
    labels:
      severity: warning
    annotations:
      summary: "High authentication failure rate"
      description: "{{ $value | humanizePercentage }} of auth attempts are failing"

  # Redis down
  - alert: RedisDown
    expr: redis_up == 0
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: "Redis is down"
      description: "Redis instance is unavailable"

  # Disk space low
  - alert: DiskSpaceLow
    expr: (node_filesystem_avail_bytes / node_filesystem_size_bytes) < 0.2
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "Low disk space"
      description: "Disk usage is {{ $value | humanizePercentage }}"

  # Memory usage high
  - alert: HighMemoryUsage
    expr: (1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) > 0.85
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High memory usage"
      description: "Memory usage is {{ $value | humanizePercentage }}"
```

---

## Dashboards

### Grafana Dashboard JSON

Create comprehensive Grafana dashboards for:

1. **Overview Dashboard** - Service health at a glance
2. **Performance Dashboard** - Latency, throughput, errors
3. **Business Metrics Dashboard** - User activity, auth success rates
4. **Infrastructure Dashboard** - Database, Redis, pods
5. **Security Dashboard** - Failed auth attempts, suspicious activity

**Example Dashboard Panels:**

```json
{
  "dashboard": {
    "title": "Auth Service - Overview",
    "panels": [
      {
        "title": "Request Rate",
        "targets": [
          {
            "expr": "rate(http_requests_total[5m])"
          }
        ]
      },
      {
        "title": "Error Rate",
        "targets": [
          {
            "expr": "rate(http_requests_total{status=~\"5..\"}[5m])"
          }
        ]
      },
      {
        "title": "p95 Latency",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))"
          }
        ]
      },
      {
        "title": "Active Users",
        "targets": [
          {
            "expr": "sum(active_users_gauge)"
          }
        ]
      }
    ]
  }
}
```

---

## Health Checks

### Endpoint Implementation

Already implemented in `enterprise/main.py`:

```python
@app.get("/health")
async def health():
    """Basic health check."""
    return {"status": "healthy", "edition": "enterprise"}

@app.get("/ready")
async def readiness():
    """Readiness check with dependency validation."""
    checks = {
        "database": False,
        "redis": False
    }

    # Check database
    try:
        await db.execute(text("SELECT 1"))
        checks["database"] = True
    except Exception:
        pass

    # Check Redis
    try:
        await redis_client.ping()
        checks["redis"] = True
    except Exception:
        pass

    all_healthy = all(checks.values())
    status_code = 200 if all_healthy else 503

    return JSONResponse(
        status_code=status_code,
        content={"status": "ready" if all_healthy else "not_ready", "checks": checks}
    )
```

### Load Balancer Configuration

Configure health checks in your load balancer:

**AWS ALB Target Group:**

```bash
aws elbv2 modify-target-group \
  --target-group-arn <ARN> \
  --health-check-enabled \
  --health-check-path /health \
  --health-check-interval-seconds 30 \
  --health-check-timeout-seconds 5 \
  --healthy-threshold-count 2 \
  --unhealthy-threshold-count 3
```

**Kubernetes Probes:**

```yaml
livenessProbe:
  httpGet:
    path: /health
    port: 8000
  initialDelaySeconds: 30
  periodSeconds: 10

readinessProbe:
  httpGet:
    path: /ready
    port: 8000
  initialDelaySeconds: 20
  periodSeconds: 5
```

---

## Performance Monitoring

### Key Performance Indicators (KPIs)

| Metric | Target | Critical |
|--------|--------|----------|
| p50 Latency | < 100ms | > 500ms |
| p95 Latency | < 200ms | > 1s |
| p99 Latency | < 500ms | > 2s |
| Error Rate | < 0.1% | > 5% |
| Availability | > 99.9% | < 99.5% |
| Auth Success Rate | > 95% | < 80% |

### Performance Profiling

Enable profiling in development:

```python
from fastapi import Request
import cProfile
import pstats
from io import StringIO

@app.middleware("http")
async def profile_request(request: Request, call_next):
    if request.query_params.get("profile") == "true":
        profiler = cProfile.Profile()
        profiler.enable()

        response = await call_next(request)

        profiler.disable()
        s = StringIO()
        ps = pstats.Stats(profiler, stream=s).sort_stats('cumulative')
        ps.print_stats(20)

        print(s.getvalue())
        return response
    else:
        return await call_next(request)
```

---

## Security Monitoring

### Security Events to Monitor

```python
# Failed login attempts
logger.warning(
    "Failed login attempt",
    extra={
        "email": email,
        "ip_address": request.client.host,
        "user_agent": request.headers.get("user-agent"),
        "reason": "invalid_credentials"
    }
)

# Suspicious activity (brute force detection)
if failed_attempts > 5:
    logger.critical(
        "Potential brute force attack",
        extra={
            "email": email,
            "ip_address": request.client.host,
            "failed_attempts": failed_attempts
        }
    )

# Privilege escalation attempts
logger.warning(
    "Unauthorized access attempt",
    extra={
        "user_id": current_user.id,
        "attempted_resource": resource_id,
        "required_permission": permission,
        "user_permissions": current_user.permissions
    }
)
```

### SIEM Integration

Send security logs to SIEM (Splunk, ELK, etc.):

```python
import logging
from logging.handlers import SysLogHandler

siem_handler = SysLogHandler(address=('siem.company.com', 514))
security_logger = logging.getLogger('security')
security_logger.addHandler(siem_handler)

# Log security events
security_logger.warning(
    "Failed login attempt",
    extra={"event_type": "auth_failure", ...}
)
```

---

## Incident Response

### Incident Severity Levels

| Level | Description | Response Time | Escalation |
|-------|-------------|---------------|------------|
| P1 - Critical | Service down, data breach | 15 minutes | Immediate |
| P2 - High | Degraded performance, partial outage | 1 hour | Manager |
| P3 - Medium | Minor issues, workaround available | 4 hours | Team lead |
| P4 - Low | Cosmetic issues, no impact | 1 business day | None |

### On-Call Runbook

**Service Down:**

1. Check Grafana dashboards for service health
2. Verify load balancer is routing traffic
3. Check pod/container status: `kubectl get pods`
4. Review recent logs: `kubectl logs -f deployment/auth-service`
5. Check database connectivity
6. Check Redis connectivity
7. Review recent deployments
8. Rollback if necessary

**High Error Rate:**

1. Identify error patterns in logs
2. Check for recent code deployments
3. Verify database migration status
4. Check external dependencies (Redis, SMTP)
5. Review error traces in Jaeger
6. Consider circuit breaker activation

**Database Issues:**

1. Check database connection pool saturation
2. Verify database server health
3. Check for long-running queries
4. Review recent schema changes
5. Consider read replica failover

---

## Summary Checklist

Production monitoring setup:

- [ ] Prometheus metrics collection enabled
- [ ] Custom business metrics implemented
- [ ] Grafana dashboards created
- [ ] Structured JSON logging configured
- [ ] Log aggregation setup (ELK/Loki)
- [ ] Distributed tracing enabled
- [ ] AlertManager configured
- [ ] Alert rules defined
- [ ] PagerDuty/Slack integration
- [ ] Health check endpoints working
- [ ] Load balancer health checks configured
- [ ] Security monitoring enabled
- [ ] Performance baselines established
- [ ] Incident response runbooks documented
- [ ] On-call rotation scheduled

---

**Version:** 1.0.0
**Last Updated:** 2024-11-18
**Maintained By:** FaultMaven Platform Team
