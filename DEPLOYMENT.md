# FaultMaven Auth Service - Enterprise Edition
## Production Deployment Guide

This guide provides comprehensive instructions for deploying the FaultMaven Auth Service Enterprise Edition to production environments.

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Architecture Overview](#architecture-overview)
- [Pre-Deployment Checklist](#pre-deployment-checklist)
- [Deployment Methods](#deployment-methods)
  - [Docker Compose (Simple)](#docker-compose-simple)
  - [Kubernetes (Recommended)](#kubernetes-recommended)
  - [AWS ECS/Fargate](#aws-ecsfargate)
- [Configuration](#configuration)
- [Database Setup](#database-setup)
- [Security Hardening](#security-hardening)
- [Monitoring & Observability](#monitoring--observability)
- [Backup & Disaster Recovery](#backup--disaster-recovery)
- [Scaling Guidelines](#scaling-guidelines)
- [Troubleshooting](#troubleshooting)
- [Post-Deployment Verification](#post-deployment-verification)

---

## Prerequisites

### System Requirements

- **Minimum Hardware:**
  - 2 vCPU cores
  - 4 GB RAM
  - 20 GB storage (SSD recommended)

- **Recommended Hardware (Production):**
  - 4+ vCPU cores
  - 8+ GB RAM
  - 50+ GB storage (SSD)

### Software Requirements

- Docker 20.10+ or Kubernetes 1.23+
- PostgreSQL 15+ (managed service recommended)
- Redis 7+ (managed service recommended)
- Load balancer (ALB, NGINX, Traefik)
- SSL/TLS certificates
- Secrets management system (AWS Secrets Manager, HashiCorp Vault, etc.)

### Network Requirements

- Inbound: HTTPS (443), Health checks
- Outbound: Database (5432), Redis (6379), SMTP (587), External APIs
- Internal: Service mesh communication (if applicable)

---

## Architecture Overview

```
┌─────────────┐
│ Load        │
│ Balancer    │
│ (SSL/TLS)   │
└──────┬──────┘
       │
       ├──────────┬──────────┬──────────┐
       │          │          │          │
    ┌──▼──┐    ┌──▼──┐    ┌──▼──┐    ┌──▼──┐
    │Auth │    │Auth │    │Auth │    │Auth │
    │Svc 1│    │Svc 2│    │Svc 3│    │Svc N│
    └──┬──┘    └──┬──┘    └──┬──┘    └──┬──┘
       │          │          │          │
       └──────────┴──────────┴──────────┘
                  │
        ┌─────────┴─────────┐
        │                   │
    ┌───▼───┐         ┌─────▼────┐
    │Redis  │         │PostgreSQL│
    │Cluster│         │ (Primary │
    │       │         │+ Replicas)│
    └───────┘         └──────────┘
```

**Key Components:**
- **Load Balancer:** SSL termination, health checks, request distribution
- **Auth Service Instances:** Stateless API servers (horizontally scalable)
- **PostgreSQL:** Primary database with read replicas
- **Redis:** Session storage, token blacklist, caching

---

## Pre-Deployment Checklist

### Security

- [ ] Generate strong JWT secret key (`openssl rand -hex 64`)
- [ ] Obtain valid SSL/TLS certificates
- [ ] Configure secrets management system
- [ ] Set up firewall rules and security groups
- [ ] Enable database encryption at rest and in transit
- [ ] Configure CORS with specific allowed origins
- [ ] Review and harden password policies
- [ ] Set up rate limiting and DDoS protection

### Infrastructure

- [ ] Provision managed PostgreSQL instance
- [ ] Provision managed Redis instance
- [ ] Set up load balancer with health checks
- [ ] Configure DNS records
- [ ] Set up backup and disaster recovery
- [ ] Configure monitoring and alerting
- [ ] Set up log aggregation

### Configuration

- [ ] Create production `.env` file (never commit to git)
- [ ] Validate all required environment variables
- [ ] Test database connectivity
- [ ] Test Redis connectivity
- [ ] Configure SAML SSO (if applicable)
- [ ] Set up email service (SMTP)

---

## Deployment Methods

### Docker Compose (Simple)

**Use Case:** Small deployments, single-server setups, development staging

#### Step 1: Prepare Environment

```bash
# Clone repository (or use private enterprise repo)
cd /opt/faultmaven

# Copy production environment template
cp .env.production.example .env.production

# Edit with production values (use secrets manager in real production)
nano .env.production
```

#### Step 2: Configure Environment Variables

```bash
# Critical settings (use secrets manager)
export JWT_SECRET_KEY=$(openssl rand -hex 64)
export POSTGRES_PASSWORD=$(openssl rand -hex 32)
export REDIS_PASSWORD=$(openssl rand -hex 32)

# Update .env.production with these values
```

#### Step 3: Deploy

```bash
# Pull latest enterprise image
docker pull faultmaven/fm-auth-service-enterprise:latest

# Start services
docker-compose -f docker-compose.production.yml up -d

# Check logs
docker-compose -f docker-compose.production.yml logs -f auth-service
```

#### Step 4: Run Database Migrations

```bash
# Run migrations
docker-compose -f docker-compose.production.yml exec auth-service \
  alembic upgrade head

# Verify migration
docker-compose -f docker-compose.production.yml exec auth-service \
  alembic current
```

#### Step 5: Seed Initial Data (Optional)

```bash
# Create default organization and admin user
docker-compose -f docker-compose.production.yml exec auth-service \
  python -m enterprise.scripts.seed_data
```

---

### Kubernetes (Recommended)

**Use Case:** Production deployments, high availability, auto-scaling

#### Prerequisites

- Kubernetes cluster (v1.23+)
- `kubectl` configured
- Helm 3+ (optional but recommended)
- Container registry access

#### Step 1: Create Namespace

```bash
kubectl create namespace faultmaven-auth
kubectl config set-context --current --namespace=faultmaven-auth
```

#### Step 2: Configure Secrets

```bash
# Create database secret
kubectl create secret generic postgres-credentials \
  --from-literal=username='<DB_USER>' \
  --from-literal=password='<DB_PASSWORD>' \
  --from-literal=host='<DB_HOST>' \
  --from-literal=database='faultmaven_auth'

# Create Redis secret
kubectl create secret generic redis-credentials \
  --from-literal=password='<REDIS_PASSWORD>' \
  --from-literal=host='<REDIS_HOST>'

# Create JWT secret
kubectl create secret generic jwt-secret \
  --from-literal=secret-key="$(openssl rand -hex 64)"

# Create SAML certificates (if applicable)
kubectl create secret tls saml-certificate \
  --cert=path/to/saml-cert.pem \
  --key=path/to/saml-key.pem
```

#### Step 3: Deploy PostgreSQL (if not using managed service)

```bash
# Using Helm chart (example)
helm repo add bitnami https://charts.bitnami.com/bitnami

helm install postgres bitnami/postgresql \
  --set auth.username=postgres \
  --set auth.password=<STRONG_PASSWORD> \
  --set auth.database=faultmaven_auth \
  --set persistence.size=100Gi \
  --set metrics.enabled=true
```

#### Step 4: Deploy Redis (if not using managed service)

```bash
helm install redis bitnami/redis \
  --set auth.password=<STRONG_PASSWORD> \
  --set master.persistence.size=10Gi \
  --set replica.replicaCount=2 \
  --set metrics.enabled=true
```

#### Step 5: Create ConfigMap

```yaml
# auth-service-config.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: auth-service-config
  namespace: faultmaven-auth
data:
  ENVIRONMENT: "production"
  LOG_LEVEL: "INFO"
  LOG_FORMAT: "json"
  CORS_ORIGINS: "https://app.faultmaven.com,https://admin.faultmaven.com"
  ACCESS_TOKEN_EXPIRE_MINUTES: "15"
  REFRESH_TOKEN_EXPIRE_DAYS: "7"
  ENABLE_SSO: "true"
  ENABLE_TEAM_MANAGEMENT: "true"
  ENABLE_AUDIT_LOGGING: "true"
```

```bash
kubectl apply -f auth-service-config.yaml
```

#### Step 6: Create Deployment

```yaml
# auth-service-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: auth-service
  namespace: faultmaven-auth
  labels:
    app: auth-service
    version: v1
spec:
  replicas: 3
  selector:
    matchLabels:
      app: auth-service
  template:
    metadata:
      labels:
        app: auth-service
        version: v1
    spec:
      containers:
      - name: auth-service
        image: faultmaven/fm-auth-service-enterprise:latest
        ports:
        - containerPort: 8000
          name: http
        env:
        # Database configuration
        - name: POSTGRES_HOST
          valueFrom:
            secretKeyRef:
              name: postgres-credentials
              key: host
        - name: POSTGRES_USER
          valueFrom:
            secretKeyRef:
              name: postgres-credentials
              key: username
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: postgres-credentials
              key: password
        - name: POSTGRES_DB
          valueFrom:
            secretKeyRef:
              name: postgres-credentials
              key: database
        # Redis configuration
        - name: REDIS_HOST
          valueFrom:
            secretKeyRef:
              name: redis-credentials
              key: host
        - name: REDIS_PASSWORD
          valueFrom:
            secretKeyRef:
              name: redis-credentials
              key: password
        # JWT configuration
        - name: JWT_SECRET_KEY
          valueFrom:
            secretKeyRef:
              name: jwt-secret
              key: secret-key
        envFrom:
        - configMapRef:
            name: auth-service-config
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 3
        readinessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 20
          periodSeconds: 5
          timeoutSeconds: 3
          failureThreshold: 3
        volumeMounts:
        - name: saml-certs
          mountPath: /var/secrets/saml
          readOnly: true
      volumes:
      - name: saml-certs
        secret:
          secretName: saml-certificate
          optional: true
```

```bash
kubectl apply -f auth-service-deployment.yaml
```

#### Step 7: Create Service

```yaml
# auth-service-service.yaml
apiVersion: v1
kind: Service
metadata:
  name: auth-service
  namespace: faultmaven-auth
  labels:
    app: auth-service
spec:
  type: ClusterIP
  ports:
  - port: 80
    targetPort: 8000
    protocol: TCP
    name: http
  selector:
    app: auth-service
```

```bash
kubectl apply -f auth-service-service.yaml
```

#### Step 8: Create Ingress (with SSL)

```yaml
# auth-service-ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: auth-service-ingress
  namespace: faultmaven-auth
  annotations:
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
    nginx.ingress.kubernetes.io/rate-limit: "60"
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
spec:
  ingressClassName: nginx
  tls:
  - hosts:
    - auth.faultmaven.com
    secretName: auth-service-tls
  rules:
  - host: auth.faultmaven.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: auth-service
            port:
              number: 80
```

```bash
kubectl apply -f auth-service-ingress.yaml
```

#### Step 9: Run Database Migrations

```bash
# Create migration job
kubectl run migration-job --image=faultmaven/fm-auth-service-enterprise:latest \
  --restart=Never \
  --env="POSTGRES_HOST=$(kubectl get secret postgres-credentials -o jsonpath='{.data.host}' | base64 -d)" \
  --env="POSTGRES_PASSWORD=$(kubectl get secret postgres-credentials -o jsonpath='{.data.password}' | base64 -d)" \
  --command -- alembic upgrade head

# Check logs
kubectl logs migration-job

# Clean up
kubectl delete pod migration-job
```

#### Step 10: Configure Horizontal Pod Autoscaler

```yaml
# auth-service-hpa.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: auth-service-hpa
  namespace: faultmaven-auth
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: auth-service
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

```bash
kubectl apply -f auth-service-hpa.yaml
```

---

### AWS ECS/Fargate

**Use Case:** AWS-native deployments, serverless containers

#### Step 1: Create ECR Repository

```bash
# Create repository
aws ecr create-repository --repository-name faultmaven/auth-service-enterprise

# Get repository URI
REPO_URI=$(aws ecr describe-repositories \
  --repository-names faultmaven/auth-service-enterprise \
  --query 'repositories[0].repositoryUri' \
  --output text)

echo $REPO_URI
```

#### Step 2: Push Docker Image

```bash
# Authenticate Docker to ECR
aws ecr get-login-password --region us-east-1 | \
  docker login --username AWS --password-stdin $REPO_URI

# Tag and push image
docker tag faultmaven/fm-auth-service-enterprise:latest $REPO_URI:latest
docker push $REPO_URI:latest
```

#### Step 3: Create Task Definition

```json
{
  "family": "auth-service-enterprise",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "512",
  "memory": "1024",
  "executionRoleArn": "arn:aws:iam::ACCOUNT_ID:role/ecsTaskExecutionRole",
  "taskRoleArn": "arn:aws:iam::ACCOUNT_ID:role/authServiceTaskRole",
  "containerDefinitions": [
    {
      "name": "auth-service",
      "image": "REPO_URI:latest",
      "portMappings": [
        {
          "containerPort": 8000,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {"name": "ENVIRONMENT", "value": "production"},
        {"name": "LOG_LEVEL", "value": "INFO"}
      ],
      "secrets": [
        {
          "name": "POSTGRES_PASSWORD",
          "valueFrom": "arn:aws:secretsmanager:REGION:ACCOUNT:secret:db-password"
        },
        {
          "name": "JWT_SECRET_KEY",
          "valueFrom": "arn:aws:secretsmanager:REGION:ACCOUNT:secret:jwt-secret"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/auth-service",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "ecs"
        }
      },
      "healthCheck": {
        "command": ["CMD-SHELL", "curl -f http://localhost:8000/health || exit 1"],
        "interval": 30,
        "timeout": 5,
        "retries": 3,
        "startPeriod": 60
      }
    }
  ]
}
```

#### Step 4: Create ECS Service

```bash
# Create service with ALB integration
aws ecs create-service \
  --cluster faultmaven-production \
  --service-name auth-service \
  --task-definition auth-service-enterprise:1 \
  --desired-count 3 \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[subnet-xxx,subnet-yyy],securityGroups=[sg-xxx],assignPublicIp=DISABLED}" \
  --load-balancers "targetGroupArn=arn:aws:elasticloadbalancing:REGION:ACCOUNT:targetgroup/auth-service/xxx,containerName=auth-service,containerPort=8000" \
  --health-check-grace-period-seconds 60
```

#### Step 5: Configure Auto Scaling

```bash
# Register scalable target
aws application-autoscaling register-scalable-target \
  --service-namespace ecs \
  --resource-id service/faultmaven-production/auth-service \
  --scalable-dimension ecs:service:DesiredCount \
  --min-capacity 3 \
  --max-capacity 10

# Create scaling policy
aws application-autoscaling put-scaling-policy \
  --service-namespace ecs \
  --resource-id service/faultmaven-production/auth-service \
  --scalable-dimension ecs:service:DesiredCount \
  --policy-name cpu-scaling-policy \
  --policy-type TargetTrackingScaling \
  --target-tracking-scaling-policy-configuration '{
    "TargetValue": 70.0,
    "PredefinedMetricSpecification": {
      "PredefinedMetricType": "ECSServiceAverageCPUUtilization"
    }
  }'
```

---

## Configuration

### Environment Variables Reference

See `.env.production.example` for comprehensive list.

**Critical Variables:**

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `POSTGRES_HOST` | Yes | Database host | `prod-db.aws.com` |
| `POSTGRES_PASSWORD` | Yes | Database password | Use secrets manager |
| `REDIS_HOST` | Yes | Redis host | `prod-redis.aws.com` |
| `REDIS_PASSWORD` | Yes | Redis password | Use secrets manager |
| `JWT_SECRET_KEY` | Yes | JWT signing key | Use secrets manager (64+ chars) |
| `CORS_ORIGINS` | Yes | Allowed origins | `https://app.faultmaven.com` |
| `ENVIRONMENT` | Yes | Environment name | `production` |

### Secrets Management

**AWS Secrets Manager Example:**

```bash
# Store JWT secret
aws secretsmanager create-secret \
  --name faultmaven/auth/jwt-secret \
  --secret-string "$(openssl rand -hex 64)"

# Store database password
aws secretsmanager create-secret \
  --name faultmaven/auth/db-password \
  --secret-string "<STRONG_PASSWORD>"

# Retrieve in application
JWT_SECRET=$(aws secretsmanager get-secret-value \
  --secret-id faultmaven/auth/jwt-secret \
  --query SecretString \
  --output text)
```

---

## Database Setup

### PostgreSQL Configuration

**Recommended Settings (postgresql.conf):**

```ini
max_connections = 100
shared_buffers = 2GB
effective_cache_size = 6GB
maintenance_work_mem = 512MB
checkpoint_completion_target = 0.9
wal_buffers = 16MB
default_statistics_target = 100
random_page_cost = 1.1
effective_io_concurrency = 200
work_mem = 10MB
min_wal_size = 1GB
max_wal_size = 4GB
```

### Migration Management

```bash
# Check current version
alembic current

# Upgrade to latest
alembic upgrade head

# Rollback one version
alembic downgrade -1

# View migration history
alembic history

# Generate new migration (if schema changes)
alembic revision --autogenerate -m "description"
```

### Backup Strategy

**Daily automated backups:**

```bash
#!/bin/bash
# /opt/scripts/backup-auth-db.sh

BACKUP_DIR="/backups/postgres"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
DB_NAME="faultmaven_auth"

pg_dump -h $POSTGRES_HOST -U $POSTGRES_USER $DB_NAME | \
  gzip > $BACKUP_DIR/auth_${TIMESTAMP}.sql.gz

# Upload to S3
aws s3 cp $BACKUP_DIR/auth_${TIMESTAMP}.sql.gz \
  s3://faultmaven-backups/auth/

# Retain last 30 days locally
find $BACKUP_DIR -name "auth_*.sql.gz" -mtime +30 -delete
```

**Cron job:**

```cron
0 2 * * * /opt/scripts/backup-auth-db.sh
```

---

## Security Hardening

### SSL/TLS Configuration

- Use TLS 1.2+ only
- Strong cipher suites
- HSTS enabled
- Valid certificates (Let's Encrypt, commercial CA)

### Database Security

```sql
-- Create dedicated database user
CREATE USER auth_service WITH PASSWORD '<STRONG_PASSWORD>';

-- Grant minimal permissions
GRANT CONNECT ON DATABASE faultmaven_auth TO auth_service;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO auth_service;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO auth_service;

-- Enable SSL
ALTER SYSTEM SET ssl = on;
ALTER SYSTEM SET ssl_cert_file = '/path/to/server.crt';
ALTER SYSTEM SET ssl_key_file = '/path/to/server.key';
```

### Network Security

- Use VPC/private subnets
- Security groups: Allow only necessary ports
- Enable DDoS protection (CloudFlare, AWS Shield)
- Configure WAF rules

### Application Security

- JWT secret: 64+ characters, rotated regularly
- Rate limiting: 30 requests/min per IP
- Password requirements: 12+ chars, complexity rules
- MFA enabled for admin users
- Audit logging enabled

---

## Monitoring & Observability

See [MONITORING.md](MONITORING.md) for detailed setup.

**Quick Setup:**

### Health Checks

- **Endpoint:** `GET /health`
- **Expected:** `200 OK {"status": "healthy"}`
- **Interval:** 30s
- **Timeout:** 5s

### Metrics

Key metrics to monitor:

- Request rate (req/s)
- Response time (p50, p95, p99)
- Error rate (5xx responses)
- Database connection pool usage
- Redis connection pool usage
- JWT token validation rate
- Authentication success/failure rate

### Logging

```yaml
# Structured JSON logging
{
  "timestamp": "2024-01-15T10:30:45Z",
  "level": "INFO",
  "service": "auth-service",
  "environment": "production",
  "trace_id": "abc123",
  "user_id": "uuid",
  "endpoint": "/api/v1/enterprise/auth/login",
  "method": "POST",
  "status_code": 200,
  "duration_ms": 45
}
```

### Alerting

Configure alerts for:

- Error rate > 5%
- p95 latency > 500ms
- Database connection failures
- Redis connection failures
- Disk usage > 80%
- Memory usage > 85%
- Pod restarts > 3 in 5 minutes

---

## Backup & Disaster Recovery

### Backup Schedule

- **Database:** Daily full backup, hourly incremental
- **Configuration:** Version controlled (Git)
- **Secrets:** Encrypted backups in secrets manager
- **Retention:** 30 days online, 1 year archival

### Disaster Recovery Plan

**RTO (Recovery Time Objective):** 1 hour
**RPO (Recovery Point Objective):** 15 minutes

**Recovery Steps:**

1. Assess impact and severity
2. Notify stakeholders
3. Activate DR plan
4. Restore database from latest backup
5. Deploy service to DR region
6. Update DNS to DR endpoint
7. Verify functionality
8. Monitor closely

**DR Testing:** Quarterly

---

## Scaling Guidelines

### Horizontal Scaling

**Triggers:**

- CPU usage > 70% for 5 minutes
- Memory usage > 80% for 5 minutes
- Request queue depth > 100

**Kubernetes HPA:** 3-10 pods
**ECS Auto Scaling:** 3-10 tasks

### Vertical Scaling

**Database:**

- Monitor connection pool saturation
- Increase instance size if CPU > 70%
- Add read replicas for read-heavy workloads

**Redis:**

- Monitor memory usage
- Increase instance size if memory > 80%
- Consider Redis Cluster for > 10GB datasets

### Performance Optimization

- Database query optimization (EXPLAIN ANALYZE)
- Redis caching for frequently accessed data
- Connection pooling tuning
- JWT token caching

---

## Troubleshooting

### Common Issues

#### Issue: Service fails to start

**Symptoms:** Container crashes on startup

**Diagnosis:**
```bash
# Check logs
docker logs fm-auth-service
kubectl logs deployment/auth-service
```

**Solutions:**
- Verify database connectivity
- Check environment variables
- Verify secrets are accessible
- Check migrations ran successfully

#### Issue: Database connection errors

**Symptoms:** `OperationalError: could not connect to server`

**Diagnosis:**
```bash
# Test connectivity
nc -zv $POSTGRES_HOST 5432

# Check credentials
psql -h $POSTGRES_HOST -U $POSTGRES_USER -d $POSTGRES_DB
```

**Solutions:**
- Verify security groups/firewall rules
- Check database is running
- Verify credentials
- Check SSL/TLS configuration

#### Issue: High latency

**Symptoms:** Response times > 1 second

**Diagnosis:**
```bash
# Check database query performance
SELECT * FROM pg_stat_statements ORDER BY mean_exec_time DESC LIMIT 10;

# Check connection pool
kubectl exec -it deployment/auth-service -- python -c "from enterprise.database import engine; print(engine.pool.status())"
```

**Solutions:**
- Add database indexes
- Increase connection pool size
- Enable query caching
- Add read replicas

#### Issue: JWT token validation failures

**Symptoms:** `401 Unauthorized` errors

**Diagnosis:**
```bash
# Check token claims
echo $TOKEN | cut -d'.' -f2 | base64 -d | jq

# Verify JWT_SECRET_KEY consistency
kubectl get secret jwt-secret -o jsonpath='{.data.secret-key}' | base64 -d
```

**Solutions:**
- Verify JWT_SECRET_KEY is consistent across instances
- Check token expiration times
- Verify token format (Bearer prefix)

---

## Post-Deployment Verification

### Smoke Tests

```bash
# Health check
curl https://auth.faultmaven.com/health

# API documentation
curl https://auth.faultmaven.com/enterprise/docs

# User registration
curl -X POST https://auth.faultmaven.com/api/v1/enterprise/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "Test123!@#",
    "first_name": "Test",
    "last_name": "User",
    "organization_id": "<ORG_UUID>"
  }'

# User login
curl -X POST https://auth.faultmaven.com/api/v1/enterprise/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "Test123!@#"
  }'

# Protected endpoint (with token)
curl -X GET https://auth.faultmaven.com/api/v1/enterprise/auth/me \
  -H "Authorization: Bearer <ACCESS_TOKEN>"
```

### Performance Baseline

Establish baseline metrics:

- Authentication requests: < 200ms p95
- Organization queries: < 100ms p95
- Token refresh: < 50ms p95
- Error rate: < 0.1%

### Security Validation

- [ ] SSL/TLS A+ rating (SSL Labs)
- [ ] No exposed secrets in logs
- [ ] CORS configured correctly
- [ ] Rate limiting functional
- [ ] Security headers present
- [ ] OWASP Top 10 mitigations verified

---

## Rollback Procedures

### Kubernetes Rollback

```bash
# View deployment history
kubectl rollout history deployment/auth-service

# Rollback to previous version
kubectl rollout undo deployment/auth-service

# Rollback to specific revision
kubectl rollout undo deployment/auth-service --to-revision=3

# Monitor rollback
kubectl rollout status deployment/auth-service
```

### Database Migration Rollback

```bash
# Downgrade one version
alembic downgrade -1

# Downgrade to specific version
alembic downgrade <revision_id>

# Check current version
alembic current
```

---

## Support & Escalation

**Production Issues:**

1. Check monitoring dashboards
2. Review recent deployments
3. Check error logs and traces
4. Engage on-call engineer
5. Escalate to architecture team if needed

**Contact:**

- **On-Call:** PagerDuty rotation
- **Email:** ops@faultmaven.com
- **Slack:** #faultmaven-auth-alerts

---

## Additional Resources

- [API Reference](API_REFERENCE.md)
- [Architecture Documentation](ARCHITECTURE.md)
- [Monitoring Guide](MONITORING.md)
- [Secrets Management](SECRETS_MANAGEMENT.md)
- [Security Best Practices](SECURITY.md)

---

**Version:** 1.0.0
**Last Updated:** 2024-11-18
**Maintained By:** FaultMaven Platform Team
