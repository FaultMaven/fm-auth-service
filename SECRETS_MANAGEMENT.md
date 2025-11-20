# FaultMaven Auth Service - Enterprise Edition
## Secrets Management Guide

This guide provides comprehensive instructions for managing secrets and sensitive credentials in the FaultMaven Auth Service.

---

## Table of Contents

- [Overview](#overview)
- [Critical Secrets](#critical-secrets)
- [Secrets Management Solutions](#secrets-management-solutions)
  - [AWS Secrets Manager](#aws-secrets-manager)
  - [HashiCorp Vault](#hashicorp-vault)
  - [Kubernetes Secrets](#kubernetes-secrets)
  - [Azure Key Vault](#azure-key-vault)
  - [Google Secret Manager](#google-secret-manager)
- [Best Practices](#best-practices)
- [Secret Rotation](#secret-rotation)
- [Disaster Recovery](#disaster-recovery)
- [Compliance](#compliance)
- [Troubleshooting](#troubleshooting)

---

## Overview

### Why Secrets Management Matters

Proper secrets management is critical for:
- **Security**: Prevent unauthorized access and data breaches
- **Compliance**: Meet regulatory requirements (SOC2, GDPR, HIPAA)
- **Operations**: Enable secret rotation without downtime
- **Audit**: Track who accessed what and when

### Security Principles

1. **Never commit secrets to version control**
2. **Encrypt secrets at rest and in transit**
3. **Implement least privilege access**
4. **Rotate secrets regularly**
5. **Audit all secret access**
6. **Use different secrets per environment**

---

## Critical Secrets

### JWT Secret Key

**Purpose**: Sign and verify JWT tokens

**Requirements**:
- Minimum 64 characters (256 bits)
- Cryptographically random
- Unique per environment
- Never exposed in logs or error messages

**Generation**:
```bash
# Generate strong JWT secret
openssl rand -hex 64
```

**Rotation Impact**: HIGH - requires user re-authentication

### Database Credentials

**Purpose**: PostgreSQL connection authentication

**Secrets**:
- `POSTGRES_USER`: Database username
- `POSTGRES_PASSWORD`: Database password
- `POSTGRES_HOST`: Database hostname (less sensitive)
- `POSTGRES_DB`: Database name (less sensitive)

**Rotation Impact**: MEDIUM - requires connection pool restart

### Redis Credentials

**Purpose**: Redis authentication for sessions and caching

**Secrets**:
- `REDIS_PASSWORD`: Redis authentication password
- `REDIS_HOST`: Redis hostname (less sensitive)

**Rotation Impact**: MEDIUM - invalidates cached sessions

### SAML Certificates

**Purpose**: SAML SSO authentication

**Secrets**:
- Private key (`.pem` file)
- Certificate (`.crt` file)

**Rotation Impact**: HIGH - disrupts SSO for all users

### SMTP Credentials

**Purpose**: Email sending (password reset, notifications)

**Secrets**:
- `SMTP_USER`: Email account username
- `SMTP_PASSWORD`: Email account password

**Rotation Impact**: LOW - only affects new emails

---

## Secrets Management Solutions

### AWS Secrets Manager

**Use Case**: AWS-hosted deployments

#### Setup

```bash
# Install AWS CLI
pip install awscli

# Configure credentials
aws configure
```

#### Create Secrets

```bash
# JWT secret
aws secretsmanager create-secret \
    --name faultmaven/auth/jwt-secret \
    --description "JWT signing secret for auth service" \
    --secret-string "$(openssl rand -hex 64)" \
    --tags Key=Environment,Value=production Key=Service,Value=auth

# Database password
aws secretsmanager create-secret \
    --name faultmaven/auth/db-password \
    --secret-string '{"username":"postgres","password":"<STRONG_PASSWORD>","host":"prod-db.rds.amazonaws.com","port":"5432","database":"faultmaven_auth"}'

# Redis password
aws secretsmanager create-secret \
    --name faultmaven/auth/redis-password \
    --secret-string "$(openssl rand -hex 32)"

# SAML certificates
aws secretsmanager create-secret \
    --name faultmaven/auth/saml-private-key \
    --secret-binary fileb://saml-private-key.pem

aws secretsmanager create-secret \
    --name faultmaven/auth/saml-certificate \
    --secret-binary fileb://saml-cert.pem
```

#### Retrieve Secrets in Application

```python
import boto3
import json
from botocore.exceptions import ClientError

def get_secret(secret_name: str, region_name: str = "us-east-1") -> dict:
    """Retrieve secret from AWS Secrets Manager."""
    session = boto3.session.Session()
    client = session.client(service_name='secretsmanager', region_name=region_name)

    try:
        response = client.get_secret_value(SecretId=secret_name)
    except ClientError as e:
        raise Exception(f"Failed to retrieve secret {secret_name}: {e}")

    # Parse secret
    if 'SecretString' in response:
        return json.loads(response['SecretString'])
    else:
        return response['SecretBinary']

# Usage
db_secret = get_secret("faultmaven/auth/db-password")
POSTGRES_PASSWORD = db_secret['password']

jwt_secret = get_secret("faultmaven/auth/jwt-secret")
JWT_SECRET_KEY = jwt_secret
```

#### IAM Policy for Service

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue",
        "secretsmanager:DescribeSecret"
      ],
      "Resource": [
        "arn:aws:secretsmanager:us-east-1:ACCOUNT_ID:secret:faultmaven/auth/*"
      ]
    }
  ]
}
```

#### Secret Rotation

```bash
# Enable automatic rotation (30 days)
aws secretsmanager rotate-secret \
    --secret-id faultmaven/auth/db-password \
    --rotation-lambda-arn arn:aws:lambda:us-east-1:ACCOUNT_ID:function:SecretsManagerRotation \
    --rotation-rules AutomaticallyAfterDays=30
```

---

### HashiCorp Vault

**Use Case**: Multi-cloud, hybrid deployments

#### Setup

```bash
# Install Vault
wget https://releases.hashicorp.com/vault/1.15.0/vault_1.15.0_linux_amd64.zip
unzip vault_1.15.0_linux_amd64.zip
sudo mv vault /usr/local/bin/

# Start Vault server (dev mode for testing)
vault server -dev

# Set environment variables
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='<ROOT_TOKEN>'
```

#### Create Secrets

```bash
# Enable KV secrets engine
vault secrets enable -path=faultmaven kv-v2

# Store JWT secret
vault kv put faultmaven/auth/jwt secret_key="$(openssl rand -hex 64)"

# Store database credentials
vault kv put faultmaven/auth/database \
    username=postgres \
    password="<STRONG_PASSWORD>" \
    host=prod-db.example.com \
    port=5432 \
    database=faultmaven_auth

# Store Redis password
vault kv put faultmaven/auth/redis password="$(openssl rand -hex 32)"

# Store SAML certificates
vault kv put faultmaven/auth/saml \
    private_key=@saml-private-key.pem \
    certificate=@saml-cert.pem
```

#### Retrieve Secrets in Application

```python
import hvac
import os

# Initialize Vault client
client = hvac.Client(
    url=os.getenv('VAULT_ADDR', 'http://localhost:8200'),
    token=os.getenv('VAULT_TOKEN')
)

def get_vault_secret(path: str) -> dict:
    """Retrieve secret from Vault."""
    try:
        response = client.secrets.kv.v2.read_secret_version(
            path=path,
            mount_point='faultmaven'
        )
        return response['data']['data']
    except Exception as e:
        raise Exception(f"Failed to retrieve secret {path}: {e}")

# Usage
jwt_secret = get_vault_secret('auth/jwt')
JWT_SECRET_KEY = jwt_secret['secret_key']

db_secret = get_vault_secret('auth/database')
POSTGRES_PASSWORD = db_secret['password']
```

#### Access Control with Policies

```hcl
# auth-service-policy.hcl
path "faultmaven/data/auth/*" {
  capabilities = ["read"]
}

path "faultmaven/metadata/auth/*" {
  capabilities = ["list"]
}
```

```bash
# Create policy
vault policy write auth-service auth-service-policy.hcl

# Create token with policy
vault token create -policy=auth-service
```

#### Dynamic Database Credentials

```bash
# Enable database secrets engine
vault secrets enable database

# Configure PostgreSQL connection
vault write database/config/faultmaven-postgres \
    plugin_name=postgresql-database-plugin \
    allowed_roles="auth-service" \
    connection_url="postgresql://{{username}}:{{password}}@prod-db:5432/faultmaven_auth" \
    username="vault-admin" \
    password="<ADMIN_PASSWORD>"

# Create role with TTL
vault write database/roles/auth-service \
    db_name=faultmaven-postgres \
    creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; \
    GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO \"{{name}}\";" \
    default_ttl="1h" \
    max_ttl="24h"
```

---

### Kubernetes Secrets

**Use Case**: Kubernetes deployments

#### Create Secrets

```bash
# JWT secret
kubectl create secret generic jwt-secret \
    --from-literal=secret-key="$(openssl rand -hex 64)" \
    --namespace=faultmaven-auth

# Database credentials
kubectl create secret generic postgres-credentials \
    --from-literal=username=postgres \
    --from-literal=password=<STRONG_PASSWORD> \
    --from-literal=host=postgres.database.svc.cluster.local \
    --from-literal=port=5432 \
    --from-literal=database=faultmaven_auth \
    --namespace=faultmaven-auth

# Redis credentials
kubectl create secret generic redis-credentials \
    --from-literal=password=<STRONG_PASSWORD> \
    --from-literal=host=redis.cache.svc.cluster.local \
    --namespace=faultmaven-auth

# SAML certificates
kubectl create secret tls saml-certificate \
    --cert=saml-cert.pem \
    --key=saml-private-key.pem \
    --namespace=faultmaven-auth

# Verify secrets
kubectl get secrets -n faultmaven-auth
```

#### Use Secrets in Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: auth-service
spec:
  template:
    spec:
      containers:
      - name: auth-service
        image: faultmaven/auth-service-enterprise:latest
        env:
        # JWT secret from secret
        - name: JWT_SECRET_KEY
          valueFrom:
            secretKeyRef:
              name: jwt-secret
              key: secret-key
        # Database credentials from secret
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
        # Redis password from secret
        - name: REDIS_PASSWORD
          valueFrom:
            secretKeyRef:
              name: redis-credentials
              key: password
        volumeMounts:
        # Mount SAML certificates as files
        - name: saml-certs
          mountPath: /var/secrets/saml
          readOnly: true
      volumes:
      - name: saml-certs
        secret:
          secretName: saml-certificate
```

#### Sealed Secrets (for GitOps)

```bash
# Install Sealed Secrets controller
kubectl apply -f https://github.com/bitnami-labs/sealed-secrets/releases/download/v0.24.0/controller.yaml

# Install kubeseal CLI
wget https://github.com/bitnami-labs/sealed-secrets/releases/download/v0.24.0/kubeseal-linux-amd64 -O kubeseal
sudo install -m 755 kubeseal /usr/local/bin/kubeseal

# Create sealed secret
kubectl create secret generic jwt-secret \
    --from-literal=secret-key="$(openssl rand -hex 64)" \
    --dry-run=client -o yaml | \
kubeseal -o yaml > jwt-sealed-secret.yaml

# Commit sealed secret to Git (safe)
git add jwt-sealed-secret.yaml
git commit -m "Add JWT sealed secret"
```

---

### Azure Key Vault

**Use Case**: Azure-hosted deployments

#### Create Secrets

```bash
# Create Key Vault
az keyvault create \
    --name faultmaven-auth-vault \
    --resource-group faultmaven-rg \
    --location eastus

# Store JWT secret
az keyvault secret set \
    --vault-name faultmaven-auth-vault \
    --name jwt-secret-key \
    --value "$(openssl rand -hex 64)"

# Store database password
az keyvault secret set \
    --vault-name faultmaven-auth-vault \
    --name postgres-password \
    --value "<STRONG_PASSWORD>"
```

#### Retrieve Secrets

```python
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

credential = DefaultAzureCredential()
vault_url = "https://faultmaven-auth-vault.vault.azure.net/"
client = SecretClient(vault_url=vault_url, credential=credential)

# Retrieve secret
jwt_secret = client.get_secret("jwt-secret-key")
JWT_SECRET_KEY = jwt_secret.value
```

---

### Google Secret Manager

**Use Case**: GCP-hosted deployments

#### Create Secrets

```bash
# Enable API
gcloud services enable secretmanager.googleapis.com

# Create JWT secret
echo -n "$(openssl rand -hex 64)" | \
gcloud secrets create jwt-secret-key --data-file=-

# Create database password
echo -n "<STRONG_PASSWORD>" | \
gcloud secrets create postgres-password --data-file=-
```

#### Retrieve Secrets

```python
from google.cloud import secretmanager

client = secretmanager.SecretManagerServiceClient()
project_id = "faultmaven-prod"

def get_secret(secret_id: str, version: str = "latest") -> str:
    name = f"projects/{project_id}/secrets/{secret_id}/versions/{version}"
    response = client.access_secret_version(request={"name": name})
    return response.payload.data.decode("UTF-8")

JWT_SECRET_KEY = get_secret("jwt-secret-key")
```

---

## Best Practices

### Secret Generation

✅ **DO:**
- Use cryptographically secure random generators
- Generate secrets with sufficient length (256 bits minimum)
- Use different secrets per environment
- Generate unique secrets per service

❌ **DON'T:**
- Use predictable patterns or default values
- Reuse secrets across environments
- Use short or weak secrets
- Store secrets in code or version control

### Secret Storage

✅ **DO:**
- Encrypt secrets at rest
- Use managed secrets services
- Implement access controls
- Enable audit logging

❌ **DON'T:**
- Store secrets in plain text files
- Commit secrets to Git
- Email or Slack secrets
- Store secrets in environment variables visible to all processes

### Secret Access

✅ **DO:**
- Use IAM roles and service accounts
- Implement least privilege access
- Audit secret access
- Rotate access credentials

❌ **DON'T:**
- Use long-lived access tokens
- Share credentials between services
- Grant overly broad permissions
- Disable audit logging

### Secret Rotation

✅ **DO:**
- Rotate secrets regularly (90 days max)
- Automate rotation where possible
- Test rotation procedures
- Have rollback plan

❌ **DON'T:**
- Wait for breaches to rotate
- Rotate without testing
- Forget to update dependent services
- Skip rotation for "old" secrets

---

## Secret Rotation

### JWT Secret Rotation

**Challenge**: Rotating JWT secret invalidates all existing tokens

**Strategy**: Dual-key rotation with grace period

```python
# Support multiple JWT secrets during rotation
JWT_SECRET_KEYS = [
    os.getenv("JWT_SECRET_KEY_NEW"),  # Primary (sign new tokens)
    os.getenv("JWT_SECRET_KEY_OLD"),  # Secondary (verify old tokens)
]

def verify_token(token: str) -> dict:
    """Verify token with fallback to old key."""
    for secret_key in JWT_SECRET_KEYS:
        try:
            payload = jwt.decode(token, secret_key, algorithms=["HS256"])
            return payload
        except JWTError:
            continue

    raise HTTPException(status_code=401, detail="Invalid token")
```

**Rotation Procedure:**

1. Generate new JWT secret
2. Add new secret as `JWT_SECRET_KEY_NEW`
3. Keep old secret as `JWT_SECRET_KEY_OLD`
4. Deploy updated service (verifies both keys, signs with new)
5. Wait for token expiration (30 minutes + grace period)
6. Remove old secret
7. Redeploy

### Database Password Rotation

**Strategy**: Create new user, migrate, delete old

```bash
# Step 1: Create new database user
CREATE USER auth_service_new WITH PASSWORD '<NEW_PASSWORD>';
GRANT ALL PRIVILEGES ON DATABASE faultmaven_auth TO auth_service_new;

# Step 2: Update secret with new credentials
aws secretsmanager update-secret \
    --secret-id faultmaven/auth/db-password \
    --secret-string '{"username":"auth_service_new","password":"<NEW_PASSWORD>",...}'

# Step 3: Rolling restart of service (picks up new credentials)
kubectl rollout restart deployment/auth-service

# Step 4: Verify new credentials work
# Step 5: Drop old user
DROP USER auth_service_old;
```

### Automation with AWS Lambda

```python
import boto3
import psycopg2

def lambda_handler(event, context):
    """Rotate PostgreSQL password in Secrets Manager."""
    service_client = boto3.client('secretsmanager')
    secret_arn = event['SecretId']
    token = event['ClientRequestToken']
    step = event['Step']

    if step == "createSecret":
        # Generate new password
        new_password = generate_password(32)

        # Update secret with AWSPENDING label
        service_client.put_secret_value(
            SecretId=secret_arn,
            ClientRequestToken=token,
            SecretString=json.dumps({"password": new_password}),
            VersionStages=['AWSPENDING']
        )

    elif step == "setSecret":
        # Update database with new password
        current_secret = json.loads(service_client.get_secret_value(SecretId=secret_arn)['SecretString'])
        pending_secret = json.loads(service_client.get_secret_value(SecretId=secret_arn, VersionStage='AWSPENDING')['SecretString'])

        conn = psycopg2.connect(host=current_secret['host'], user=current_secret['username'], password=current_secret['password'])
        cursor = conn.cursor()
        cursor.execute(f"ALTER USER {current_secret['username']} WITH PASSWORD '{pending_secret['password']}'")
        conn.commit()

    elif step == "testSecret":
        # Test new credentials
        pending_secret = json.loads(service_client.get_secret_value(SecretId=secret_arn, VersionStage='AWSPENDING')['SecretString'])
        conn = psycopg2.connect(host=pending_secret['host'], user=pending_secret['username'], password=pending_secret['password'])
        conn.close()

    elif step == "finishSecret":
        # Move AWSCURRENT label to new version
        service_client.update_secret_version_stage(
            SecretId=secret_arn,
            VersionStage='AWSCURRENT',
            MoveToVersionId=token
        )
```

---

## Disaster Recovery

### Backup Secrets

```bash
# AWS Secrets Manager
aws secretsmanager list-secrets | \
    jq -r '.SecretList[].Name' | \
    while read secret; do
        aws secretsmanager get-secret-value --secret-id "$secret" > "backup_${secret}.json"
    done

# Encrypt backups
gpg --encrypt --recipient admin@faultmaven.com backup_*.json

# Store in secure location (not in regular backups)
aws s3 cp backup_*.json.gpg s3://faultmaven-disaster-recovery/secrets/ --sse aws:kms
```

### Recovery Procedures

1. Restore secrets from encrypted backups
2. Update service configuration
3. Restart services with new secrets
4. Verify functionality
5. Rotate secrets (assume compromised)

---

## Compliance

### SOC 2 Requirements

- ✅ Encrypt secrets at rest and in transit
- ✅ Implement access controls
- ✅ Audit all secret access
- ✅ Rotate secrets regularly
- ✅ Document secrets management procedures

### GDPR Requirements

- ✅ Encrypt personal data (database passwords protect PII)
- ✅ Implement data breach procedures
- ✅ Document data processing activities

### HIPAA Requirements

- ✅ Encrypt PHI (database credentials protect PHI)
- ✅ Access controls and audit logs
- ✅ Disaster recovery procedures

---

## Troubleshooting

### Secret Not Found

**Error**: `SecretNotFoundException` or `404`

**Solutions**:
1. Verify secret name/path is correct
2. Check region (AWS)
3. Verify namespace (Kubernetes)
4. Check secret exists: `aws secretsmanager describe-secret --secret-id <name>`

### Permission Denied

**Error**: `AccessDeniedException` or `403`

**Solutions**:
1. Verify IAM policy grants `secretsmanager:GetSecretValue`
2. Check service account bindings (Kubernetes)
3. Verify RBAC policies (Vault)
4. Review audit logs for denied access

### Expired/Rotated Secrets

**Error**: Authentication failures after rotation

**Solutions**:
1. Verify service restarted after secret update
2. Check secret version being used
3. Implement dual-key rotation for JWT
4. Review rotation logs

### Certificate Validation Failures

**Error**: `SSLError` or certificate verification failed

**Solutions**:
1. Verify certificate not expired: `openssl x509 -in cert.pem -noout -dates`
2. Check certificate chain is complete
3. Verify Common Name (CN) matches
4. Ensure certificate authority (CA) is trusted

---

## Summary Checklist

Production secrets management setup:

- [ ] All secrets stored in managed service (not env files)
- [ ] Unique secrets per environment
- [ ] Strong secret generation (256+ bits)
- [ ] Encryption at rest enabled
- [ ] Encryption in transit (TLS) enabled
- [ ] IAM/RBAC access controls configured
- [ ] Least privilege access implemented
- [ ] Audit logging enabled
- [ ] Secret rotation procedures documented
- [ ] Automated rotation enabled (where possible)
- [ ] Disaster recovery backups created
- [ ] Recovery procedures tested
- [ ] Compliance requirements met
- [ ] Team trained on secrets management
- [ ] Incident response plan includes secret rotation

---

**Version:** 1.0.0
**Last Updated:** 2024-11-18
**Maintained By:** FaultMaven Platform Team
