# Sentinel on AWS (Terraform)

A production-shaped skeleton: ECS Fargate (API + worker), RDS PostgreSQL 16, ElastiCache
Redis 7, an S3 audit bucket with Object Lock in compliance mode, Secrets Manager, an ALB with
TLS 1.3 and AWS WAF, and CloudWatch logs and alarms. It is a starting point to review and
adapt, not a turnkey module: read every file before `apply`.

## What it builds

| Component | Resource | Notes |
|---|---|---|
| Network | VPC, 2 public + 2 private subnets, NAT per AZ, S3 gateway endpoint | Tasks and data stores have no public IPs |
| Compute | ECS cluster, `api` and `worker` Fargate services | Same image, `command` selects the role; read-only root FS, all capabilities dropped, non-root UID 10001 |
| Database | RDS PostgreSQL 16, Multi-AZ, encrypted with a CMK, `rds.force_ssl=1`, deletion protection | `DATABASE_URL` is assembled into Secrets Manager with `sslmode=require` |
| Queue | ElastiCache Redis 7 replication group, TLS + AUTH, `noeviction` | `REDIS_URL` uses `rediss://` |
| Audit WORM | S3 bucket, versioning, Object Lock COMPLIANCE default retention, SSE-KMS, TLS-only policy | The task role may only `s3:PutObject` under the audit prefix |
| Secrets | Secrets Manager entries for `SESSION_SECRET`, `ADMIN_PASSWORD`, `INGEST_API_KEY`, `AUDIT_SIGNING_KEY`, `DATABASE_URL`, `REDIS_URL`; empty containers for `OIDC_CLIENT_SECRET`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY` | Injected as task `secrets`, never as plain environment |
| Edge | ALB (HTTP to HTTPS redirect, TLS13 policy), `/metrics` blocked, WAF with rate limit + AWS managed rule groups, WAF logs with auth headers redacted | ACM certificate requested and DNS-validated when `hosted_zone_id` is set |
| Observability | CloudWatch log groups (KMS-encrypted, retention), alarms for 5xx, unhealthy hosts, worker task count, RDS CPU | Add an SNS topic to `alarm_actions` for paging |

## Usage

```bash
cd infra/terraform
cp terraform.tfvars.example terraform.tfvars   # edit image digest, domain, zone
terraform init
terraform plan -out plan.tfplan
terraform apply plan.tfplan
```

Then:

1. Populate the external secrets (values are never in Terraform):
   `aws secretsmanager put-secret-value --secret-id sentinel-production/OIDC_CLIENT_SECRET --secret-string '...'`
2. Read the bootstrap owner password:
   `aws secretsmanager get-secret-value --secret-id sentinel-production/ADMIN_PASSWORD --query SecretString --output text`
3. Log in at `https://<domain_name>` and follow the production checklist in `docs/DEPLOYMENT.md`.

The API task runs `scripts/migrate.py` at start (`RUN_MIGRATIONS=true`). Migrations are
idempotent, so two API tasks starting at once is safe.

## Decisions you must make

- **Retention**: `audit_retention_days` is enforced by S3 Object Lock in compliance mode. It
  cannot be shortened, and objects cannot be deleted before it elapses by anyone.
- **Egress**: the task security group allows HTTPS to the internet so that model providers,
  identity providers, cloud APIs and authorized test targets are reachable. Narrow it to
  prefix lists or route through an egress proxy when you know the destinations.
- **Allowed CIDRs**: `allowed_cidrs` defaults to the internet (WAF and application auth are
  in front). Restrict it for internal-only deployments.
- **State**: configure the S3 backend in `versions.tf`; the state contains generated secrets.
- **Testing tools**: the image does not bundle nuclei, zap, prowler, semgrep or trivy. Build an
  extras image or a separate worker task definition with those binaries when you enable
  active testing, and keep that worker in its own security group with its own egress rules.

## Variables and outputs

See `variables.tf` and `outputs.tf`. Every variable has a description. Outputs include the
ALB DNS name, the ECS service names (for `aws ecs update-service --force-new-deployment`),
the audit bucket, and the Secrets Manager ARNs.

## Validation

```bash
terraform fmt -check -recursive
terraform init -backend=false && terraform validate
```

CI runs `terraform fmt -check` (`.github/workflows/test.yml`). No credentials are embedded;
the AWS provider uses the ambient credential chain.
