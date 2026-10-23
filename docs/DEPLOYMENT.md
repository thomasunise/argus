# Deployment

This document covers the four supported shapes (development, compose pilot, Kubernetes,
managed cloud via Terraform), the configuration contract, and the production checklist.
All configuration is environment variables read by `app/core/config.py`; `.env.example`
lists every key with its default.

## 1. Process model

One image, two roles, selected by the entrypoint argument:

| Role | Command | What it does |
|---|---|---|
| `api` | `docker/entrypoint.sh api` | optional `scripts/migrate.py` when `RUN_MIGRATIONS=true`, then `uvicorn app.main:app --proxy-headers --forwarded-allow-ips $FORWARDED_ALLOW_IPS` |
| `worker` | `docker/entrypoint.sh worker` (`python -m app.worker`) | the same queue handlers as the API, consuming `REDIS_URL`; requires `REDIS_URL` |
| `migrate` | `docker/entrypoint.sh migrate` | apply schema and exit |

Queue handlers registered at startup: `graph.recompute`, `detections.run`,
`detections.baselines`, `collectors.run`, `testing.run`, `agents.run`, `actions.execute`,
`actions.rollback`, `integrations.fanout`, `integrations.deliver`, `integrations.wazuh_sync`.
With `WORKERS_INPROCESS=true` (default) the API process runs them itself; set it to `false`
whenever dedicated workers exist so the API never executes long jobs.

Background loops started by packages (`app.state.startup_hooks`): detections scheduler
(every 60 s per active tenant), collectors scheduler, Wazuh pull scheduler, testing scheduler
when `AUTOSCAN_ENABLED=true`. They run in whichever process has them enabled; in a
multi-process deployment the engines tolerate duplicate runs (fingerprint dedupe, idempotency
keys), but prefer a single API replica running schedulers or a dedicated scheduler replica.

Schema: `scripts/migrate.py` runs `alembic upgrade head` (the initial revision creates every
table). Set `DB_AUTO_CREATE=false` wherever migrations own the schema so the application never
touches it; for an existing `create_all` database run `python scripts/migrate.py --stamp head`
once. Details and authoring rules: `docs/MIGRATIONS.md`.

Endpoints used by infrastructure:

- `GET /health` - process alive (liveness).
- `GET /ready` - database reachable (readiness); returns queue backend and provider.
- `GET /metrics` - Prometheus exposition (unauthenticated; keep it off the public ingress).

## 2. Development (SQLite, in-process queue)

```bash
pip install -r requirements.txt -r requirements-dev.txt
cp .env.example .env && python scripts/generate_secrets.py --write
uvicorn app.main:app --host 127.0.0.1 --port 8080 --reload
```

`DB_AUTO_CREATE=true` creates tables at startup. SQLite uses WAL mode and is suitable for one
process only.

## 3. Compose pilot

`compose.yaml` runs `api`, `worker`, `postgres:16`, `redis:7` and, under
`--profile observability`, `otel-collector`, `prometheus` and `grafana`.

```bash
cp .env.example .env && python scripts/generate_secrets.py --write
docker compose up --build -d
docker compose ps
curl -s http://127.0.0.1:8080/ready
```

Properties of the stack:

- API bound to `127.0.0.1:8080`; Prometheus `127.0.0.1:9090`; Grafana `127.0.0.1:3000`.
- `DATABASE_URL`, `REDIS_URL`, `SCAN_ROOT`, `AUDIT_JSONL_PATH` are set by compose and override `.env`.
- API container: `RUN_MIGRATIONS=true`, `WORKERS_INPROCESS=false`. Worker: `WORKER_CONCURRENCY` (default 4).
- Both containers: read-only root FS, `tmpfs /tmp`, `cap_drop ALL`, `no-new-privileges`, PID limit, memory and CPU limits.
- `./targets` is mounted read-only at `/app/targets` for repo-type assets. No Docker socket, no other host paths.
- Redis runs with `appendonly yes`, `maxmemory-policy noeviction` (eviction would drop jobs).
- Postgres data, Redis AOF, audit JSONL and Prometheus/Grafana state are named volumes.

TLS for a single host: `compose.prod.yaml` adds Caddy (ACME certificates, HSTS, `/metrics`
blocked), sets `APP_ENV=production`, `COOKIE_SECURE=true`, `LOG_JSON=true`,
`FORWARDED_ALLOW_IPS=*` (Caddy is the only client on the internal network), `restart: always`
and log rotation. Set `SENTINEL_DOMAIN` and `ACME_EMAIL` in `.env`.

```bash
docker compose -f compose.yaml -f compose.prod.yaml up -d
```

Upgrades: pull or build the new image, `docker compose up -d`; the API applies migrations at
start. Back up the Postgres volume first (`pg_dump` from the `postgres` container).

## 4. Kubernetes (Helm)

Chart: `infra/helm/sentinel`.

```bash
kubectl create namespace sentinel
kubectl -n sentinel create secret generic sentinel-secrets \
  --from-literal=SESSION_SECRET="$(python -c 'import secrets;print(secrets.token_urlsafe(48))')" \
  --from-literal=ADMIN_PASSWORD="$(python -c 'import secrets;print(secrets.token_urlsafe(24))')" \
  --from-literal=INGEST_API_KEY="$(python -c 'import secrets;print(secrets.token_urlsafe(40))')" \
  --from-literal=AUDIT_SIGNING_KEY="$(python -c 'import secrets;print(secrets.token_hex(32))')"   --from-literal=DATA_ENCRYPTION_KEY="$(python -c 'import secrets;print(secrets.token_urlsafe(32))')" \
  --from-literal=DATABASE_URL='postgresql+psycopg://sentinel:...@postgres:5432/sentinel?sslmode=require' \
  --from-literal=REDIS_URL='rediss://:...@redis:6379/0'
helm upgrade --install sentinel infra/helm/sentinel -n sentinel \
  --set existingSecret=sentinel-secrets \
  --set image.digest=sha256:... \
  --set ingress.host=sentinel.example.com \
  --set config.BASE_URL=https://sentinel.example.com
```

What the chart renders:

- `Deployment` api (rolling, `maxUnavailable: 0`, startup/liveness `/health`, readiness `/ready`) and worker (exec liveness; the Redis lease reaper requeues jobs of a dead worker).
- `HorizontalPodAutoscaler` for the API (CPU and memory), `PodDisruptionBudget` for both.
- `ConfigMap` from `values.config`, `Secret` from `values.secrets` unless `existingSecret` is set (recommended; pods roll on checksum change).
- `Service`, `Ingress` with TLS and nginx annotations (`/metrics` denied by server snippet; adapt for other controllers).
- `NetworkPolicy`: default deny; API ingress from the ingress-controller namespace (and the monitoring namespace when `serviceMonitor.enabled`); egress allows DNS plus the list in `networkPolicy.egress` (Postgres, Redis, HTTPS). Workers get the same egress because collectors and adapters run there.
- `ServiceAccount` with `automountServiceAccountToken: false`; annotate it for IRSA or Workload Identity if the audit sink uses S3 or Azure.
- Pod security: non-root UID 10001, read-only root FS, all capabilities dropped, seccomp RuntimeDefault, `emptyDir` for `/tmp` and `/app/data` (or a RWX PVC when `auditVolume.enabled`).
- Optional `ServiceMonitor` for the Prometheus operator.

Database and Redis are not part of the chart; use managed services or your own operators.

## 5. AWS (Terraform)

`infra/terraform` builds a VPC, ECS Fargate services for API and worker, RDS PostgreSQL 16
(Multi-AZ, CMK, forced SSL), ElastiCache Redis 7 (TLS, AUTH, noeviction), an S3 audit bucket
with Object Lock in compliance mode (task role may only `PutObject`), Secrets Manager entries
injected as task secrets, an ALB with TLS 1.3 and `/metrics` blocked, AWS WAF (rate limit,
common rules, known bad inputs, IP reputation, logs with auth headers redacted), KMS-encrypted
CloudWatch log groups and alarms. Read `infra/terraform/README.md` for the decisions you must
make (retention, egress, state backend) before applying.

## 6. Azure (Terraform)

`infra/terraform-azure` builds a VNet, a Container Apps environment (internal, zone
redundant) with API and worker apps using a user-assigned identity, PostgreSQL Flexible
Server (zone-redundant HA, private DNS, `require_secure_transport`), Azure Cache for Redis
(TLS, private endpoint), a GZRS storage account with an immutable container for the audit
mirror, Key Vault (RBAC, purge protection) with generated secrets, Log Analytics and
Application Insights, and Front Door Premium with a WAF policy (rate limit, DRS 2.1, bot
manager) plus HSTS and `/metrics` blocked. Read `infra/terraform-azure/README.md` for the
Front Door origin and immutability-lock decisions.

## 7. Configuration contract

Startup fails (`assert_safe_config`) when:

- `SESSION_SECRET` is shorter than 32 characters or still a `REPLACE_` placeholder;
- `ADMIN_PASSWORD` is shorter than 14 characters or a placeholder;
- `INGEST_API_KEY` is set but shorter than 24 characters;
- `APP_ENV=production` with SQLite, without `REDIS_URL`, without `COOKIE_SECURE=true`, with a non-`https://` `BASE_URL`, without `DATA_ENCRYPTION_KEY` (or `DATA_ENCRYPTION_KEYS`), without `AUDIT_SIGNING_KEY` (or `AUDIT_SIGNING_KEYS`), without an audit sink (`AUDIT_JSONL_PATH`, `AUDIT_S3_BUCKET` or `AUDIT_AZURE_CONTAINER`), or without `TOTP_REQUIRED=true` / `OIDC_ISSUER`;
- `AI_PROVIDER=anthropic` without `ANTHROPIC_API_KEY` (or an Anthropic auth profile), or `AI_PROVIDER=openai` without `OPENAI_API_KEY`.

Reverse proxies: the API trusts `X-Forwarded-*` only from `FORWARDED_ALLOW_IPS`. Set it to
the proxy address (compose: `*` on the isolated network; Kubernetes: `*` behind the network
policy; ALB/Front Door: `*` because the security group or environment restricts clients).
`BASE_URL` must be the public origin; it feeds OIDC redirect URIs and canary URLs.

Secrets referenced by collectors and integrations use `secret_ref` strings: `env:NAME`,
`file:/path`, `secrets:KEY` (with `SECRETS_BACKEND=file` and `SECRETS_FILE`). Values are
resolved at run time and never stored.

Audit sinks: `AUDIT_JSONL_PATH` (local append-only file), `AUDIT_S3_BUCKET` +
`AUDIT_S3_PREFIX` (needs `boto3` from `requirements-optional.txt` and an IAM principal),
`AUDIT_AZURE_CONTAINER` + `AUDIT_AZURE_CONNECTION_STRING` (needs `azure-storage-blob`).
A sink failure is logged and never blocks the operation; the database chain remains the
source of truth and `GET /api/v1/audit/verify` recomputes it.

## 8. Observability

- Metrics: `/metrics` with `sentinel_http_requests_total`, `sentinel_http_request_seconds`, `sentinel_jobs_total`, `sentinel_agent_tokens_total`, `sentinel_agent_runs_total`, `sentinel_findings_open`, `sentinel_actions_total`, `sentinel_detections_total`.
- Prometheus config and alert rules: `infra/prometheus/`.
- Grafana dashboard: `infra/grafana/sentinel.json` (provisioned automatically in the compose profile).
- Traces: set `OTEL_EXPORTER_OTLP_ENDPOINT` (OTLP/HTTP, e.g. `http://otel-collector:4318/v1/traces`); requires the `opentelemetry-*` extras (`EXTRAS=1` image). Collector config: `infra/otel/otel-collector.yaml`.
- Logs: `LOG_JSON=true` emits one JSON object per line with `request_id`, `tenant_id`, `job_id`, `run_id` when present. Secrets are redacted before persistence; do not log request bodies at the proxy.

## 9. Production checklist

The ordered, command-level version of this list for a monitoring-only rollout is `docs/GO-LIVE.md`.

Identity and access

- [ ] OIDC configured (`OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`), `OIDC_ALLOWED_DOMAINS` set, `OIDC_DEFAULT_ROLE=viewer`.
- [ ] `TOTP_REQUIRED=true`; the bootstrap owner enrolled TOTP; `ADMIN_PASSWORD` rotated after first login and stored in the secret manager.
- [ ] Sensor API keys created with role `viewer` and scope `ingest`; the bootstrap `INGEST_API_KEY` revoked once per-sensor keys exist.
- [ ] Memberships reviewed; owners limited to named people.

Platform

- [ ] `APP_ENV=production`, `COOKIE_SECURE=true`, `BASE_URL` is the HTTPS origin, `SESSION_MAX_AGE` fits your policy.
- [ ] PostgreSQL with TLS, automated backups, tested restore. `DB_AUTO_CREATE=false` once migrations own the schema.
- [ ] Redis with TLS and AUTH, persistence on, `noeviction`.
- [ ] Workers separate from the API (`WORKERS_INPROCESS=false`), sized for collector and test-tool workloads; worker egress restricted to known destinations.
- [ ] Image pinned by digest, signature verified (`cosign verify`), SBOM retained.
- [ ] `/metrics` unreachable from the internet; health endpoints reachable by the load balancer only.
- [ ] Rate limiting at the edge in addition to the in-process limiter.

Audit and evidence

- [ ] `AUDIT_SIGNING_KEY` set and stored with the other secrets; rotation procedure read (`docs/RUNBOOKS.md`).
- [ ] `DATA_ENCRYPTION_KEY` set and stored with the other secrets (rotation: `DATA_ENCRYPTION_KEYS=k2=<new>,k1=<old>`).
- [ ] Object-lock sink configured (S3 Object Lock compliance or Azure immutable container) with a deliberate retention period.
- [ ] `GET /api/v1/audit/verify` returns `valid: true` after deployment and is checked on a schedule.

Agents, testing, actions

- [ ] `AI_PROVIDER` chosen deliberately; data-handling terms of the provider reviewed; budgets (`AGENT_*`) set.
- [ ] Prompt-injection eval suite run against the configured provider and model (`POST /api/v1/evals/run`, suite `prompt_injection`).
- [ ] `ALLOW_PRIVATE_TARGETS=false` unless an explicit `PRIVATE_TARGET_CIDRS` allowlist and worker egress rules exist.
- [ ] External tools (nuclei templates, ZAP, Prowler, CALDERA, Semgrep, Gitleaks, Trivy) installed only in worker images, from pinned versions.
- [ ] `ACTIONS_KILL_SWITCH` understood by the on-call rota; `ACTIONS_AUTO_APPROVE_LOW=false` until the policy is reviewed; `actions_enabled` left false for tenants that have not signed off.
- [ ] Signed scope documents referenced from `TestScope.signed_document_ref` and `AssetAuthorization.scope_document_ref`.

Operations

- [ ] Alerts from `infra/prometheus/rules/sentinel.yml` (or the CloudWatch / Azure Monitor equivalents) routed to a pager.
- [ ] Runbooks read by the on-call team; a dry run of "lost worker" and "revoke API key" performed.
- [ ] Log retention and PII handling agreed; logs contain no secrets by construction, but event payloads may contain personal data from your sensors.
