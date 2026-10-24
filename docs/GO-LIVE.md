# Go-live: production rollout in monitoring-only mode

This is the ordered, command-level checklist for putting Argus into production for a new
customer estate with **no automated change**: kill switch engaged, intrusive testing off, AI
provider deliberately chosen (`none` is fine), collectors read-only. Everything here was
executed against the compose stack on 2026-10-23 with the current image; where a step was
verified by `scripts/smoke_test.py` it says so. Tick every box in order. Background and
rationale live in `docs/DEPLOYMENT.md`; incident procedures in `docs/RUNBOOKS.md`.

Conventions: `$BASE` is the public HTTPS origin (`https://argus.example.com`), `$JAR` a
curl cookie jar, `$CSRF` the token returned by login. Compose commands run in the directory that
holds `compose.yaml` and `.env`; Kubernetes/ECS/Container Apps equivalents are noted inline.

Use the commands as written. In production `COOKIE_SECURE=true`, so every session call must go to
the **https** origin (a cookie jar will silently drop the cookie over plain http, including from
inside the container).

---

## 0. What "monitoring-only" means in configuration

| Control | Setting | Effect |
|---|---|---|
| Action broker | `ACTIONS_KILL_SWITCH=true` | `request()` and the `actions.execute` handler reject everything with `policy_denied`; queued jobs re-check at execution time |
| Tenant actions | `actions_enabled=false` (default for every new tenant) | second, per-tenant gate; leave it off until the customer signs off |
| Auto-approval | `ACTIONS_AUTO_APPROVE_LOW=false` | nothing executes without human approval even after the switch is lifted |
| Executor credentials | do not set the `action_credentials` tenant setting | the broker has nothing to act with |
| Scheduled testing | `AUTOSCAN_ENABLED=false` | no test plans run on a timer |
| Active / intrusive tools | `NUCLEI_TEMPLATES=`, `ZAP_URL=`, `CALDERA_URL=`, `ENABLE_TRIVY=false` | adapters report unavailable |
| Private targets | `ALLOW_PRIVATE_TARGETS=false`, `PRIVATE_TARGET_CIDRS=` | RFC1918 and loopback targets denied |
| Authorizations | create **no** `POST /api/v1/assets/{id}/authorize` records | without an authorization nothing beyond passive inventory is permitted |
| AI | `AI_PROVIDER=none` (or `anthropic` / `openai` with a key once data-handling terms are signed) | with `none`, specialists use deterministic fallbacks; nothing leaves the estate |
| Collectors | read-only credentials only (see 4.4) | collectors only ever read; they must be given read-only roles anyway |

Verification after boot (step 3.4): `GET /api/v1/actions/kill-switch` returns
`{"global":true,"tenant_engaged":true,"actions_enabled":false,"effective":true}`.

---

## 1. Prerequisites (owned by the platform team, done before the change window)

### 1.1 PostgreSQL 16
- [ ] Managed instance or `postgres:16` with TLS; connection string `postgresql+psycopg://argus:<pw>@<host>:5432/argus?sslmode=require`.
- [ ] Database `argus`, role `argus` owning it; no superuser.
- [ ] Automated backups + PITR on; restore rehearsed (section 7).
- [ ] Compose shape: the `postgres` service in `compose.yaml` (`--data-checksums`, named volume). Set a strong `POSTGRES_PASSWORD`.

### 1.2 Redis 7
- [ ] TLS and AUTH: `rediss://:<pw>@<host>:6379/0` (Azure uses port 6380).
- [ ] `maxmemory-policy noeviction`, persistence on (`appendonly yes`). Eviction drops jobs.
- [ ] Compose shape: the `redis` service already runs with `--appendonly yes --maxmemory-policy noeviction`.

### 1.3 TLS and ingress
- [ ] Compose: `compose.prod.yaml` adds Caddy with ACME. Needs inbound 80/443 (443 UDP for h3) and outbound 443 to the ACME CA; set `ARGUS_DOMAIN` and `ACME_EMAIL` (both required; `up` refuses to start without them). DNS A/AAAA for `ARGUS_DOMAIN` must resolve before `up`.
- [ ] Kubernetes: ingress-nginx + cert-manager (`ingress.annotations` in `values.yaml`). The chart does not block `/metrics` (ingress-nginx 1.12+ rejects `server-snippet`); block it at the edge or set `config.METRICS_ENABLED="false"` as described in `docs/DEPLOYMENT.md` section 4.
- [ ] AWS/Azure Terraform: ALB TLS1.3 / Front Door Premium already block `/metrics`.
- [ ] `/metrics` and `/health` must not be reachable from the internet. Prometheus scrapes on the internal network.
- [ ] Edge rate limiting in front of the in-process limiter (Caddy/WAF/nginx `limit-rps`).

### 1.4 Egress allowlist for API and worker
Outbound from the API and worker containers, nothing else:

| Destination | Port | Why |
|---|---|---|
| PostgreSQL | 5432 | database |
| Redis | 6379 / 6380 | queue |
| ACME CA (`acme-v02.api.letsencrypt.org`) | 443 | Caddy only, compose shape |
| OIDC issuer | 443 | only when `OIDC_ISSUER` is set |
| Object-lock sink endpoint (S3 or Azure Blob) | 443 | only when `AUDIT_S3_BUCKET` / `AUDIT_AZURE_CONTAINER` is set |
| Outbound channels (Slack, PagerDuty, Jira, ServiceNow, SMTP, webhook) | 443 / 587 | only for integrations you create |
| Cloud / IdP APIs for collectors | 443 | only for collectors you create (read-only) |
| Model provider | 443 | only when `AI_PROVIDER` is not `none` |

Nothing inbound to the worker. With `AI_PROVIDER=none` and no collectors, the worker needs only Postgres and Redis.

### 1.5 Image
- [ ] Pin by digest: `ARGUS_IMAGE=ghcr.io/<owner>/argus@sha256:<digest>` in `.env` (Helm: `image.digest`; Terraform: `image` variable).
- [ ] Verify the signature before pulling anywhere near production:
  ```bash
  cosign verify "ghcr.io/<owner>/argus@sha256:<digest>" \
    --certificate-identity-regexp 'https://github.com/<owner>/argus/.github/workflows/release.yml@refs/tags/.*' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
  ```
- [ ] Record the digest and the previous production digest in the change ticket (section 8 needs it).

### 1.6 Host (compose shape)
- [ ] Docker Engine 24+ with Compose v2; 4 vCPU / 8 GB minimum (api 1 GB + worker 2 GB limits + Postgres + Redis + Caddy).
- [ ] Time synchronised (TOTP tolerates +-30 s only).
- [ ] `./targets` directory exists (mounted read-only; may stay empty).

---

## 2. Required environment and how to generate it

Copy the template and generate the random values; **never** reuse values between environments or customers.

```bash
cp .env.example .env
python scripts/generate_secrets.py --write      # fills ADMIN_PASSWORD, SESSION_SECRET, INGEST_API_KEY, AUDIT_SIGNING_KEY, DATA_ENCRYPTION_KEY
chmod 600 .env
```

Then set these by hand. Every one of them is enforced by `assert_safe_config` at startup when
`APP_ENV=production` (verified: the API refuses to start with any of them missing).

| Variable | Value for monitoring-only production | How to generate / notes |
|---|---|---|
| `APP_ENV` | `production` | |
| `BASE_URL` | `https://<ARGUS_DOMAIN>` | must start with `https://` |
| `COOKIE_SECURE` | `true` | |
| `SESSION_SECRET` | 64 random chars | `python -c 'import secrets;print(secrets.token_urlsafe(48))'` |
| `SESSION_MAX_AGE` | `3600` (or your policy) | seconds |
| `DB_AUTO_CREATE` | `false` | Alembic owns the schema |
| `DATABASE_URL` | `postgresql+psycopg://...?sslmode=require` | from 1.1 |
| `REDIS_URL` | `rediss://:<pw>@<host>:<port>/0` | from 1.2; compose sets `redis://redis:6379/0` on the internal network |
| `WORKERS_INPROCESS` | `false` | compose and Helm set it; the worker owns job execution |
| `ADMIN_EMAIL` | the break-glass owner mailbox | |
| `ADMIN_PASSWORD` | 32 random chars | `secrets.token_urlsafe(24)`; rotated in step 3.6 and stored in the vault |
| `INGEST_API_KEY` | **empty** | per-sensor keys are minted in step 3.10; a value here is re-created as a key on every boot |
| `TOTP_REQUIRED` | `true` | required unless `OIDC_ISSUER` is set; enrolment happens in step 3.7 |
| `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_ALLOWED_DOMAINS`, `OIDC_DEFAULT_ROLE=viewer` | as agreed with the customer IdP, or empty | recommended for humans; without OIDC there is no self-service password change (see 3.9) |
| `AUDIT_SIGNING_KEY` | 64 hex chars | `secrets.token_hex(32)`; rotation runbook in RUNBOOKS.md |
| `DATA_ENCRYPTION_KEY` | 32 random bytes, base64url | `python -c 'import secrets;print(secrets.token_urlsafe(32))'`; encrypts TOTP seeds and stored credentials; rotation: `DATA_ENCRYPTION_KEYS=k2=<new>,k1=<old>` |
| `AUDIT_JSONL_PATH` | `/app/data/audit.jsonl` | compose sets it; Helm needs `auditVolume.enabled=true` (RWX) or an object-lock sink |
| `AUDIT_S3_BUCKET` / `AUDIT_AZURE_CONTAINER` (+ connection string) | the object-lock bucket when available | needs the `-extras` image (`boto3` / `azure-storage-blob`) |
| `LOG_JSON` | `true` | |
| `AI_PROVIDER` | `none` | or `anthropic` + `ANTHROPIC_API_KEY`, `openai` + `OPENAI_API_KEY` |
| `ACTIONS_KILL_SWITCH` | `true` | section 0 |
| `ACTIONS_AUTO_APPROVE_LOW` | `false` | |
| `AUTOSCAN_ENABLED` | `false` | |
| `ALLOW_PRIVATE_TARGETS` | `false` | |
| `ENABLE_TRIVY`, `NUCLEI_TEMPLATES`, `ZAP_URL`, `CALDERA_URL` | `false` / empty | |
| `RUN_MIGRATIONS` | `true` on the API | compose and Helm set it; the worker never migrates |
| `FORWARDED_ALLOW_IPS` | `*` behind Caddy/ingress/ALB on an isolated network | compose.prod.yaml sets it |
| `POSTGRES_PASSWORD` | 32 random chars | compose `postgres` service only |
| `ARGUS_DOMAIN`, `ACME_EMAIL` | public hostname, ops mailbox | compose.prod.yaml only |
| `ARGUS_IMAGE` | `ghcr.io/<owner>/argus@sha256:<digest>` | from 1.5 |
| `GITHUB_WEBHOOK_SECRET`, `OKTA_HOOK_SECRET` | random 32+ chars | only if you connect those webhooks (4.4/4.5); referenced as `env:NAME` |

Kubernetes: the same keys go in the `existingSecret` (`SESSION_SECRET ADMIN_PASSWORD INGEST_API_KEY AUDIT_SIGNING_KEY DATA_ENCRYPTION_KEY DATABASE_URL REDIS_URL`, optional `OIDC_CLIENT_SECRET` ...) and `values.config`. AWS/Azure Terraform generate all of them except the OIDC/model keys.

Quick check before starting anything (no containers needed):

```bash
docker run --rm --env-file .env -e DATABASE_URL=postgresql+psycopg://x:x@localhost/x -e REDIS_URL=rediss://localhost/0 -e AUDIT_JSONL_PATH=/app/data/audit.jsonl "$ARGUS_IMAGE" \
  python -c "from app.core.config import get_settings, assert_safe_config; assert_safe_config(get_settings()); print('config ok')"
```

---

## 3. First boot

- [ ] **3.1 Back up** the previous state if this is an upgrade (section 7). Fresh install: skip.
- [ ] **3.2 Start the data stores** and wait for health:
  ```bash
  docker compose -f compose.yaml -f compose.prod.yaml pull
  docker compose -f compose.yaml -f compose.prod.yaml up -d postgres redis
  docker compose ps            # postgres and redis "healthy"
  ```
- [ ] **3.3 Migrate explicitly**, then start the API and worker (the API would also migrate on start; doing it first gives a clean log line to attach to the ticket):
  ```bash
  docker compose -f compose.yaml -f compose.prod.yaml run --rm --no-deps api migrate
  docker compose -f compose.yaml -f compose.prod.yaml run --rm --no-deps api python scripts/migrate.py --current   # expect "Rev: <head>"
  docker compose -f compose.yaml -f compose.prod.yaml up -d api worker caddy
  ```
  Kubernetes: `helm upgrade --install ...` (the API pods migrate, `maxUnavailable: 0`). ECS/Container Apps: the API task migrates at start.
- [ ] **3.4 Health, readiness, kill switch**:
  ```bash
  curl -fsS "$BASE/health"      # {"status":"healthy","version":"1.0.0"}
  curl -fsS "$BASE/ready"       # {"status":"ready","queue":"redis","provider":"none"}
  docker compose logs --tail=50 api worker   # "Argus 1.0.0 started (env=production, provider=none, queue=redis)" and "worker started with 12 handlers"
  ```
  `queue` must say `redis`; `memory` means `REDIS_URL` is not set and the worker is idle.
- [ ] **3.5 Log in as the bootstrap owner** (`ADMIN_EMAIL` / `ADMIN_PASSWORD`). With `TOTP_REQUIRED=true` and no enrolment yet the response carries `"mfa_required": true`; that session may only enrol TOTP:
  ```bash
  JAR=$(mktemp)
  curl -fsS -c "$JAR" -b "$JAR" -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
    -d '{"email":"'"$ADMIN_EMAIL"'","password":"'"$ADMIN_PASSWORD"'"}'
  # {"authenticated":true,"csrf":"...","tenant_id":"...","mfa":false,"mfa_required":true,"enroll_uri":null}
  ```
  Eight failed attempts per source IP lock login for five minutes.
- [ ] **3.6 Enrol TOTP for the bootstrap owner**, then verify:
  ```bash
  curl -fsS -c "$JAR" -b "$JAR" -X POST "$BASE/api/v1/auth/totp/enroll"
  # {"secret":"<base32>","uri":"otpauth://totp/Argus:admin@...?secret=...&issuer=Argus&digits=6&period=30"}
  #   -> load the uri into the team's hardware/soft token; store the secret in the vault as the break-glass seed
  curl -fsS -c "$JAR" -b "$JAR" -X POST "$BASE/api/v1/auth/totp/verify" -H 'Content-Type: application/json' -d '{"code":"123456"}'
  # {"ok":true,"csrf":"<token>"}        <- export CSRF=<token>; every mutating call below needs -H "X-CSRF-Token: $CSRF"
  curl -fsS -b "$JAR" "$BASE/api/v1/auth/session"     # "authenticated":true, "role":"owner", "user":{"totp_enabled":true}
  ```
  From now on login is `{"email":...,"password":...,"totp":"<code>"}`.
- [ ] **3.7 Rotate the bootstrap password the right way.** `bootstrap()` re-applies `ADMIN_PASSWORD` from the environment on **every** start, so a password changed through the API would be reverted at the next restart. Rotate it in the secret store and restart:
  ```bash
  NEW=$(python -c 'import secrets;print(secrets.token_urlsafe(24))')
  sed -i "s|^ADMIN_PASSWORD=.*|ADMIN_PASSWORD=$NEW|" .env      # Kubernetes: patch the Secret; ECS: new secret version; Container Apps: Key Vault version
  docker compose -f compose.yaml -f compose.prod.yaml up -d api
  # store $NEW in the vault, delete it from the shell history, re-login (step 3.5 with totp)
  ```
  The audit log shows `user.password_reset` with `bootstrap: true`.
- [ ] **3.8 Create one tenant per customer estate** (the creator becomes its owner), and switch into it:
  ```bash
  curl -fsS -b "$JAR" -H "X-CSRF-Token: $CSRF" -X POST "$BASE/api/v1/admin/tenants" -H 'Content-Type: application/json' \
    -d '{"slug":"<customer-slug>","name":"<Customer legal name>"}'
  # {"id":"...","slug":"...","name":"...","is_active":true,"actions_enabled":false,"role":"owner"}
  curl -fsS -c "$JAR" -b "$JAR" -H "X-CSRF-Token: $CSRF" -X POST "$BASE/api/v1/auth/switch-tenant" -H 'Content-Type: application/json' \
    -d '{"tenant":"<customer-slug>"}'
  # {"ok":true,"tenant_id":"...","csrf":"<new token>"}   <- switch-tenant rotates the CSRF token: export CSRF again
  ```
  Repeat per estate (slug: 2-64 chars, `[a-z0-9-]`). Confirm `actions_enabled` is `false` on each. Keep the `default` tenant for operators only; do not point sensors at it.
- [ ] **3.9 Invite users** into the current tenant. With OIDC configured, invite (no password; they sign in through SSO with `OIDC_DEFAULT_ROLE`, then you raise the role):
  ```bash
  curl -fsS -b "$JAR" -H "X-CSRF-Token: $CSRF" -X POST "$BASE/api/v1/admin/users" -H 'Content-Type: application/json' \
    -d '{"email":"analyst@customer.example","display_name":"Analyst Name","role":"analyst","invite":true}'
  ```
  Without OIDC, omit `invite` and the response contains `temporary_password`; deliver it out of band. **Known gap:** there is no self-service password-change endpoint; an admin resets with `POST /api/v1/admin/users/{id}/reset-password {"password": "..."}`. Prefer OIDC for every human. Roles: `viewer < analyst < operator < admin < owner`; keep owners to named people. `POST /api/v1/admin/memberships {"user_id","role"}` changes a role.
- [ ] **3.10 Mint one ingest key per sensor, per tenant** (switch tenant first; the key is bound to the session's tenant). Role `viewer`, scope `ingest`, nothing else:
  ```bash
  curl -fsS -b "$JAR" -H "X-CSRF-Token: $CSRF" -X POST "$BASE/api/v1/auth/api-keys" -H 'Content-Type: application/json' \
    -d '{"name":"wazuh-<site>","role":"viewer","scopes":["ingest"]}'
  # {"id":"...","name":"wazuh-<site>","prefix":"53e90648","role":"viewer","scopes":["ingest"],"key":"argus_53e90648_..."}   <- "key" is shown once
  ```
  One key each for `wazuh-<site>`, `falco-<cluster>`, `cloudtrail-<account>`, `okta-<org>`, `github-<org>`. Put each in the sensor's own secret store. Revocation: `DELETE /api/v1/auth/api-keys/{id}` (RUNBOOKS.md "Revoking a compromised API key"). If `INGEST_API_KEY` was ever set in `.env`, revoke the `bootstrap-ingest` key listed by `GET /api/v1/auth/api-keys` **and** remove the variable, or it comes back on the next boot.
- [ ] **3.11 Audit chain baseline** per tenant and attach to the ticket:
  ```bash
  curl -fsS -b "$JAR" "$BASE/api/v1/audit/verify"
  # {"valid":true,"checked":N,"signed":true,"key_id":"...","note":"..."}
  ```
  Schedule the same call (read-only API key, `audit:read`) hourly; a `valid:false` is S1 (RUNBOOKS.md).

---

## 4. Connecting the first sensors

All push endpoints are `POST $BASE/api/v1/ingest/<source>` with `X-API-Key: <sensor key>` and a JSON body (object or array, max 500 items / 2 MB). Response: `{"source":...,"received":N,"accepted":N,"duplicates":N,"event_ids":[...],"errors":[...]}`. `GET $BASE/api/v1/integrations/types` lists every parser. Optional header `X-Asset-Id: <asset id>` ties events to an inventory asset.

### 4.1 Wazuh (manager integration or indexer pull)
Accepts a raw alert, an indexer hit (`_source`), or a whole search response (`hits.hits[]`). Wazuh rule levels map 13+ critical, 10+ high, 6+ medium, 3+ low.
```bash
curl -fsS -X POST "$BASE/api/v1/ingest/wazuh" -H "X-API-Key: $WAZUH_KEY" -H 'Content-Type: application/json' \
  --data-binary @examples/wazuh-alert.json
```
Manager side: a custom integration (`/var/ossec/integrations/custom-argus`) that POSTs each alert JSON line to that URL with the header; or set `WAZUH_INDEXER_URL`/`WAZUH_INDEXER_USER`/`WAZUH_INDEXER_PASSWORD`/`WAZUH_CA_BUNDLE` for the read-only indexer poll (`integrations.wazuh_sync` job).

### 4.2 Falco (falcosidekick webhook)
```bash
curl -fsS -X POST "$BASE/api/v1/ingest/falco" -H "X-API-Key: $FALCO_KEY" -H 'Content-Type: application/json' \
  --data-binary @examples/falco-alert.json
```
falcosidekick config: `webhook.address: https://<ARGUS_DOMAIN>/api/v1/ingest/falco`, `webhook.customHeaders: "X-API-Key:<key>"`, `webhook.minimumpriority: notice`.

### 4.3 AWS CloudTrail (EventBridge API destination, or a forwarder reading the S3 trail)
Body is `{"Records":[...]}`, a single record, or the EventBridge "AWS API Call via CloudTrail" envelope. This exact record trips `cloud.public_exposure_change` (verified; use it in step 5):
```bash
curl -fsS -X POST "$BASE/api/v1/ingest/aws_cloudtrail" -H "X-API-Key: $CLOUDTRAIL_KEY" -H 'Content-Type: application/json' -d '{
  "Records": [{
    "eventVersion": "1.09", "eventTime": "'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'", "eventSource": "s3.amazonaws.com", "eventName": "PutBucketPolicy",
    "awsRegion": "us-east-1", "sourceIPAddress": "203.0.113.10", "userAgent": "aws-cli/2.15.0", "eventID": "golive-synthetic-public-bucket-1",
    "eventType": "AwsApiCall", "readOnly": false, "recipientAccountId": "123456789012",
    "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::123456789012:user/golive-synthetic", "accountId": "123456789012", "userName": "golive-synthetic"},
    "requestParameters": {"bucketName": "golive-synthetic-bucket",
      "bucketPolicy": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::golive-synthetic-bucket/*"}]}},
    "resources": [{"ARN": "arn:aws:s3:::golive-synthetic-bucket", "type": "AWS::S3::Bucket"}]
  }]
}'
```
EventBridge: rule on `detail-type: AWS API Call via CloudTrail` -> API destination `https://<ARGUS_DOMAIN>/api/v1/ingest/aws_cloudtrail`, connection auth type *API key*, header name `X-API-Key`.

### 4.4 Okta (event hook with signature, or System Log pull)
Preferred: the verified webhook path, which authenticates Okta's static header instead of an API key. Put the shared secret in the API container's environment (`.env`: `OKTA_HOOK_SECRET=<32+ random chars>`), then create an inbound integration in the customer tenant:
```bash
curl -fsS -b "$JAR" -H "X-CSRF-Token: $CSRF" -X POST "$BASE/api/v1/integrations" -H 'Content-Type: application/json' \
  -d '{"name":"okta-<org>","kind":"okta_logs","config":{"auth_header_name":"Authorization"},"secret_refs":{"auth_header":"env:OKTA_HOOK_SECRET"}}'
# {"id":"<integration id>", ...}
```
Okta Admin -> Workflow -> Event Hooks: URL `https://<ARGUS_DOMAIN>/api/v1/ingest/okta/verify?integration=<integration id>`, authentication field `Authorization`, value `<OKTA_HOOK_SECRET>`; subscribe to `user.session.start`, `user.account.privilege.grant`, `group.privilege.grant`, `user.mfa.factor.*`, `system.api_token.create`, `user.session.impersonation.*`, `policy.*`. Okta's one-time verification (`GET` with `X-Okta-Verification-Challenge`) is answered automatically. `literal:` secret refs are refused in production; use `env:` or `file:`.

Fallback (API key, System Log array):
```bash
curl -fsS -X POST "$BASE/api/v1/ingest/okta" -H "X-API-Key: $OKTA_KEY" -H 'Content-Type: application/json' \
  --data-binary @tests/fixtures/integrations/okta_logs/system_log.json
```
A read-only Okta collector (`POST /api/v1/collectors`, kind `okta`) needs a *Read-only Administrator* API token.

### 4.5 GitHub (organization webhook with HMAC signature)
```bash
# .env: GITHUB_WEBHOOK_SECRET=<32+ random chars>, then:
curl -fsS -b "$JAR" -H "X-CSRF-Token: $CSRF" -X POST "$BASE/api/v1/integrations" -H 'Content-Type: application/json' \
  -d '{"name":"github-<org>","kind":"github_webhook","secret_refs":{"webhook_secret":"env:GITHUB_WEBHOOK_SECRET"}}'
```
GitHub org -> Settings -> Webhooks: payload URL `https://<ARGUS_DOMAIN>/api/v1/ingest/github/verify?integration=<integration id>`, content type `application/json`, secret `<GITHUB_WEBHOOK_SECRET>`, events: *Secret scanning alerts, Code scanning alerts, Dependabot alerts, Repositories, Members, Organizations, Branch protection rules*. Signature is `X-Hub-Signature-256` over the raw body.

API-key test without GitHub (the event kind comes from the header):
```bash
curl -fsS -X POST "$BASE/api/v1/ingest/github" -H "X-API-Key: $GITHUB_KEY" -H 'Content-Type: application/json' \
  -H 'X-GitHub-Event: secret_scanning_alert' --data-binary @tests/fixtures/integrations/github_webhook/secret_scanning_alert.json
```

### 4.6 Collector credentials (only if you create collectors on day 1)
Collectors never write, and their credentials must not be able to either: AWS `SecurityAudit` managed policy; Azure `Reader` + `Security Reader`; GCP `roles/viewer` + `roles/securitycenter.findingsViewer`; Kubernetes `view` ClusterRole; GitHub fine-grained token, read-only; Okta read-only admin; Entra `Directory.Read.All`. Reference them as `env:`/`file:` secret refs. A collector run is `POST /api/v1/collectors/{id}/run`; it reads inventory and posture only.

---

## 5. Verifying detections fire

**Pre-production rehearsal (staging or a scratch compose stack, `APP_ENV` not `production`).** The seed refuses to run against production. It creates an isolated `demo` tenant and runs the engine:
```bash
docker compose exec -T api python scripts/seed_demo.py --password '<demo owner pw>'
```
Expected (verified 2026-10-23 against the compose stack): `detections created=3 rules_run=12`, listing `cloud.public_exposure_change`, `swarm.machine_speed_sequence`, `swarm.novel_action_burst`. Then log in as `demo-owner@argus.local` / tenant `demo` and read `GET /api/v1/detections`.

**Production.** Use the synthetic CloudTrail record from 4.3 with the CloudTrail key of the tenant, then run the engine and read back (verified: produces one `cloud.public_exposure_change`, severity `high`, title `golive-synthetic-bucket opened to the internet via s3.put_bucket_policy`):
```bash
curl -fsS -b "$JAR" -H "X-CSRF-Token: $CSRF" -X POST "$BASE/api/v1/detections/run" -H 'Content-Type: application/json' -d '{"since_minutes":60}'
# {"job_id":"<id>","status":"queued"}
curl -fsS -b "$JAR" "$BASE/api/v1/ops/jobs/<id>"       # poll until "status":"completed"; "failed" or stuck "queued" = no worker (RUNBOOKS "Lost worker")
curl -fsS -b "$JAR" "$BASE/api/v1/detections?limit=5"  # items[].rule_id == "cloud.public_exposure_change"
```
Close the synthetic detection so it does not pollute the customer view:
```bash
curl -fsS -b "$JAR" -H "X-CSRF-Token: $CSRF" -X PATCH "$BASE/api/v1/detections/<detection id>" -H 'Content-Type: application/json' \
  -d '{"status":"false_positive","note":"go-live synthetic record, ticket <id>"}'
```
The detections scheduler then runs every 60 s per active tenant without further action.

---

## 6. Day-1 smoke test

`scripts/smoke_test.py` (standard library only) logs in, creates a `SMOKE` asset, mints a temporary ingest key, ingests one synthetic event through `/api/v1/ingest/generic`, confirms it is queryable, runs `detections.run` through the queue and waits for the worker, checks `/api/v1/detections/stats`, verifies the audit chain, then revokes the key, deletes the asset and logs out. Exit code 0 only when all ten steps pass.

```bash
# from an operator machine, against the public origin (required in production because of Secure cookies)
ARGUS_PASSWORD='<owner password>' ARGUS_TOTP_SECRET='<base32 seed from 3.6>' \
  python scripts/smoke_test.py --url "$BASE" --email "$ADMIN_EMAIL" --tenant <customer-slug>

# or with a one-time code instead of the seed
python scripts/smoke_test.py --url "$BASE" --email "$ADMIN_EMAIL" --totp 123456 --tenant <customer-slug>
```
Run it once per tenant. Expected tail: `OK: 10/10 steps passed`. A failure prints the step, the HTTP status and the `X-Request-ID` to grep in the API log. Verified 2026-10-23 against SQLite in-process (10/10) and against the compose stack with Redis and a dedicated worker (10/10).

---

## 7. Backup and restore

Back up **before** every upgrade and on a schedule. The database chain is the source of truth; the JSONL/object-lock mirror is the evidence copy.

```bash
# PostgreSQL (compose)
TS=$(date -u +%Y%m%dT%H%M%SZ)
docker compose exec -T postgres pg_dump -U argus -Fc argus > "argus-$TS.dump"
# Redis AOF (queue state; losing it only loses queued jobs)
docker compose exec -T redis redis-cli BGREWRITEAOF
docker run --rm -v "$(docker compose ps -q redis | xargs docker inspect -f '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Name}}{{end}}{{end}}')":/data:ro -v "$PWD":/backup alpine tar czf "/backup/redis-$TS.tgz" -C /data .
# Audit JSONL mirror (argus-data volume)
docker run --rm -v "$(docker compose ps -q api | xargs docker inspect -f '{{range .Mounts}}{{if eq .Destination "/app/data"}}{{.Name}}{{end}}{{end}}')":/data:ro -v "$PWD":/backup alpine tar czf "/backup/audit-$TS.tgz" -C /data .
# Caddy certificates: caddy-data volume (optional; ACME re-issues)
```
Managed services: RDS automated snapshots / Azure Flexible Server PITR; take a manual snapshot before the change window. Encrypt and ship the dumps off-host; they contain tenant data.

Restore (compose):
```bash
docker compose stop api worker
docker compose exec -T postgres pg_restore -U argus -d argus --clean --if-exists --no-owner < argus-<TS>.dump
docker compose up -d api worker
curl -fsS "$BASE/ready"
curl -fsS -b "$JAR" "$BASE/api/v1/audit/verify"     # expect valid:true; a restore older than the mirror is documented, not repaired (RUNBOOKS)
```
Rehearse the restore once on staging before go-live and record the time it took.

---

## 8. Rollback to the previous image

Decide **before** the upgrade whether the release is image-only or carries a schema/data-format change (the release notes must say). Image-only rollback:

```bash
# compose: pin the previous digest recorded in 1.5
sed -i 's|^ARGUS_IMAGE=.*|ARGUS_IMAGE=ghcr.io/<owner>/argus@sha256:<previous digest>|' .env
docker compose -f compose.yaml -f compose.prod.yaml pull api worker
docker compose -f compose.yaml -f compose.prod.yaml up -d api worker
curl -fsS "$BASE/ready" && docker compose logs --tail=30 api
```
Kubernetes: `helm rollback argus <previous revision> -n argus` (or `helm upgrade --set image.digest=<previous>`). ECS: `aws ecs update-service --task-definition <previous revision> --force-new-deployment` for `api` and `worker`. Container Apps: activate the previous revision.

If the new release ran a migration the old code cannot read, the rollback is a **database restore** (section 7) from the pre-upgrade dump, and data since the upgrade is lost; say so in the change ticket. `python scripts/migrate.py --current` shows the schema revision; `alembic downgrade <rev>` is only used when the migration author has confirmed the downgrade is safe for data written since. Note for this release: revision `95936aa8afb2` (encryption at rest, keyed audit signatures) writes `enc:v1:` values and key-id signatures that the previous image cannot interpret; rolling back across it requires the restore path.

After any rollback: run the smoke test (section 6) and `GET /api/v1/audit/verify`.

---

## 9. Who to page

Severity scale from `docs/RUNBOOKS.md`: **S1** security control failed or evidence integrity in doubt; **S2** platform degraded; **S3** single feature degraded. Fill the names before the change window; keep this table in the on-call tool, not only here.

| Trigger | Severity | Page | Runbook |
|---|---|---|---|
| `ArgusApiDown`, `/ready` 503 | S2 | Argus platform on-call: ____________ | API unavailable |
| `ArgusNoJobsCompleting`, `ArgusJobsFailing` | S2 (S1 if detections) | Argus platform on-call: ____________ | Lost worker / Redis down |
| `GET /api/v1/audit/verify` -> `valid:false` | S1 | Security lead: ____________ and platform on-call | Audit chain verification failure |
| `ArgusCanaryTripped` | S1 | Customer SOC lead for the tenant: ____________ | Handling a canary hit |
| API key exposure, unexpected `last_used_at` | S1 | Security lead: ____________ | Revoking a compromised API key |
| `ArgusHigh5xxRate`, `ArgusSlowRequests` | S3 | Platform on-call (business hours) | API unavailable |
| `ArgusCriticalFindingsOpen` | per tenant SLA | Customer SOC lead for the tenant | n/a |
| Any request to lift the kill switch | change approval | Service owner: ____________ + customer sign-off | Disabling actions via the kill switch |

Escalation: platform on-call -> service owner (____________) -> vendor engineering (____________). Alert routing comes from `infra/prometheus/rules/argus.yml` (or the CloudWatch / Azure Monitor equivalents created by Terraform); confirm a test alert reaches the pager before go-live.

---

## 10. Sign-off

- [ ] Sections 1-2 complete; `.env` (or Secret) reviewed by a second person; no `REPLACE_` values; `chmod 600`.
- [ ] Section 3 complete for every tenant; bootstrap password rotated; TOTP enrolled; `bootstrap-ingest` key absent or revoked.
- [ ] Section 4: at least one sensor per tenant delivering (`GET /api/v1/events?limit=1` in the tenant shows a fresh `received_at`).
- [ ] Section 5: synthetic detection fired and closed.
- [ ] Section 6: smoke test `10/10` per tenant, output attached to the ticket.
- [ ] Section 7: backup taken and restore rehearsed; section 8: previous digest recorded; section 9: pager tested.
- [ ] `GET /api/v1/actions/kill-switch` -> `effective:true` on every tenant, screenshot attached.


## Addendum: secret reference policy

Every secret used by a collector, integration or action executor is a *reference*, never a value.
In production the platform only resolves:

- `env:ARGUS_SECRET_<NAME>` (any name with the `SECRET_ENV_PREFIX` prefix) or an exact name listed in `SECRET_ENV_ALLOWLIST`;
- `file:<path>` where the path resolves under `SECRETS_DIR` (default `/run/secrets`, i.e. Kubernetes or Docker secret mounts);
- `secrets:<key>` from the configured secrets file.

`literal:` references and `env:` names outside the policy are refused at configuration time (HTTP 400) and
at resolution time (logged, resolved to empty). Set `SECRET_ENV_ALLOWLIST=*` only in development; production
startup refuses it. Requests larger than `MAX_REQUEST_BODY_BYTES` (8 MB default) are rejected with 413.
