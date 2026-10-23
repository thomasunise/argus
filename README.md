# Sentinel

Sentinel is a self-hosted, multi-tenant security operations platform in which AI agents
analyze evidence but never act on the estate. Collectors inventory cloud, identity, code,
endpoint, network and Kubernetes assets into an evidence graph; a detection engine evaluates
events for swarm, identity, cloud, code and canary signals; a scope-gated test harness runs
authorized security tools; governed agents triage, investigate and hunt with read-only tools;
and a separate action broker (typed actions, policy, approvals, dry runs, rollback, kill
switch) is the only component allowed to change anything.

This README describes what is in the repository today. `docs/ARCHITECTURE.md` is the build
contract; `docs/ROADMAP.md` lists what is implemented versus planned.

## Architecture

```
  Browser / SDK / sensors
          |
          v  HTTPS (Caddy, ALB, Front Door or your ingress)
  +-------------------------------------------------------------+
  |  API  (FastAPI)  auth: session / OIDC+PKCE / TOTP / API keys |
  |  RBAC (viewer < analyst < operator < admin < owner), CSRF,   |
  |  per-principal rate limits, request ids, security headers    |
  +------+------------------+------------------+----------------+
         |                  |                  |
   PostgreSQL           Redis queue        Audit chain
   (tenant_id on       (leases, retries,   (hash-linked per tenant,
    every table)        python -m          HMAC, JSONL / S3 Object
                        app.worker)        Lock / Azure immutable)
         |                  |
  +------+------------------+----------------------------------+
  |  Worker processes run the same handlers as the API:        |
  |   collectors.run   detections.run / baselines              |
  |   graph.recompute  testing.run   agents.run                |
  +------------------------------------------------------------+
         |
         v  agents call propose_action only -> ActionRequest(pending)
  Action broker (separate policy, approvals, dry run, rollback, kill switch)
```

Trust boundaries, in one sentence each (details in `docs/THREAT-MODEL.md`):

1. Agents cannot execute anything; their one write-capable tool creates a pending request.
2. Everything an agent reads is wrapped as untrusted data and the prompt says so.
3. Active testing runs only inside a recorded authorization and scope, re-checked at run time.
4. Every domain table carries `tenant_id`; queries go through a scoped helper; tests assert it.
5. The audit chain is hash-linked, optionally HMAC-signed, and mirrored to a WORM sink.

## What is in this checkout

| Area | Status | Where |
|---|---|---|
| App factory, settings, DB, RBAC, auth (local, OIDC, TOTP, API keys), CSRF, rate limits | implemented, tested | `app/core/`, `app/api/auth.py`, `app/api/deps.py` |
| Audit chain with JSONL / S3 Object Lock / Azure immutable blob sinks | implemented | `app/core/audit.py` |
| Job queue (in-memory and Redis, leases, retries, cancellation, reaper) and standalone worker | implemented | `app/core/queue.py`, `app/worker.py` |
| Prometheus metrics, JSON logging, optional OpenTelemetry tracing | implemented | `app/core/telemetry.py` |
| Evidence graph: nodes, edges, attack paths, exposure scoring | implemented | `app/graph/`, `app/api/graph.py` |
| Detections: 12 rules (swarm x4, identity x2, cloud, k8s, code, canary, anomaly, agentic), baselines, canaries | implemented | `app/detections/`, `app/api/detections.py`, `app/api/canaries.py` |
| Collectors: AWS, Azure, GCP, Kubernetes, GitHub, Okta, Entra, osquery, netflow | implemented with fixtures; cloud SDKs optional | `app/collectors/`, `app/api/collectors.py` |
| Test harness: scope policy, rate limits, adapters for web baseline, trivy, nuclei, zap, prowler, caldera, semgrep, gitleaks | implemented; tools must be installed separately | `app/testing/`, `app/api/tests.py`, `app/api/scans.py` |
| Agent runtime, providers (Anthropic, OpenAI, Ollama, none), read-only tools, 7 specialists, eval suites | implemented | `app/agents/`, `app/api/agents.py`, `app/api/evals.py` |
| Action broker: catalog of 25 typed actions (AWS, Azure, GCP, Kubernetes, GitHub, Okta, Entra, Cloudflare, Sentinel-internal), policy, approvals, dry run, execute, rollback, kill switch | implemented | `app/actions/`, `app/api/actions.py` |
| Integrations: 13 inbound parsers behind `POST /api/v1/ingest/{source}`, 6 outbound channels (webhook, Slack, Jira, ServiceNow, PagerDuty, email) with deliveries and retries, Wazuh indexer pull | implemented | `app/integrations/`, `app/api/ingest.py`, `app/api/integrations.py` |
| Admin, assets, findings, events, investigations, approvals, audit, reports routers | implemented | `app/api/` |
| Alembic migrations (initial revision) and `scripts/migrate.py` | implemented | `alembic/`, `docs/MIGRATIONS.md` |
| Containers, compose, Helm, Terraform (AWS, Azure), CI, observability, docs | this workstream | `Dockerfile`, `compose*.yaml`, `infra/`, `.github/`, `docs/` |

Routers are discovered automatically. The full v1 surface is in `docs/API.md`.

## Quick start (development, SQLite, no Docker)

Requirements: Python 3.11 or 3.12.

```bash
python -m venv .venv && . .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
python scripts/generate_secrets.py --write          # fills the three REPLACE_ values and AUDIT_SIGNING_KEY stays empty unless you set it
uvicorn app.main:app --host 127.0.0.1 --port 8080
```

Open http://127.0.0.1:8080 and sign in as `ADMIN_EMAIL` / `ADMIN_PASSWORD` from `.env`.
With `REDIS_URL` empty, jobs run inside the API process (`WORKERS_INPROCESS=true`). With
`DB_AUTO_CREATE=true` (the default) tables are created at startup; for Alembic-managed
schemas set it to `false` and run `python scripts/migrate.py` (see `docs/MIGRATIONS.md`).

Synthetic demo data in an isolated tenant (never touches the network):

```bash
python scripts/seed_demo.py
```

It prints a `demo` tenant login and creates DEMO-labelled assets, authorizations, events that
trip `cloud.public_exposure_change` and `swarm.machine_speed_sequence`, findings, a canary and
an agent run record. Refuses to run when `APP_ENV=production`.

Tests:

```bash
python -m pytest -q
```

## Pilot (Docker Compose: API, worker, PostgreSQL, Redis)

```bash
cp .env.example .env && python scripts/generate_secrets.py --write
docker compose up --build -d
docker compose logs -f api
```

`compose.yaml` binds the API to `127.0.0.1:8080` only, runs the API and worker from one image
with a read-only root filesystem, no capabilities and no Docker socket, mounts `./targets`
read-only, and applies the schema at API start (`RUN_MIGRATIONS=true`). Add
`--profile observability` for an OpenTelemetry collector, Prometheus (scraping `/metrics`) and
Grafana with the dashboard in `infra/grafana/sentinel.json`.

TLS termination for a single host:

```bash
# .env: APP_ENV=production COOKIE_SECURE=true BASE_URL=https://host SENTINEL_DOMAIN=host ACME_EMAIL=ops@example.com
docker compose -f compose.yaml -f compose.prod.yaml up -d
```

## Production

Kubernetes: `infra/helm/sentinel` (API + worker deployments, HPA, PDB, default-deny
NetworkPolicy, ingress with TLS, optional ServiceMonitor). AWS: `infra/terraform` (ECS
Fargate, RDS, ElastiCache, S3 Object Lock audit bucket, Secrets Manager, ALB + WAF).
Azure: `infra/terraform-azure` (Container Apps, Flexible Postgres, Azure Cache, immutable
blob container, Key Vault, Front Door + WAF).

The production checklist is in `docs/DEPLOYMENT.md`. The short version, enforced partly by
`assert_safe_config()` at startup:

- `APP_ENV=production` requires PostgreSQL, `REDIS_URL` and `COOKIE_SECURE=true`.
- Dedicated workers (`WORKERS_INPROCESS=false`, `python -m app.worker`).
- `AUDIT_SIGNING_KEY` set and an object-lock audit sink configured.
- OIDC configured, `TOTP_REQUIRED=true` for local accounts.
- `/metrics` blocked at the edge; egress filtering for workers; secrets in a secret manager.
- Images pinned by digest and verified with cosign (`.github/workflows/release.yml`).

## Roles

Roles are cumulative (`app/core/rbac.py`):

| Role | Adds |
|---|---|
| viewer | read everything in the tenant |
| analyst | edit findings and detections, run agents and evals, manage canaries, record approvals |
| operator | manage and authorize assets, run tests, scans and collectors, request, approve, execute and roll back actions, run detections |
| admin | users, API keys, settings, collector and integration configuration, the actions kill switch, test scopes |
| owner | tenant settings, approving critical actions |

API keys carry a role and optional scopes (for example `ingest`) that further restrict them.
A `system` principal is used only inside queue handlers.

## How agents, testing and actions are governed

**Agents** (`app/agents/runtime.py`). A specialist is an `AgentSpec` with a system prompt, a
list of tool names, an output schema and budgets (`AGENT_MAX_STEPS`, `AGENT_MAX_TOKENS`,
`AGENT_MAX_SECONDS`, `AGENT_COST_CEILING_USD`). Tools are read-only views over Sentinel data;
the only `propose` tool creates a pending `ActionRequest` through the broker. Every tool
result is redacted, truncated and wrapped as `<untrusted_data source=...>`; the guardrail
prompt tells the model that instructions inside evidence are indicators of injection. Each
model and tool step is persisted (`agent_steps`) with input hash, tokens and latency. With
`AI_PROVIDER=none`, specialists run deterministic fallbacks. Prompt-injection and precision
eval suites live in `app/agents/evals/suites/`.

**Testing** (`app/testing/`). A `TestScope` lists assets, allowed tiers (passive, active,
intrusive), environments, a UTC window, rate and concurrency limits. A run is allowed only if
the asset has a current `AssetAuthorization` whose flags permit the tier, the scope permits
it, the window is open and the target passes policy validation. `scope.check()` runs at
request time and again inside the worker; intrusive tiers are limited to staging and lab
environments. External tools run through `run_tool()` with a fixed argv, a timeout, bounded
output and a minimal environment.

**Actions** (`app/actions/`). Typed actions declare risk, reversibility and a parameter
schema, and implement `dry_run`, `execute` and `rollback`. A request (from an operator or an
agent's `propose_action`) goes through policy (`app/actions/policy.py`: kill switch, tenant
`actions_enabled`, deny-lists, maintenance window, auto-approval only for low-risk reversible
actions when `ACTIONS_AUTO_APPROVE_LOW`), approvals (approver differs from requester; high risk
needs two when `ACTIONS_REQUIRE_TWO_FOR_HIGH`; critical additionally needs a principal with
`actions:approve_critical`), a dry run with blast radius, execution as the `actions.execute`
queue job with a stored rollback payload, and an audit entry at every transition.
`ACTIONS_KILL_SWITCH=true` (global, environment) or `POST /api/v1/actions/kill-switch`
(per tenant, sets `actions_enabled=false`) rejects every request and execution.

## Documentation

| Document | Content |
|---|---|
| `docs/ARCHITECTURE.md` | build contract: packages, interfaces, data model, API table |
| `docs/API.md` | v1 route summary with status |
| `docs/DEPLOYMENT.md` | dev, compose, Kubernetes, AWS, Azure; production checklist |
| `docs/SECURITY.md` | security model as implemented, reporting |
| `docs/THREAT-MODEL.md` | STRIDE per trust boundary, prompt injection, SSRF, tenancy, credentials, broker abuse, supply chain |
| `docs/RUNBOOKS.md` | incident procedures |
| `docs/COMPLIANCE.md` | SOC 2 / NIST 800-171 / ISO 27001 control mapping (evidence support, not certification) |
| `docs/ROADMAP.md` | implemented versus next |
| `CONTRIBUTING.md` | workstream conventions |

## License

MIT for this repository. Third-party tools (nuclei, ZAP, Prowler, CALDERA, Semgrep, Gitleaks,
Trivy), cloud SDKs and model providers are governed by their own licenses and terms.
