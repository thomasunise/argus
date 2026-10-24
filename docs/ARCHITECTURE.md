# Argus — Agentic Security Operations Platform

**Purpose.** Argus lets a security team analyze, test and fix security issues across an
enterprise estate using governed AI agents, and defends that estate against autonomous
attacker agents and swarms. It is multi-tenant, auditable, and safe by construction: agents
reason over an evidence graph with read-only tools, active testing is scope-gated, and every
change to the world goes through a separate action broker with typed actions, policy,
approvals, dry runs, rollback and a kill switch.

This document is the build contract. Every package below is self-contained and
exposes only the interfaces described here. Conventions apply to all code.

---

## 1. System layout

```
                 ┌──────────────────────────────────────────────────────────────┐
                 │                         Argus API                         │
  Browser ──────►│  FastAPI app factory  ·  SSO/local auth  ·  RBAC  ·  tenancy │
  SDK/CLI ──────►│  routers: /api/v1/*   ·  CSRF  ·  rate limits  ·  OpenAPI    │
  Sensors ──────►│  /api/v1/ingest/*     (API-key auth, per-source parsers)     │
                 └───────┬───────────────┬───────────────┬──────────────────────┘
                         │               │               │
          ┌──────────────▼──┐   ┌────────▼────────┐  ┌───▼──────────────────┐
          │ Evidence graph  │   │  Job queue      │  │  Audit chain         │
          │ nodes + edges   │   │ Redis / memory  │  │ db + jsonl + WORM    │
          │ attack paths    │   │ leases, retries │  │ sinks (S3/Azure)     │
          └──────┬──────────┘   └───┬───────┬─────┘  └──────────────────────┘
                 │                  │       │
   ┌─────────────▼───┐   ┌──────────▼──┐  ┌─▼──────────────┐   ┌──────────────────────┐
   │ Collectors      │   │ Detections  │  │ Test harness   │   │ Agent runtime        │
   │ AWS Azure GCP   │   │ rules       │  │ scope policy   │   │ planner + specialists│
   │ K8s GitHub Okta │   │ swarm det.  │  │ nuclei zap     │   │ read-only tools      │
   │ Entra osquery   │   │ canaries    │  │ prowler caldera│   │ budgets + traces     │
   │ netflow         │   │ anomaly     │  │ semgrep trivy  │   │ evals                │
   └─────────────────┘   └─────────────┘  └────────────────┘   └──────────┬───────────┘
                                                                          │ proposes
                                                               ┌──────────▼───────────┐
                                                               │ Action broker        │
                                                               │ typed actions        │
                                                               │ policy · approvals   │
                                                               │ dry-run · rollback   │
                                                               │ kill switch          │
                                                               └──────────────────────┘
```

**Trust boundaries**

1. Agents never execute anything. Their only write-capable tool is `propose_action`,
   which creates an `ActionRequest` in `pending` state. The broker is separate code with a
   separate policy evaluation and is the only component that can change the world.
2. Every piece of evidence shown to a model (event text, finding titles, log excerpts,
   repository content) is untrusted data. The runtime wraps it in delimiters and the system
   prompt says so. Prompt-injection evals must pass before a specialist ships.
3. Active testing runs only against assets with a recorded authorization, inside a scope
   with environment, rate and time-window limits, and the adapter re-checks scope at
   execution time. Queued work is not a grant.
4. Tenants are isolated by a `tenant_id` column on every domain table and a scoped query
   helper. Cross-tenant reads are a bug and tests assert on them.
5. The audit chain is hash-linked in the database and mirrored to an append-only sink.

---

## 2. Package layout and ownership

```
app/
  main.py                     app factory, lifespan, router registration        (core)
  worker.py                   `python -m app.worker` standalone queue worker    (core)
  core/
    config.py                 Settings via pydantic-settings                    (core)
    db.py                     engine, session_scope, init_db, scoped()         (core)
    security.py               passwords, sessions, CSRF, API keys, TOTP, OIDC  (core)
    rbac.py                   Role, Permission, Principal, require()            (core)
    audit.py                  record_audit(), verify_chain(), sinks            (core)
    queue.py                  JobQueue, Job, handler registry, workers         (core)
    telemetry.py              logging, OpenTelemetry, Prometheus /metrics      (core)
    errors.py                 typed exceptions → HTTP mapping                  (core)
    policy.py                 target validation (moved from app/policy.py)     (core)
  models/
    __init__.py               imports every model module                       (core)
    base.py                   Base, TenantMixin, utcnow, uid                   (core)
    identity.py               Tenant, User, Membership, ApiKey, OidcIdentity   (core)
    inventory.py              Asset, AssetAuthorization                        (core)
    findings.py               Finding, SecurityEvent, Investigation, Approval  (core)
    audit.py                  AuditEntry                                       (core)
    graph.py                  GraphNode, GraphEdge, AttackPath                 (graph)
    detections.py             Detection, Canary, CanaryHit, Baseline           (detections)
    collectors.py             CollectorConfig, CollectorRun                    (collectors)
    agents.py                 AgentRun, AgentStep, EvalRun                     (agents)
    testing.py                TestScope, TestPlan, TestRun, TestResult         (testing)
    actions.py                ActionRequest, ActionApproval, ActionRun         (actions)
    integrations.py           Webhook, WebhookDelivery, IntegrationConfig      (integrations)
  api/
    __init__.py               list of routers to mount                         (each)
    deps.py                   get_db, current_principal, require()             (core)
    auth.py                   login, logout, session, OIDC, TOTP, API keys     (core)
    admin.py                  tenants, users, memberships, settings            (core-api)
    assets.py findings.py events.py scans.py investigations.py approvals.py
    audit.py reports.py ingest.py                                              (core-api)
    graph.py                                                                   (graph)
    detections.py canaries.py                                                  (detections)
    collectors.py                                                              (collectors)
    agents.py evals.py                                                         (agents)
    tests.py                                                                   (testing)
    actions.py                                                                 (actions)
    integrations.py                                                            (integrations)
  graph/        service.py queries.py attack_paths.py scoring.py              (graph)
  detections/   engine.py rules/ swarm.py canaries.py anomaly.py              (detections)
  collectors/   base.py registry.py aws.py azure.py gcp.py kubernetes.py
                github.py okta.py entra.py osquery.py netflow.py               (collectors)
  agents/
    runtime.py                AgentRuntime loop, budgets, traces                (core)
    providers.py              Anthropic / OpenAI / Ollama adapters              (core)
    tools/registry.py         Tool, ToolRegistry                                (core)
    tools/*.py                read-only tools over graph/events/findings/CVE   (agents)
    specialists/*.py          triage, investigate, hunt, redteam_plan, remediate(agents)
    evals/                    datasets + runner + prompt-injection suite       (agents)
  testing/
    harness.py scope.py ratelimit.py sarif.py
    adapters/ web_baseline.py trivy.py nuclei.py zap.py prowler.py caldera.py
              semgrep.py gitleaks.py                                           (testing)
  actions/
    catalog.py policy.py broker.py executors/ aws.py azure.py gcp.py
    kubernetes.py github.py okta.py entra.py cloudflare.py                     (actions)
  integrations/
    inbound/  wazuh.py falco.py trivy.py guardduty.py defender.py crowdstrike.py
              sentinelone.py cloudtrail.py okta_logs.py k8s_audit.py
    outbound/ webhook.py slack.py jira.py servicenow.py pagerduty.py          (integrations)
  static/                     UI                                               (frontend)
alembic/                      migrations                                       (core)
infra/                        compose, helm, terraform, otel config            (infra)
docs/                         this file, THREAT-MODEL, RUNBOOKS, COMPLIANCE    (infra)
tests/                        one file per package, cross-tenant tests         (each)
```

A contributor working on a package adds files inside that package and its own `api/<name>.py`,
`models/<name>.py`, `tests/test_<name>*.py`, and does not reach into another package's files.
If the package needs something from core that does not exist, add a small helper inside the
package and say so in the pull request.

---

## 3. Conventions (all code)

- Python 3.11+, `from __future__ import annotations`, type hints everywhere, no `print`.
- SQLAlchemy 2.0 declarative. Every domain table includes `TenantMixin` (adds
  `tenant_id: str` indexed). Primary keys are `String(36)` UUID via `uid()`.
- Timestamps are `DateTime(timezone=True)` with `utcnow()` defaults.
- JSON columns are `Text` holding JSON; use `models.base.JSONText` helpers `dumps/loads`.
- Routers are `APIRouter(prefix='/api/v1/<name>', tags=['<name>'])` and export `router`.
- Every endpoint depends on `Principal` via `require('<perm>')` from `app.api.deps`.
  Mutating endpoints under session auth also pass CSRF (handled inside `require`).
- Queries use `scoped(db, Model, principal)` which returns `select(Model).where(Model.tenant_id == principal.tenant_id)`.
- Side effects that change security state call `record_audit(db, principal, action, subject, detail)`.
- Background work is a queue handler: `@queue.handler('<package>.<verb>')`. Handlers are
  idempotent, take `(job: Job, ctx: JobContext)` and re-validate authorization themselves.
- Secrets never go in logs, audit detail, finding evidence or model context. Use
  `core.security.redact()` on free text before persisting.
- External binaries (nuclei, zap, prowler, semgrep, trivy) are invoked via
  `testing.harness.run_tool(argv, timeout, cwd)` with a fixed argv list, never a shell.
- Optional heavy SDKs (boto3, azure-*, google-*, kubernetes) are imported lazily inside the
  function that needs them and the package reports `available()` so the UI can show it.
- Tests use the `client`, `principal` and `db` fixtures from `tests/conftest.py`, SQLite,
  and never touch the network. Network calls are mocked with `respx` or monkeypatch.

---

## 4. Core interfaces

### 4.1 Settings (`app/core/config.py`)

`Settings` (pydantic-settings, env-driven, `.env` supported). Groups: app, database,
redis/queue, auth (local, OIDC, TOTP), audit sinks, telemetry, AI providers, collectors
credentials, testing tool paths and limits, actions (kill switch, approval thresholds),
integrations. `get_settings()` is cached; `assert_safe_config()` runs at startup.

### 4.2 Principal and RBAC (`app/core/rbac.py`)

```python
class Role(StrEnum): viewer, analyst, operator, admin, owner
class Principal: user_id: str | None; tenant_id: str; role: Role; auth: 'session'|'api_key'|'system'; scopes: set[str]; email: str
PERMISSIONS: dict[Role, set[str]]   # cumulative; see rbac.py for the full matrix
def has(principal, perm) -> bool
```

Permissions are strings `<domain>:<verb>`: e.g. `findings:read`, `findings:write`,
`tests:run`, `actions:request`, `actions:approve`, `actions:execute`, `agents:run`,
`admin:users`, `admin:tenant`. `require(perm)` is the FastAPI dependency.

### 4.3 Queue (`app/core/queue.py`)

```python
queue = JobQueue(settings)                       # app.state.queue
job = await queue.enqueue(kind, payload, tenant_id=..., lease_seconds=600, idempotency_key=None, delay_seconds=0)
@queue.handler('scan.run')
async def run_scan(job: Job, ctx: JobContext): ...   # ctx.db_factory, ctx.settings, ctx.app, ctx.heartbeat()
await queue.cancel(job_id)
queue.status(job_id) -> JobStatus(queued|running|completed|failed|cancelled, attempts, error, started_at, finished_at)
```

Memory backend runs handlers as asyncio tasks in-process. Redis backend (`REDIS_URL`) uses
a list per priority, a lease hash, and `python -m app.worker` processes. Failed jobs retry
with backoff up to `max_attempts`. `ctx.heartbeat()` extends the lease.

### 4.4 Audit (`app/core/audit.py`)

`record_audit(db, actor: Principal | str, action: str, subject: str = '', detail: dict | None = None)`
appends a hash-chained `AuditEntry` and writes the same record to each configured sink
(`jsonl` file, S3 Object Lock bucket, Azure immutable blob). `verify_chain(db, tenant_id)`
recomputes hashes. `AUDIT_SIGNING_KEY` adds an HMAC per entry.

### 4.5 Agent runtime (`app/agents/runtime.py`)

```python
class Tool: name, description, input_schema (JSON schema, additionalProperties false), handler(args, ctx) -> str|dict, risk: 'read'|'propose'
registry = ToolRegistry(); registry.register(tool)
spec = AgentSpec(name, system_prompt, tools: list[str], max_steps=12, max_tokens=120_000, max_seconds=300, model=None)
run = await runtime.run(spec, task: str, inputs: dict, principal, db) -> AgentRun   # steps persisted as AgentStep
```

The loop: build messages → provider.complete → execute tool calls in parallel → append
results → repeat until end_turn, budget exhaustion or refusal. Every step stores the
model input hash, tool name, arguments, truncated result, tokens and latency. The final
answer is parsed with the spec's `output_schema` (structured outputs when the provider
supports it). Evidence from tools is wrapped as
`<untrusted_data source="...">...</untrusted_data>`.

### 4.6 Providers (`app/agents/providers.py`)

`Provider.complete(system, messages, tools, max_tokens, output_schema=None) -> ModelTurn(text, tool_calls: list[ToolCall], stop_reason, usage, raw)`.
Anthropic uses the official SDK (`claude-opus-5-5` default, `fallbacks='default'`,
structured outputs via `output_config.format`). OpenAI uses the official SDK. Ollama uses
httpx against `/api/chat` with `format: json` and tool calls. Provider selection is per
tenant setting with env default.

### 4.7 Graph (`app/graph/service.py`)

```python
upsert_node(db, tenant_id, kind, key, props: dict, source) -> GraphNode     # kinds: asset, identity, role, permission, network, exposure, vuln, secret, data_store, finding, event, canary
upsert_edge(db, tenant_id, src_id, dst_id, rel, props, source)              # rels: owns, can_assume, has_permission, exposes, runs, connects_to, affected_by, accessed, triggered
query(db, tenant_id, kind=None, key=None, props_filter=None, limit=200)
neighbors(db, tenant_id, node_id, rels=None, depth=1)
attack_paths(db, tenant_id, from_kind='exposure', to_kind='data_store', max_hops=6) -> list[AttackPath]
exposure_score(db, tenant_id, node_id) -> float
```

### 4.8 Detections (`app/detections/engine.py`)

`DetectionRule(id, name, severity, description, evaluate(ctx: RuleContext) -> list[DetectionDraft])`.
`engine.run(db, tenant_id, since)` runs rules over new events and graph changes, dedupes
by fingerprint, and creates `Detection` rows plus matching `Finding` rows. `swarm.py`
implements coordinated-activity detection: identity fan-out, novel-action bursts,
synchronized multi-asset access, canary tripwires, rate anomalies vs `Baseline`.

### 4.9 Collectors (`app/collectors/base.py`)

```python
class Collector: name, kind ('cloud'|'identity'|'code'|'endpoint'|'network'|'k8s'), config_schema (JSON schema), available() -> bool
  async def collect(self, ctx: CollectorContext) -> CollectorResult(nodes: list[NodeDraft], edges: list[EdgeDraft], events: list[EventDraft], stats: dict)
registry.get(name); registry.all()
```

Collector runs are queue jobs (`collectors.run`) that call `graph.service.apply(result)`.
Credentials come from `CollectorConfig.secret_ref` resolved via `core.security.secrets`.

### 4.10 Test harness (`app/testing/harness.py`)

```python
class TestAdapter: name, tier ('passive'|'active'|'intrusive'), target_kinds, available(), 
  async def run(self, plan: TestPlan, scope: TestScope, ctx: HarnessContext) -> list[NormalizedFinding]
scope.check(adapter, asset, now) raises ScopeDenied   # authorization, environment, window, rate
harness.execute(plan_id)  # queue job 'tests.run'; writes TestRun, TestResult, Finding
```

Intrusive adapters (CALDERA, ZAP active) are allowed only for assets with
`environment in ('staging','lab')` and an authorization record with `allow_intrusive=True`.

### 4.11 Action broker (`app/actions/broker.py`)

```python
class ActionType: name, description, params_schema, risk ('low'|'medium'|'high'|'critical'), reversible: bool, platforms: list[str],
  async def dry_run(params, ctx) -> DryRunResult(ok, summary, blast_radius: dict)
  async def execute(params, ctx) -> ExecResult(ok, summary, rollback_payload)
  async def rollback(rollback_payload, ctx) -> ExecResult
request(db, principal, action_type, params, reason, finding_id=None, agent_run_id=None) -> ActionRequest(status='pending'|'auto_approved')
approve(db, principal, request_id, decision, comment)     # approvers must differ from requester; high needs 2, critical needs 2 + owner
execute(request_id)   # queue job 'actions.execute': kill switch → policy → dry run → execute → ActionRun with rollback payload
rollback(db, principal, run_id)
```

Policy (`actions/policy.py`): per-tenant settings for auto-approval of low-risk reversible
actions whose dry run reports blast radius under thresholds, maintenance windows, and
deny-lists. Global `ACTIONS_KILL_SWITCH=true` or tenant `actions_enabled=false` rejects
everything.

### 4.12 Integrations

Inbound parsers implement `parse(payload: dict) -> list[EventDraft]` and register with
`integrations.inbound.registry`. The ingest endpoint is `POST /api/v1/ingest/{source}`
with API-key auth and per-key rate limiting. Outbound channels implement
`send(event: OutboundEvent) -> DeliveryResult` with retries and are triggered by the
event bus (`core.events.publish('finding.created', ...)`).

---

## 5. API surface (v1)

All routes under `/api/v1`. JSON in and out. Lists accept `?limit=&cursor=` and return
`{items, next_cursor}`. Errors are `{detail, code}`.

| Area | Routes |
|---|---|
| auth | `POST /auth/login`, `POST /auth/logout`, `GET /auth/session`, `GET /auth/oidc/start`, `GET /auth/oidc/callback`, `POST /auth/totp/enroll`, `POST /auth/totp/verify`, `GET/POST/DELETE /auth/api-keys` |
| admin | `GET/POST /admin/tenants`, `GET/POST/PATCH/DELETE /admin/users`, `POST /admin/memberships`, `GET/PATCH /admin/settings` |
| inventory | `GET/POST/PATCH/DELETE /assets`, `POST /assets/{id}/authorize`, `GET /assets/{id}/graph` |
| findings | `GET /findings`, `GET /findings/{id}`, `PATCH /findings/{id}`, `POST /findings/{id}/investigate`, `GET /findings/export.csv` |
| events | `GET /events`, `GET /events/{id}` |
| graph | `GET /graph/nodes`, `GET /graph/nodes/{id}`, `GET /graph/nodes/{id}/neighbors`, `GET /graph/attack-paths`, `GET /graph/exposures`, `GET /graph/stats` |
| detections | `GET /detections`, `PATCH /detections/{id}`, `GET /detections/rules`, `POST /detections/run`, `GET/POST/DELETE /canaries`, `POST /canaries/{token}/hit` (unauth, by token) |
| collectors | `GET /collectors/types`, `GET/POST/PATCH/DELETE /collectors`, `POST /collectors/{id}/run`, `GET /collectors/{id}/runs` |
| agents | `GET /agents/specs`, `POST /agents/run`, `GET /agents/runs`, `GET /agents/runs/{id}` (with steps), `POST /agents/runs/{id}/cancel`, `GET/POST /agents/evals` |
| tests | `GET /tests/adapters`, `GET/POST /tests/scopes`, `GET/POST /tests/plans`, `POST /tests/plans/{id}/run`, `GET /tests/runs`, `GET /tests/runs/{id}` |
| actions | `GET /actions/catalog`, `GET/POST /actions/requests`, `POST /actions/requests/{id}/approve`, `POST /actions/requests/{id}/execute`, `GET /actions/runs`, `POST /actions/runs/{id}/rollback`, `GET/POST /actions/kill-switch` |
| integrations | `GET /integrations/types`, `GET/POST/PATCH/DELETE /integrations`, `POST /integrations/{id}/test`, `GET /integrations/deliveries`, `POST /ingest/{source}` |
| audit | `GET /audit`, `GET /audit/verify` |
| reports | `GET /reports/summary`, `GET /reports/posture`, `GET /reports/compliance/{framework}` |
| ops | `GET /health`, `GET /ready`, `GET /metrics` |

---

## 6. Data model summary

Core: `tenants`, `users`, `memberships`, `api_keys`, `oidc_identities`, `assets`,
`asset_authorizations`, `findings`, `events`, `investigations`, `approvals`, `audit`.
Graph: `graph_nodes(kind,key,props,tenant)`, `graph_edges(src,dst,rel,props)`, `attack_paths`.
Detections: `detections`, `canaries`, `canary_hits`, `baselines`.
Collectors: `collector_configs`, `collector_runs`.
Agents: `agent_runs`, `agent_steps`, `eval_runs`.
Testing: `test_scopes`, `test_plans`, `test_runs`, `test_results`.
Actions: `action_requests`, `action_approvals`, `action_runs`.
Integrations: `integration_configs`, `webhook_deliveries`.

Fingerprint rule for findings: `sha256(tenant|asset|source|rule)`; for detections
`sha256(tenant|rule|entity|bucket)`.

---

## 7. Security requirements checklist

- [ ] No endpoint without `require()`; ingest and canary-hit use their own key auth.
- [ ] Cross-tenant test for every list and get endpoint.
- [ ] Model context contains no secrets, IPs beyond what the tool returns, or raw logs over 4 KB.
- [ ] Every action executor has `dry_run` and either `rollback` or `reversible=False` with `risk>='high'`.
- [ ] Every test adapter re-checks scope at execution time.
- [ ] Every collector stores credentials by `secret_ref`, never inline.
- [ ] Audit entry for login, authorization, scope creation, test run, action lifecycle, settings change, user/role change.
- [ ] Prompt-injection eval suite passes for every specialist.

---

## 8. As-built deviations (recorded during integration)

- Queue handler kinds follow `<package>.<verb>`: `testing.run` (not `tests.run`), `collectors.run`, `detections.run`, `detections.baselines`, `graph.recompute`, `agents.run`, `agents.eval`, `actions.execute`, `actions.rollback`, `integrations.fanout`, `integrations.deliver`, `integrations.wazuh_sync`.
- In-process workers run on a dedicated thread with their own event loop (`core/queue.py`); every queue call is marshalled onto it. Handlers may still do blocking database work without stalling HTTP requests. SQLite busy timeout is 30 s.
- Integrations models are `IntegrationConfig`, `WebhookDelivery`, `IngestBatch`; inbound webhook secrets are `IntegrationConfig` rows of inbound kinds. `FindingDraft` lives in `app.integrations.inbound`.
- The tenant kill switch is `Tenant.actions_enabled` (default `False`, so actions are blocked until an admin or owner releases them). `POST /actions/kill-switch {enabled: true}` sets it to `False`.
- `GraphNode.exposure_score` is persisted and refreshed by `graph.recompute`; `graph.service` has no `query()`, callers select `GraphNode` directly through `scoped()`.
- `scope.check` in the testing harness takes `settings` and `tier`; `execute_run` accepts a `heartbeat` callable.
- Models from non-core packages are imported from their module (`app.models.graph`, `app.models.detections`, …), not re-exported by `app.models`.
- `app.actions.broker.request` is async because it runs the dry run.
