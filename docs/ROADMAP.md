# Roadmap

Status as of this checkout. "Implemented" means code and tests exist in the repository;
"next" means planned. Nothing here is a commitment of dates.

## Implemented

Platform core

- [x] Multi-tenant data model (`tenant_id` on every domain table, scoped query helpers)
- [x] Local login, OIDC (PKCE), TOTP, API keys with roles and scopes, CSRF, login throttling
- [x] RBAC with five cumulative roles and per-endpoint permissions
- [x] Hash-chained, HMAC-signed audit log with JSONL, S3 Object Lock and Azure immutable sinks; `GET /audit/verify` and JSONL export
- [x] Audit HMAC with key ids: signatures carry the key id and `AUDIT_SIGNING_KEYS` (`kid=value,...`) rotates keys while older segments still verify
- [x] Job queue with in-memory and Redis backends: leases, heartbeat, retries, cancellation, reaper, standalone worker
- [x] Prometheus metrics, JSON logs with request/tenant/job/run ids, optional OpenTelemetry tracing
- [x] Startup safety checks (`assert_safe_config`), bootstrap of tenant, owner and ingest key
- [x] Event bus (`finding.created`, `event.created`, `graph.applied`, `action.*`, ...)
- [x] Alembic migrations with an initial revision; `scripts/migrate.py` (upgrade, check, current, sql, stamp)

Core API

- [x] Admin (tenants, users, memberships, settings, overview), assets (CRUD, import, authorize, revoke, graph), findings (list, stats, CSV, patch, investigate), events, investigations, record-only approvals, audit, reports (summary, posture, compliance for SOC 2 / NIST 800-171 / ISO 27001, trends)

Evidence graph

- [x] Nodes, edges, natural keys, upsert, neighbors, stats, exposures, attack paths, exposure scoring, recompute job

Detections

- [x] Rule engine with fingerprint dedupe, per-tenant rule state and parameters, run history
- [x] 12 rules: coordinated identity fan-out, novel action burst, synchronized multi-asset access, machine-speed sequence, impossible travel, privilege escalation chain, public exposure change, privileged workload, secret committed, canary tripwire, rate spike, automated client tool abuse
- [x] Baselines (Welford, per dimension and window), canaries of eight kinds with hit recording and artifacts

Collectors

- [x] AWS, Azure, GCP, Kubernetes, GitHub, Okta, Entra, osquery, netflow collectors with fixture-based tests; cloud SDKs optional and lazily imported; schedules and run history

Testing harness

- [x] Scopes, plans, runs, results; scope re-check at execution; rate limits; per-scope `max_concurrency` (excess runs wait in the queue); shell-free tool runner
- [x] Adapters: web baseline, Trivy, Nuclei, ZAP, Prowler, CALDERA, Semgrep, Gitleaks (binaries installed separately)

Agents

- [x] Runtime with budgets, traces, untrusted-data wrapping, structured results via `submit_result`; cost ceiling with built-in Claude prices and `AGENT_MODEL_PRICES` for other models
- [x] Providers: Anthropic, OpenAI, Ollama, none (deterministic fallbacks)
- [x] Read-only tools over assets, findings, events, graph, detections, tests, intel, memory; `propose_action`
- [x] Specialists: triage, investigate, hunt, redteam_plan, remediate, posture_report, swarm_responder
- [x] Eval harness with suites: prompt_injection, triage_precision, hunt_recall

Action broker

- [x] Catalog of 25 typed actions across AWS, Azure, GCP, Kubernetes, GitHub, Okta, Entra, Cloudflare and Argus-internal operations, each with dry run and rollback or `reversible=False`
- [x] Policy: global and tenant kill switch, deny-lists, maintenance window, auto-approval of low-risk reversible actions, two approvals for high risk, owner-level approval for critical, request TTL
- [x] Queue jobs `actions.execute` and `actions.rollback`; audit entries for every transition

Integrations

- [x] Inbound parsers: AWS CloudTrail, GuardDuty, Azure Defender, CrowdStrike, Falco, GCP SCC, generic, GitHub webhook, Kubernetes audit, Okta logs, SentinelOne, Trivy, Wazuh; `POST /ingest/{source}` with API-key scope and signed-webhook verification where the source supports it
- [x] Outbound channels: webhook, Slack, Jira, ServiceNow, PagerDuty, email; event-bus fan-out, delivery log, retries
- [x] Wazuh indexer pull job

Infrastructure and documentation

- [x] Multi-stage image, entrypoint with migrations, compose dev/pilot stack, prod overlay with Caddy
- [x] Helm chart with HPA, PDB, NetworkPolicy, ServiceMonitor
- [x] Terraform skeletons for AWS (ECS, RDS, ElastiCache, S3 Object Lock, Secrets Manager, ALB, WAF, CloudWatch) and Azure (Container Apps, Flexible Postgres, Azure Cache, immutable blob, Key Vault, Front Door, WAF)
- [x] CI (pytest 3.11/3.12, Postgres job, pip-audit, bandit, Docker build, infra lint), release (SBOM, cosign, provenance), Dependabot
- [x] OpenTelemetry collector, Prometheus config and alert rules, Grafana dashboard
- [x] Deployment, threat model, runbooks, compliance mapping, API summary, migrations, contributing guide
- [x] Demo seed for the current models

## Next

Security hardening

- [ ] PostgreSQL row-level security as defence in depth under the application scoping
- [ ] Distributed rate limiting (Redis-backed) and per-tenant quotas
- [ ] Identity-based Azure audit sink (replace the connection string)
- [ ] Dedicated test-tool worker image with pinned binaries and an isolated egress path; DNS pinning in web adapters
- [ ] Session revocation list and admin-forced logout
- [ ] Per-tenant encryption keys for stored evidence
- [ ] Cancel of an agent run stops the model loop promptly (today the run is marked cancelled but the in-flight loop runs to its step/time budget)

Detection and response

- [ ] More rules from the ATT&CK matrix for cloud and identity; versioned rule packs per tenant
- [ ] Attack-path-aware prioritization of findings (graph score into severity)
- [ ] Automatic reversible containment for narrow, heavily validated cases only, behind policy and canary-grade evidence
- [ ] CVE / KEV / EPSS enrichment feeds with offline caching

Agents

- [ ] Larger eval datasets with measured precision, recall and latency per provider and model
- [ ] Specialist-level tool allowlists per tenant; per-tenant provider and model selection exposed in admin settings UI
- [ ] Cost reporting per tenant from `agent_runs`

Testing

- [ ] Test harness workers in their own network segment with per-scope egress rules
- [ ] SARIF import/export for third-party scanners

Frontend

- [ ] UI parity with the full v1 API (actions, integrations, reports, admin)

Operations

- [ ] CI migration drift check (`scripts/migrate.py --check`) against PostgreSQL
- [ ] Retention and purge jobs for events, test results, agent steps and deliveries
- [ ] Backup and restore automation; restore drill documentation
- [ ] Evidence bundle export for assessors (zip of the items in `docs/COMPLIANCE.md`)
- [ ] Redis-backed login throttling and rate limits shared across replicas
