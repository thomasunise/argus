# API v1

Base path `/api/v1`. JSON in and out. Lists accept `?limit=` (1 to 500, default 50) and
`?cursor=` and return `{"items": [...], "next_cursor": "..."|null}`. Errors are
`{"detail": "...", "code": "..."}` with codes `unauthorized` (401), `forbidden` (403),
`policy_denied` / `scope_denied` (403), `not_found` (404), `conflict` (409),
`rate_limited` (429), `unavailable` (503). Interactive docs: `/api/docs`; schema:
`/api/openapi.json`.

Authentication: a session cookie from `POST /auth/login` (then send `X-CSRF-Token` on every
non-GET request), or an API key in `X-API-Key` or `Authorization: Bearer`. The permission
required by each route is in parentheses; roles are cumulative viewer < analyst < operator <
admin < owner (`app/core/rbac.py`). Responses with status 202 mean a queue job was enqueued;
poll `GET /ops/jobs/{job_id}` or the resource's run endpoint.

Every router listed here is present in this checkout (`app/api/*.py`); routers are discovered
automatically by `app/api/__init__.py`.

## Ops (no prefix)

| Route | Purpose |
|---|---|
| `GET /health` | liveness `{status, version}` |
| `GET /ready` | database check; `{status, queue, provider}` or 503 |
| `GET /metrics` | Prometheus exposition when `METRICS_ENABLED` (block at the edge) |
| `GET /api/v1/ops/jobs?status=&limit=` (`audit:read`) | queue jobs for the tenant plus registered kinds |
| `GET /api/v1/ops/jobs/{id}` (`audit:read`) | one job: status, attempts, error, result |
| `POST /api/v1/ops/jobs/{id}/cancel` (`admin:settings`) | cancel a queued or running job |

## Auth

| Route | Purpose |
|---|---|
| `POST /auth/login` `{email, password, totp?, tenant?}` | start a session; returns `csrf`, memberships, `mfa_required` when TOTP is pending |
| `POST /auth/logout` | end the session |
| `GET /auth/session` | current principal and memberships |
| `POST /auth/switch-tenant` `{tenant}` | change active tenant (must be a member) |
| `POST /auth/totp/enroll` | returns secret and provisioning URI |
| `POST /auth/totp/verify` `{code}` | confirm enrolment / complete an MFA login |
| `GET /auth/oidc/start` | redirect to the IdP (authorization code + PKCE) |
| `GET /auth/oidc/callback` | exchange code, verify ID token, provision, create session |
| `GET /auth/api-keys` (`admin:api_keys`) | list keys (prefix, role, scopes, last used) |
| `POST /auth/api-keys` `{name, role, scopes[]}` (`admin:api_keys`) | create; plaintext returned once |
| `DELETE /auth/api-keys/{id}` (`admin:api_keys`) | revoke immediately |

## Admin

| Route | Purpose |
|---|---|
| `GET /admin/tenants`, `POST /admin/tenants` `{slug, name}` (`admin:tenant`) | tenants |
| `PATCH /admin/tenants/{id}` `{name?, is_active?, actions_enabled?}` (`admin:tenant`) | rename, deactivate, enable or disable actions |
| `GET /admin/users`, `POST /admin/users` `{email, display_name, role, password?, invite}` (`admin:users`) | users in the tenant |
| `PATCH /admin/users/{id}` `{display_name?, is_active?, ...}` (`admin:users`) | update |
| `POST /admin/users/{id}/reset-password` `{password?}` (`admin:users`) | reset (generated when omitted) |
| `DELETE /admin/users/{id}` (`admin:users`) | remove from tenant |
| `POST /admin/memberships` `{user_id, role}` (`admin:users`) | assign or change a role |
| `GET /admin/settings`, `PATCH /admin/settings` (`admin:settings`) | tenant settings JSON (provider selection, action policy overrides) |
| `GET /admin/overview` (`admin:users`) | tenant counts |

## Inventory

| Route | Purpose |
|---|---|
| `GET /assets`, `GET /assets/{id}` (`assets:read`) | assets; kinds web, repo, cloud_account, host, k8s_cluster, database, identity_provider, saas, network |
| `POST /assets` (`assets:write`) | create; web and repo targets are validated by `core.policy` |
| `POST /assets/import` (`assets:write`) | bulk import |
| `PATCH /assets/{id}`, `DELETE /assets/{id}` (`assets:write`) | update, delete |
| `POST /assets/{id}/authorize` (`assets:authorize`) | record an `AssetAuthorization` (attestation, allow_active, allow_intrusive, scope document ref, expiry) |
| `POST /assets/{id}/revoke-authorization` (`assets:authorize`) | revoke the current authorization |
| `GET /assets/{id}/authorizations` (`assets:read`) | authorization history |
| `GET /assets/{id}/graph` (`assets:read` + `graph:read`) | graph neighborhood of the asset |

## Findings, events, investigations, approvals

| Route | Purpose |
|---|---|
| `GET /findings` (`findings:read`) | list; filters by severity, status, asset, source, rule |
| `GET /findings/stats` | counts by severity and status |
| `GET /findings/export.csv` | CSV export (audited) |
| `GET /findings/{id}` | detail with evidence, CVEs, CVSS, EPSS, KEV |
| `PATCH /findings/{id}` (`findings:write`) | status (`open`, `investigating`, `resolved`, `accepted`, `false_positive`), assignee, tags |
| `POST /findings/{id}/investigate` (`findings:write` + `agents:run`) | rules-only investigation or an `investigate` agent run (202) |
| `GET /events`, `GET /events/stats`, `GET /events/{id}` (`events:read`) | security events |
| `GET /investigations`, `GET /investigations/{id}` (`investigations:read`) | investigation records (summary, steps, limitations, agent run id) |
| `GET /approvals`, `POST /approvals`, `GET /approvals/{id}`, `POST /approvals/{id}/decide` (`approvals:read` / `approvals:write`) | record-only approvals (not executable; see actions) |

## Graph

| Route | Purpose |
|---|---|
| `GET /graph/nodes?kind=&key=&limit=` (`graph:read`) | query nodes |
| `GET /graph/nodes/{id}`, `GET /graph/nodes/{id}/neighbors?rels=&depth=` | node and neighborhood |
| `GET /graph/attack-paths`, `GET /graph/attack-paths/{id}` | materialized paths with hops and score |
| `PATCH /graph/attack-paths/{id}` (`graph:read` + `findings:write`) | status open / accepted / resolved |
| `GET /graph/exposures` | highest exposure-score nodes |
| `GET /graph/stats` | counts by kind and relation |
| `POST /graph/recompute` (`graph:read` + `detections:run`) | enqueue `graph.recompute` (202) |

## Detections and canaries

| Route | Purpose |
|---|---|
| `GET /detections?status=&rule_id=&severity=` (`detections:read`) | detections |
| `GET /detections/{id}` | detail with evidence |
| `PATCH /detections/{id}` `{status, note}` (`detections:write`) | triage status |
| `GET /detections/rules` | registry with effective per-tenant params |
| `PATCH /detections/rules/{rule_id}` `{enabled?, params?}` (`detections:write`) | per-tenant override |
| `GET /detections/stats` | counts, last run |
| `POST /detections/run` `{since_minutes?, rule_ids?}` (`detections:run`) | enqueue `detections.run` (202) |
| `GET /canaries` (`canaries:read`) | canaries |
| `POST /canaries` `{kind, label, placement?, metadata?, expires_in_days?}` (`canaries:write`) | create; kinds token, url, credential, file, dns, aws_key, api_key, document, and for AI agents prompt_injection, agent_rules, mcp_server, llm_api_key |
| `DELETE /canaries/{id}` (`canaries:write`) | revoke |
| `GET /canaries/{id}/hits`, `GET /canaries/{id}/artifact` (`canaries:read`) | hit records; downloadable lure |
| `POST /canaries/{token}/hit`, `GET /canaries/{token}/hit` | **unauthenticated by design**: records a hit by token; GET returns a 1x1 GIF |
| `GET|POST /canaries/{token}/llm/{path}` | **unauthenticated by design**: fake OpenAI/Anthropic API for `llm_api_key` canaries; records model and prompt opening, answers 401 |
| `POST /canaries/{token}/mcp` | **unauthenticated by design**: fake MCP server for `mcp_server` canaries; answers initialize / tools/list, records every call and tool arguments |

## Attack simulator

| Route | Purpose |
|---|---|
| `GET /simulations/scenarios` (`detections:read`) | scenario catalog with ATT&CK techniques and the rules each should trigger |
| `POST /simulations` `{scenarios?, intensity: low|normal|high, evasion}` (`detections:run`) | queue a run (`simulation.run`); empty scenarios = all |
| `GET /simulations`, `GET /simulations/{id}` (`detections:read`) | runs with coverage, per-scenario outcome (detected / partial / missed), missed and disabled rules |

## Threat intel

| Route | Purpose |
|---|---|
| `GET /intel/status` (`findings:read`) | KEV catalog version and age, EPSS cache and bulk-file state, offline flag |
| `POST /intel/refresh` (`admin:settings`) | queue a KEV catalog refresh |
| `POST /intel/enrich` `{finding_ids?, include_closed?}` (`findings:write`) | queue enrichment (backfill all open CVE findings when empty) |
| `GET /intel/cve/{cve_id}` (`findings:read`) | KEV entry and EPSS score from the cache (fetches when online and stale) |

## Collectors

| Route | Purpose |
|---|---|
| `GET /collectors/types` (`collectors:read`) | registry (aws, azure, gcp, kubernetes, github, okta, entra, osquery, netflow) with config schema and availability |
| `GET /collectors`, `GET /collectors/{id}` | configured instances |
| `POST /collectors` `{name, collector, config, secret_refs, enabled, schedule_minutes}` (`collectors:write`) | create; `secret_refs` must be references (`env:`, `file:`, `secrets:`), never values |
| `PATCH /collectors/{id}`, `DELETE /collectors/{id}` (`collectors:write`) | update, delete |
| `POST /collectors/{id}/run` (`collectors:run`) | enqueue `collectors.run` (202) |
| `GET /collectors/{id}/runs`, `GET /collectors/runs/{run_id}` | run history with stats and warnings |

## Agents and evals

| Route | Purpose |
|---|---|
| `GET /agents/specs` (`agents:read`) | specialists (triage, investigate, hunt, redteam_plan, remediate, posture_report, swarm_responder) with tools, output schema, budgets |
| `GET /agents/tools` | tool registry (name, risk read/propose, schema) |
| `POST /agents/run` `{spec, task, inputs, finding_id?}` (`agents:run` plus the spec's own permission) | enqueue `agents.run` (202) |
| `GET /agents/runs`, `GET /agents/runs/{id}` | runs; detail includes every model and tool step |
| `POST /agents/runs/{id}/cancel` (`agents:run`) | cancel |
| `GET /evals/suites` (`evals:read`) | suites: prompt_injection, triage_precision, hunt_recall |
| `POST /evals/run` `{suite, spec?, case_ids?}` (`evals:run`) | enqueue an eval run (202) |
| `GET /evals`, `GET /evals/{id}` | results and per-case report |

## Tests and scans

| Route | Purpose |
|---|---|
| `GET /tests/adapters` (`tests:read`) | adapters (web_baseline, trivy, nuclei, zap, prowler, caldera, semgrep, gitleaks) with tier, target kinds, availability |
| `GET /tests/scopes`, `GET /tests/scopes/{id}` | scopes |
| `POST /tests/scopes` `{name, asset_ids, allowed_tiers, environments, window_start, window_end, max_rps, max_concurrency, signed_document_ref, expires_at}` (`tests:scopes`) | create |
| `POST /tests/scopes/{id}/revoke` (`tests:scopes`) | revoke; running work is denied at its next scope check |
| `GET /tests/plans`, `GET /tests/plans/{id}` | plans |
| `POST /tests/plans` `{name, scope_id, adapters, params, schedule_minutes, enabled}` (`tests:write`) | create |
| `POST /tests/plans/{id}/run` (`tests:run`) | enqueue one `testing.run` per adapter and asset (202) |
| `GET /tests/runs`, `GET /tests/runs/{id}` | runs and results |
| `POST /scans` `{asset_id, adapter, scope_id, tier?}` (`scans:run`) | single ad-hoc run inside a scope (202) |
| `GET /scans`, `GET /scans/{id}` (`scans:read`) | ad-hoc runs |
| `POST /tests/scopes/{id}/autonomous` `{autonomous}` (`tests:scopes`) | allow/disallow unattended autopilot runs on a scope |
| `POST /tests/autopilot` `{scope_id, asset_ids?, max_tier?, max_rounds?}` (`tests:run`) | start an autonomous, scope-checked pentest (202); 403 with a reason when disabled, the scope is not autonomous, or a kill switch is engaged |
| `GET /tests/autopilot`, `GET /tests/autopilot/{id}` (`tests:read`) | autopilot runs with their step log |
| `POST /tests/autopilot/{id}/stop` (`tests:run`) | request an autopilot run to stop |

## Actions

| Route | Purpose |
|---|---|
| `GET /actions/catalog` (`actions:read`) | 27 action types with risk, reversibility, platforms, params schema |
| `GET /actions/requests`, `GET /actions/requests/{id}` (`actions:read`) | requests with approvals and runs |
| `POST /actions/requests` `{action_type, params, reason, finding_id?, detection_id?}` (`actions:request`) | create; policy decides `pending` or `auto_approved` |
| `POST /actions/requests/{id}/approve` `{decision: approve|reject, comment}` (`actions:approve`; critical needs an approver with `actions:approve_critical`) | approvals; requester cannot approve own request |
| `POST /actions/requests/{id}/execute` (`actions:execute`) | enqueue `actions.execute` (kill switch, policy, dry run, execute) |
| `POST /actions/requests/{id}/cancel` `{reason}` | cancel a pending request |
| `GET /actions/runs`, `GET /actions/runs/{id}` (`actions:read`) | runs with summary, blast radius and rollback availability |
| `POST /actions/runs/{id}/rollback` (`actions:rollback`) | enqueue `actions.rollback` |
| `GET /actions/kill-switch` (`actions:read`), `POST /actions/kill-switch` `{enabled, reason}` (`actions:kill_switch`) | tenant kill switch state; `global` reflects `ACTIONS_KILL_SWITCH` |

## Autonomous response

Off unless `AUTORESPONSE_ENABLED=true` and the tenant opts in. See `docs/AUTONOMOUS-RESPONSE.md`.

| Route | Purpose |
|---|---|
| `GET /autoresponse/status` (`autoresponse:read`) | global and tenant switches, effective state, hourly cap, enforced in the last hour, kill switch, playbook counts |
| `PUT /autoresponse/settings` `{enabled?, max_per_hour?}` (`autoresponse:write`) | tenant opt-in and hourly cap (cannot exceed `AUTORESPONSE_MAX_PER_HOUR`) |
| `GET /autoresponse/playbooks`, `GET /autoresponse/playbooks/{id}` (`autoresponse:read`) | playbooks |
| `POST /autoresponse/playbooks`, `PATCH /autoresponse/playbooks/{id}`, `DELETE /autoresponse/playbooks/{id}` (`autoresponse:write`) | `{name, mode: shadow|enforce, rule_ids, min_severity, min_confidence, entity_kind, action_type, params_template, max_per_hour, max_blast_radius, rollback_after_minutes, allow_high_risk}`; only reversible, non-critical actions; high risk needs `allow_high_risk` |
| `GET /autoresponse/executions?playbook_id=&outcome=&detection_id=`, `GET /autoresponse/executions/{id}` (`autoresponse:read`) | every decision: `skipped`, `shadow`, `escalated`, `enforced`, `denied`, `failed`, with reason, params, dry run, request/run ids and rollback state |
| `POST /autoresponse/executions/{id}/keep` (`actions:approve`) | cancel the automatic rollback of an enforced action |
| `POST /autoresponse/executions/{id}/rollback` (`actions:rollback`) | roll the action back now through the broker |

## Integrations and ingest

| Route | Purpose |
|---|---|
| `GET /integrations/types` (`integrations:read`) | inbound sources (aws_cloudtrail, aws_guardduty, azure_defender, crowdstrike, falco, gcp_scc, generic, github_webhook, k8s_audit, okta_logs, sentinelone, trivy, wazuh) and outbound channels (webhook, slack, jira, servicenow, pagerduty, email) |
| `GET /integrations`, `GET /integrations/{id}` | configured integrations |
| `POST /integrations`, `PATCH /integrations/{id}`, `DELETE /integrations/{id}` (`integrations:write`) | manage; secrets as `secret_refs` |
| `POST /integrations/{id}/test` (`integrations:write`) | send a test delivery |
| `POST /integrations/{id}/sync` (`integrations:write`) | trigger a pull (Wazuh indexer) |
| `GET /integrations/deliveries`, `GET /integrations/deliveries/{id}`, `POST /integrations/deliveries/{id}/retry` | outbound delivery log and retry |
| `GET /integrations/ingest/batches` | inbound batch history |
| `POST /ingest/{source}` (API key with scope `ingest`; optional `X-Asset-ID`) | inbound events and findings; per-key rate limit |
| `GET /ingest/{source}/verify?integration=`, `POST /ingest/{source}/verify?integration=` | signed-webhook path for sources that support signature verification (for example Okta challenge, GitHub HMAC); rate limited per integration |
| `POST /slack/interactions/{integration_id}` (public; Slack request signature with the integration's `signing_secret`) | Approve / Deny / Roll back buttons on Slack action messages; the clicking Slack user is mapped to an Argus user and the broker enforces permissions and separation of duty; high and critical actions refused unless `allow_high_risk` |

## AI gateway and shadow-AI inventory

See `docs/AI-GATEWAY.md`. Proxy routes take an Argus API key only (`Authorization: Bearer` or
`x-api-key`) with `ai_gateway:use`, return provider-shaped errors, and are 404 unless
`AI_GATEWAY_ENABLED=true`.

| Route | Purpose |
|---|---|
| `POST /ai-gateway/openai/v1/chat/completions` (`ai_gateway:use`) | OpenAI-compatible chat completions through the gateway (streaming supported) |
| `POST /ai-gateway/openai/v1/embeddings` (`ai_gateway:use`) | OpenAI embeddings through the gateway |
| `GET /ai-gateway/openai/v1/models` (`ai_gateway:use`) | upstream model list filtered by the tenant's `allowed_models` |
| `POST /ai-gateway/anthropic/v1/messages` (`ai_gateway:use`) | Anthropic Messages API through the gateway (streaming supported) |
| `GET /ai-gateway/anthropic/v1/models` (`ai_gateway:use`) | upstream model list filtered by policy |
| `GET /ai-gateway/status` (`ai:read`) | enabled flag, configured providers, policy, month-to-date spend |
| `GET /ai-gateway/policy` (`ai:read`), `PUT /ai-gateway/policy` (`ai:write`) | tenant gateway policy; PUT replaces it, audited as `ai_gateway.policy_updated` |
| `GET /ai-gateway/requests?status=&provider=&model=&api_key_id=` (`ai:read`) | request records (metadata only), `GET /ai-gateway/requests/{id}` |
| `GET /ai-gateway/stats?days=30` (`ai:read`) | totals, tokens, cost, by status/provider/DLP action, DLP hit types, top models |
| `GET /ai/services?status=&channel=&provider=&service_key=&q=` (`ai:read`) | AI-usage inventory rows (service x channel x actor) |
| `GET /ai/services/stats` (`ai:read`) | counts by status, channel, provider, category and per service |
| `GET /ai/services/{id}` (`ai:read`), `PATCH /ai/services/{id}` (`ai:write`) | review: `status` sanctioned / blocked / unreviewed (applied to the whole service unless `apply_to_service=false`), `notes`; audited as `ai.service_reviewed` |
| `POST /ai/discover` (`ai:write`) | 202: queue an `ai.discover` job for the tenant |
| `GET /ai/discovery` (`ai:read`) | discovery cursor and counters |
| `GET /ai/catalog` (`ai:read`) | known AI services (domains, app names) and cloud API signatures |

## Backups and retention

Details and the restore procedure in `docs/BACKUP.md`. Restore is command-line only (`python -m app.ops backup restore`).

| Route | Purpose |
|---|---|
| `GET /ops/backups` (platform owner: `admin:tenant` in the bootstrap tenant) | backup configuration, `last_success_at`, history (size, SHA-256, rows, stores, errors) |
| `POST /ops/backups` (platform owner) | 202: queue a `backup.run` job |
| `GET /retention` (`admin:settings`) | effective retention policy, server defaults, overrides, rows due now, last run |
| `PUT /retention` `{overrides: {events_days: 30, runs_days: null}}` (`admin:settings`) | set (0 to 3650 days, 0 keeps forever) or remove overrides; audited as `retention.policy_updated` |
| `POST /retention/run` (`admin:settings`) | 202: queue a `retention.run` job for the tenant; audited as `retention.pruned` |

## Audit and reports

| Route | Purpose |
|---|---|
| `GET /audit` (`audit:read`) | audit entries with filters |
| `GET /audit/verify` (`audit:read`) | `{valid, checked, broken_at?, reason?, signed}` from `verify_chain` |
| `GET /audit/actions` (`audit:read`) | distinct action names seen |
| `GET /audit/export.jsonl` (`audit:read`) | export (audited as `audit.exported`) |
| `GET /reports/summary` (`reports:read`) | dashboard counts |
| `GET /reports/posture` | posture score 0..100 with weighted components |
| `GET /reports/compliance` | frameworks (`soc2`, `nist-800-171`, `iso27001`) and the control catalog |
| `GET /reports/compliance/{framework}` | per-control satisfied / partial / missing / manual with evidence; audited as `reports.compliance_generated` |
| `GET /reports/trends?days=30` | daily trends |

## Conventions for clients

- Send `X-Request-ID` to correlate with server logs; it is echoed back.
- Never put API keys in URLs. Ingest keys should be viewer role with scope `ingest`.
- All timestamps are ISO 8601 in UTC.
- Cross-tenant ids return 404, never 403, so existence is not leaked.
