# Threat model

Scope: the Argus application as described in `docs/ARCHITECTURE.md`, deployed per
`docs/DEPLOYMENT.md`. Out of scope: the security of the sensors that feed it, the cloud
accounts it inventories, and the model providers it calls (those are trust decisions you
make when you configure them).

Method: STRIDE per trust boundary, then the cross-cutting risks that matter most for an
agentic security product: prompt injection, SSRF, tenant isolation, credential handling,
action-broker abuse and supply chain. Each row states the mitigation that exists in code
today (with the file), and what remains for the deployer or for later work.

## Assets worth protecting

- Tenant data: assets, findings, events, graph, detections, test results, audit history.
- Credentials: session cookies, API keys (hash stored), OIDC client secret, collector and
  action secret references, model provider keys, the audit signing key.
- Integrity of the audit chain and of action decisions (who approved what).
- The estate itself: anything a test adapter or action executor could touch.

## Actors

- External attacker without credentials.
- Attacker with a stolen viewer or analyst session or API key.
- Malicious or compromised tenant user (including an owner) trying to reach another tenant.
- Attacker who controls content that becomes evidence: logs, alerts, repository files, DNS
  names, web pages, canary payloads. This is the prompt-injection actor.
- Compromised dependency, build system or registry.
- Insider with database access.

## Trust boundaries (from ARCHITECTURE.md section 1)

```
 B1  Internet -> API (auth, CSRF, rate limits, headers)
 B2  API -> database / Redis / audit sinks
 B3  Evidence (events, findings, repo content) -> agent model context
 B4  Agents -> action broker (propose only)
 B5  Scheduler / queue -> test harness -> external tools -> targets
 B6  Tenant A <-> Tenant B inside one database
 B7  Collectors / executors -> customer cloud accounts and identity providers
 B8  Build pipeline -> image -> runtime
```

## STRIDE by boundary

### B1: Internet to API

| Threat | Mitigation in code | Residual / deployer |
|---|---|---|
| Spoofing: password guessing | scrypt hashes (`core/security.py`), per-IP login throttle (`api/auth.py` `_throttle`, `LOGIN_MAX_ATTEMPTS`), optional TOTP (`TOTP_REQUIRED`), OIDC with PKCE, nonce, issuer, audience and signature checks (`oidc_exchange_code`) | Edge rate limiting (WAF rules provided), IdP conditional access |
| Spoofing: forged session | Signed, HttpOnly, SameSite=lax cookie (`SessionMiddleware`; lax so the OIDC callback carries it, while every mutation also needs the CSRF header), `https_only` when `COOKIE_SECURE` | Short `SESSION_MAX_AGE`; TLS everywhere |
| Spoofing: API key | `argus_<prefix>_<body>` format, SHA-256 hash stored, constant-time compare, revocation (`revoked_at`), `last_used_at` | Rotate keys; scope them (`ingest`) |
| Tampering: CSRF | `require()` enforces `X-CSRF-Token` equal to the session value for every non-safe method under session auth | |
| Tampering: forwarded headers | uvicorn `--proxy-headers --forwarded-allow-ips` limited to the proxy | Set `FORWARDED_ALLOW_IPS` correctly |
| Repudiation | Request id on every response and in logs; audit entries for login, API-key lifecycle, authorization, scope, run, action, settings and role changes | |
| Information disclosure | Security headers (CSP `default-src 'self'`, no-sniff, frame deny, no-referrer), `/api/docs` is public but shows only schema; errors are `{detail, code}` without stack traces | Block `/metrics` at the edge (done in Caddy, ALB rule, Front Door rule, nginx snippet) |
| Denial of service | Per-principal sliding window (`API_RATE_LIMIT_PER_MINUTE`), per-key ingest limit, `Page` caps lists at 500, bounded JSON columns | WAF rate rules; autoscaling |
| Elevation of privilege | RBAC matrix (`core/rbac.py`), every endpoint has `require(perm)`; API-key scopes intersect with role; `system` principal exists only in handlers | Review memberships; owners are few |

### B2: API to data stores and sinks

| Threat | Mitigation | Residual |
|---|---|---|
| Tampering with audit history | Per-tenant hash chain (`previous_hash`, `entry_hash`) and HMAC with `AUDIT_SIGNING_KEY`; `verify_chain()` recomputes; sinks mirror each entry to append-only storage (JSONL, S3 Object Lock, Azure immutable) | Set the signing key; use object lock in compliance mode; the task IAM role gets `PutObject` only (Terraform) |
| Information disclosure from the DB | `redact()` applied to finding titles, descriptions, evidence, event fields and audit detail; secrets never stored (only references; development-only `literal:` values are encrypted at rest and masked in API responses) | Encrypt at rest (RDS CMK, Azure default), TLS to the DB (`sslmode=require`) |
| Job tampering via Redis | Handlers re-validate tenant and authorization inside the job; a queued job is not a grant (`detections`, `graph`, `testing.scope.check`) | Redis AUTH + TLS, private network |
| Loss of jobs | Leases with heartbeat, reaper requeues expired leases, retries with backoff, `noeviction` | Redis persistence |

### B3: Evidence to model context (prompt injection)

| Threat | Mitigation | Residual |
|---|---|---|
| Instructions hidden in logs, alerts, commits, page titles | Every tool result is `redact()`ed, truncated to `AGENT_TOOL_RESULT_LIMIT`, and wrapped as `<untrusted_data source=...>` with closing-tag escaping (`runtime.wrap_untrusted`); the guardrail prompt states that evidence is data and injection attempts should be reported | Run the `prompt_injection` eval suite per provider/model before enabling a specialist; keep the suite growing |
| Model persuaded to act | Agents have no execution tools. `propose_action` creates a pending request only; the broker re-runs policy and requires human approval | Keep `ACTIONS_AUTO_APPROVE_LOW=false` unless the policy is reviewed |
| Exfiltration through tool arguments | Tool schemas are closed (`additionalProperties: false`), arguments validated by type (`Tool.validate`); tools read Argus's own tenant-scoped records, not arbitrary URLs | |
| Runaway cost or loops | `max_steps`, `max_tokens`, `max_seconds`, `AGENT_COST_CEILING_USD` enforced by the runtime for priced models (built-in table for Claude models, Ollama free by default, anything else via `AGENT_MODEL_PRICES`; an unpriced model logs a warning at startup and per run and is bounded by tokens, steps and time only); each step persisted | Budget alerts on `argus_agent_tokens_total` |
| Secrets reaching the provider | `redact()` on all evidence; collectors store `secret_ref` only; finding evidence capped at 6 KB | Review provider data-retention terms |

### B4: Agents to action broker

| Threat | Mitigation | Residual |
|---|---|---|
| Agent requests a destructive action | Request state is `pending`; approver must differ from requester; high risk needs two approvals, critical additionally an `actions:approve_critical` principal; dry run with blast radius precedes execution; rollback payload stored; `ACTIONS_KILL_SWITCH` and tenant `actions_enabled` gate request and execution; policy re-evaluated inside the `actions.execute` job (`app/actions/broker.py`, `app/actions/policy.py`) | Maintain deny-lists and maintenance windows per tenant; keep `ACTIONS_AUTO_APPROVE_LOW=false` |
| Approver collusion with a compromised account | Audit entries for request, approval, execution, rollback with actor and request id | Alert on approvals outside business hours; SSO conditional access |
| Executor credential misuse | Executors resolve credentials via `secret_ref` at run time, scoped per platform | Use least-privilege roles per action type; separate account for the broker |

### B5: Queue to test harness to targets

| Threat | Mitigation | Residual |
|---|---|---|
| Unauthorized or out-of-scope testing | `scope.check()` at request and execution: scope not revoked or expired, asset listed, environment allowed, tier allowed by both scope and authorization, intrusive only in staging or lab, time window, target validity | Signed scope documents referenced by `signed_document_ref` |
| SSRF / internal probing via web targets | `core/policy.py`: HTTPS only, origin only, ports 443/8443, no credentials, localhost rejected, DNS resolution checked against global addresses; private ranges only with `ALLOW_PRIVATE_TARGETS` and an explicit CIDR allowlist; loopback, link-local, multicast always denied | DNS rebinding is not prevented at the application layer: enforce egress filtering and metadata-endpoint blocking at the network (worker security group / NetworkPolicy) |
| Path traversal via repo targets | `validate_repo_target` resolves under `SCAN_ROOT` and rejects escapes; `SCAN_ROOT` mounted read-only | |
| Command injection into tools | `run_tool(argv, timeout, cwd)` uses `create_subprocess_exec` with a fixed list, never a shell; output bounded to 2 MB and redacted; minimal environment (no inherited secrets) | Pin tool versions; run workers in their own network segment |
| Rate or load damage to targets | Per-scope `max_rps` and `max_concurrency` (a run that finds its scope full stays queued and retries, under a per-scope PostgreSQL lock so replicas cannot overshoot), global `TEST_RATE_LIMIT_RPS`, tool timeouts | A worker that dies mid-run holds its slot until `TEST_TOOL_TIMEOUT_SECONDS` plus two minutes have passed |

### B6: Tenant isolation

| Threat | Mitigation | Residual |
|---|---|---|
| Cross-tenant read | `TenantMixin` on every domain table; `scoped()` / `get_scoped()` helpers; routers resolve objects by `(id, tenant_id)`; conftest `second_tenant` fixture and a cross-tenant test per list/get endpoint (brief requirement) | Code review for new endpoints; consider Postgres row-level security as defence in depth |
| Cross-tenant job execution | Handlers compare `job.payload.tenant_id` with `job.tenant_id` and raise | |
| Canary token enumeration | Tokens are 32 random characters (or credential-shaped), unique index; hit endpoint is unauthenticated by design and records source IP, UA and bounded headers (auth headers dropped) | Rate limit the hit endpoint at the edge |
| Session fixation across tenants | `switch-tenant` requires an existing membership; session stores `tenant_id` and `authed` | |

### B7: Collectors and executors to customer accounts

| Threat | Mitigation | Residual |
|---|---|---|
| Stored cloud credentials leak | Only `secret_ref` strings are stored (`CollectorConfig.secret_refs_json`); `is_secret_ref` validation rejects inline secrets; resolution at run time | Prefer workload identity (IRSA, Azure managed identity) over static keys |
| Over-privileged collector identity | Collectors are read-only by contract (`Collector.collect`) | Grant read-only roles; the Terraform skeletons leave `sts:AssumeRole` grants for you to add explicitly |
| Collector output poisoning the graph | `NodeDraft`/`EdgeDraft` validated; props redacted; graph writes are per tenant | |

### B8: Supply chain

| Threat | Mitigation | Residual |
|---|---|---|
| Vulnerable dependency | `pip-audit --strict` and `bandit -r app -ll` in CI; Dependabot for pip, actions, docker, terraform | Review and merge updates |
| Tampered image | Release workflow builds with provenance, generates an SPDX SBOM (syft), signs image and SBOM with cosign keyless, attaches GitHub build provenance | Verify signatures at deploy (`cosign verify`), pin digests |
| Malicious base image | `python:3.12-slim` pinned by tag; pin by digest in your fork | |
| Build secrets leak | No secrets in the Dockerfile or workflows; GHCR login via `GITHUB_TOKEN` | |
| Optional heavy SDKs | Imported lazily, installed only with `EXTRAS=1` | Separate worker image for test tools |

## Known gaps

- DNS rebinding and TOCTOU between validation and the actual request in web adapters are not closed in Python; network egress control is mandatory.
- The in-process rate limiter is per process; horizontal scaling needs the edge limiter.
- Row-level security in Postgres is not used; isolation relies on application code and tests.
- The Azure audit sink uses a connection string (shared key) rather than identity.
- Inbound webhook signature verification exists only for sources that define a scheme; everything else relies on the ingest API key, so protect that key like a credential.
