# Security

This page states the security model as implemented in this repository, what deployers must
add, and how to report a vulnerability. The threat analysis is in `docs/THREAT-MODEL.md`;
procedures are in `docs/RUNBOOKS.md`.

## Reporting a vulnerability

Use GitHub private vulnerability reporting on this repository (Security tab, "Report a
vulnerability") with steps to reproduce. Do not open a public issue for an unpatched
vulnerability. Expect an acknowledgement within three business days.

## Principles

1. **Agents do not act.** Model-driven code has read-only tools; the single write-capable
   tool creates a pending request for humans. Execution lives in a separate broker with its own
   policy, approvals, dry run, rollback and kill switch.
2. **Evidence is untrusted.** Everything shown to a model is redacted, size-limited and
   wrapped in `<untrusted_data>` delimiters with an explicit instruction that it is data.
3. **Testing is authorized, scoped and re-checked.** No active test runs without a recorded
   authorization and a scope; the check repeats inside the worker; intrusive tiers are
   staging/lab only.
4. **Tenants are isolated by construction.** Every domain table has `tenant_id`; queries use a
   scoped helper; tests assert cross-tenant access returns 404 or nothing.
5. **History is tamper-evident.** Audit entries are hash-chained per tenant, HMAC-signed when
   `AUDIT_SIGNING_KEY` is set, and mirrored to append-only sinks.
6. **Secrets stay out of the database, logs and model context.** Only references are stored
   (`env:`, `file:`, `secrets:`); free text passes through `redact()`. The development-only
   `literal:` form (`ALLOW_LITERAL_SECRET_REFS`, refused in production) is encrypted at rest and
   masked as `literal:[set]` in every API response.

## Implemented controls

Authentication and sessions (`app/core/security.py`, `app/api/auth.py`, `app/api/deps.py`)

- Passwords: scrypt (N=2^14, r=8, p=1), constant-time verification.
- Sessions: signed cookie, HttpOnly, SameSite=lax (the OIDC callback must carry it; mutations need the CSRF header), idle timeout `SESSION_MAX_AGE`, absolute lifetime `SESSION_ABSOLUTE_MAX_AGE`, `Secure` when `COOKIE_SECURE=true`, lifetime `SESSION_MAX_AGE`.
- CSRF: `X-CSRF-Token` required on every non-safe method for session principals.
- Login throttling per client IP (`LOGIN_MAX_ATTEMPTS` in `LOGIN_WINDOW_SECONDS`).
- TOTP (RFC 6238, six digits, one-step window); `TOTP_REQUIRED` enforces it.
- OIDC authorization code with PKCE (S256), state and nonce, ID token verified against the JWKS with issuer and audience, optional email-domain allowlist and auto-provisioning with a default role.
- API keys: `snt_<prefix>_<body>`, SHA-256 hash stored, revocation, last-used tracking, role plus optional scopes; ingest keys use `require_scope('ingest')`.
- RBAC: five cumulative roles; every endpoint declares its permission.
- Rate limits: per principal (`API_RATE_LIMIT_PER_MINUTE`) and per ingest key (`INGEST_RATE_LIMIT_PER_MINUTE`), in-process sliding window.

Transport and headers (`app/core/telemetry.py`)

- `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Permissions-Policy`, a restrictive `Content-Security-Policy`, HSTS when `COOKIE_SECURE`.
- Request id in and out (`X-Request-ID`), present in logs and audit entries.

Audit (`app/core/audit.py`)

- `record_audit()` writes actor, kind, action, subject, redacted detail, request id, `previous_hash`, `entry_hash`, `signature`, timestamp.
- Concurrent writers cannot fork a chain on PostgreSQL (transaction-scoped per-tenant advisory lock); sinks receive an entry only after its transaction commits. SQLite is development-only and does not get this guarantee.
- `verify_chain()` recomputes the chain and signatures; the result reports the first broken id.
- Sinks: JSONL (append), S3 Object Lock (one object per entry), Azure immutable blob (`overwrite=False`). Sink failures are logged, never block.

Data handling

- `redact()` patterns cover AWS keys, bearer tokens, `key=value` secrets, private key blocks, OpenAI-style keys, Sentinel API keys, GitHub and Slack tokens.
- Finding evidence capped at 6 KB, event metadata at 8 KB, audit detail at 4 KB, tool results at `AGENT_TOOL_RESULT_LIMIT`.
- Collector and integration credentials are `secret_ref` strings resolved at run time (`env:`, `file:`, `secrets:`).

Target policy and testing (`app/core/policy.py`, `app/testing/`)

- Web targets: HTTPS origin only, ports 443/8443, no credentials, path, query or fragment; localhost rejected; resolved addresses must be global unless `ALLOW_PRIVATE_TARGETS` with `PRIVATE_TARGET_CIDRS`; loopback, link-local, multicast always denied.
- Repo targets: must resolve under `SCAN_ROOT`.
- `scope.check()` enforces scope validity, asset membership, environment, tier (scope and authorization), intrusive-only-in-staging/lab, time window, target validity, at request and execution.
- `run_tool()` executes a fixed argv with a timeout, bounded output, redaction and a minimal environment.
- Per-scope `max_rps` and `max_concurrency`; global `TEST_RATE_LIMIT_RPS` and `TEST_TOOL_TIMEOUT_SECONDS`.

Agents (`app/agents/`)

- Budgets: steps, tokens, seconds, USD ceiling.
- Tool schemas closed; arguments type-checked; unknown tools rejected.
- Every step persisted with an input hash for reproducibility.
- `AI_PROVIDER=none` runs deterministic fallbacks; no provider call happens without explicit configuration.
- Eval suites including prompt injection under `app/agents/evals/suites/`.

Actions (`app/actions/`)

- 25 typed actions, each with a parameter schema, risk, reversibility and platform list; executors implement `dry_run`, `execute` and `rollback`.
- Policy evaluated at request and again at execution: global `ACTIONS_KILL_SWITCH`, tenant kill switch (`actions_enabled=false`), deny-lists, maintenance window, auto-approval only for low-risk reversible actions when enabled, two approvals for high risk, owner-level (`actions:approve_critical`) approval for critical; requester cannot approve own request; request TTL.
- Execution and rollback are queue jobs with stored rollback payloads; every transition is audited (`actions.requested`, `actions.approved`, `actions.executed`, `actions.rolled_back`, `actions.kill_switch`, ...).

Integrations (`app/integrations/`)

- Ingest requires an API key with scope `ingest` (or a signed webhook for sources that support verification); per-key and per-integration rate limits; payload size bounded; parsers emit drafts that go through `upsert_event` / `upsert_finding` (dedupe, redaction).
- Outbound channels store credentials as `secret_refs`; deliveries are logged with retries.

Queue (`app/core/queue.py`)

- Leases, heartbeat, retry with backoff, cancellation, reaper for expired leases; handlers re-validate tenant and authorization.

Containers and infrastructure (`Dockerfile`, `compose*.yaml`, `infra/`)

- Non-root UID 10001, read-only root filesystem, all capabilities dropped, `no-new-privileges`, tini as PID 1, health checks, no Docker socket.
- Compose binds the API to loopback; the prod overlay adds TLS, HSTS and blocks `/metrics`.
- Helm: default-deny NetworkPolicy, PDB, HPA, seccomp RuntimeDefault, no service-account token.
- Terraform: private subnets, CMK encryption, forced TLS to data stores, Object Lock / immutable audit storage, WAF, redacted WAF logs, write-only audit IAM.

Supply chain (`.github/`)

- CI: pytest on 3.11 and 3.12 with SQLite and with PostgreSQL, `pip-audit --strict`, `bandit -r app -ll`, Docker build and smoke test, YAML/Terraform/Helm lint.
- Release: SBOM (SPDX, syft), cosign keyless signing of image and SBOM attestation, GitHub build provenance.
- Dependabot for pip, GitHub Actions, Docker and Terraform.

## Deployer responsibilities

- TLS termination, edge rate limiting and WAF (provided configurations are starting points).
- Egress filtering for workers: the application cannot prevent DNS rebinding or guarantee that an authorized hostname never resolves to an internal address after validation.
- Secret storage and rotation; `AUDIT_SIGNING_KEY` set; object-lock sink enabled.
- OIDC and MFA; periodic access reviews.
- Installing and pinning external test tools in worker images only.
- Reviewing model-provider terms before enabling a hosted provider.
- Backups and restore tests for PostgreSQL.

## Not implemented (be explicit with stakeholders)

- Row-level security in PostgreSQL (isolation is enforced in application code and tests).
- DNS pinning between validation and request in web adapters.
- Key-id-aware verification of the audit HMAC across signing-key rotations (see runbook).
- Distributed rate limiting (the limiter is per process).
- Per-tenant encryption keys for stored evidence (encryption at rest is a platform setting).
