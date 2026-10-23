# Compliance mapping

**This document maps Sentinel features to controls in SOC 2 (Trust Services Criteria),
NIST SP 800-171 Rev. 2 and ISO/IEC 27001:2022 Annex A. It is evidence support for your own
assessment. Deploying Sentinel does not make you certified or compliant with any framework;
an auditor evaluates your organization, your configuration and your operating procedures.
Several rows depend on choices you make at deployment (marked "deployer").**

Evidence sources referenced below:

- **Audit log**: `GET /api/v1/audit` (filterable, tenant scoped), `GET /api/v1/audit/verify` (hash-chain and HMAC verification), `GET /api/v1/audit/export.jsonl` (export, itself audited). Mirrors: JSONL file, S3 Object Lock bucket, Azure immutable container.
- **Reports package** (`app/reports/`): `GET /api/v1/reports/compliance` lists the frameworks `soc2`, `nist-800-171`, `iso27001` and the control catalog; `GET /api/v1/reports/compliance/{framework}` returns, per control, a status of satisfied / partial / missing / manual with the evidence checks that produced it, computed from the tenant's own rows (`app/reports/controls.py`, `app/reports/evidence.py`). Each generation is audited as `reports.compliance_generated`. `GET /api/v1/reports/posture` and `/summary` give the weighted posture score and counts.
- **Configuration**: the running `Settings` (environment), `GET /ready` (queue backend, provider), Helm values or Terraform state.
- **Domain tables**: `memberships`, `api_keys`, `asset_authorizations`, `test_scopes`, `test_runs`, `action_requests`, `action_approvals`, `action_runs`, `agent_runs`, `eval_runs`, `detections`, `findings`.

## Control mapping

| Control area | SOC 2 TSC | NIST 800-171 | ISO 27001 Annex A | Sentinel capability (where) | Evidence | Deployer responsibility |
|---|---|---|---|---|---|---|
| Unique identification and authentication | CC6.1 | 3.5.1, 3.5.2 | A.5.16, A.8.5 | Local accounts with scrypt hashes; OIDC (PKCE, nonce, signature, issuer, audience checks); API keys with hashed storage and prefixes (`app/core/security.py`, `app/api/auth.py`) | `users`, `oidc_identities`, `api_keys`; audit `auth.login`, `auth.api_key_created` | Configure OIDC, `OIDC_ALLOWED_DOMAINS` |
| Multi-factor authentication | CC6.1 | 3.5.3 | A.8.5 | TOTP (RFC 6238) enrolment and verification; `TOTP_REQUIRED` enforces it on sessions | `users.totp_enabled`; audit `auth.totp_verified`, `auth.login` detail `mfa` | Set `TOTP_REQUIRED=true`; MFA at the IdP for SSO |
| Least privilege / role-based access | CC6.1, CC6.3 | 3.1.1, 3.1.2, 3.1.5 | A.5.15, A.5.18, A.8.2 | Five cumulative roles, permission strings per endpoint via `require()`; API-key scopes intersect with role (`app/core/rbac.py`, `app/api/deps.py`) | `memberships`, `api_keys.scopes`; audit `admin.membership_created`, `admin.role_changed`, `admin.membership_removed` | Periodic access review of memberships |
| Separation of duties for privileged change | CC6.1, CC8.1 | 3.1.4 | A.5.3 | Action approvals: approver differs from requester, two approvers for high risk, `actions:approve_critical` for critical (`app/actions/broker.py`, `app/actions/policy.py`) | `action_requests`, `action_approvals`; audit `actions.approved` | Keep `ACTIONS_AUTO_APPROVE_LOW=false` unless policy approved |
| Session management | CC6.1 | 3.1.10, 3.1.11 | A.8.5 | Signed HttpOnly SameSite=lax cookies, idle `SESSION_MAX_AGE` and absolute `SESSION_ABSOLUTE_MAX_AGE`, `COOKIE_SECURE`; logout clears the cookie (server-side revocation list is on the roadmap) | Settings; audit `auth.logout` | Set session lifetime per policy |
| Unsuccessful logon attempts | CC6.1 | 3.1.8 | A.8.5 | Per-IP login throttle (`LOGIN_MAX_ATTEMPTS`, `LOGIN_WINDOW_SECONDS`); 429 after the limit | Settings; `sentinel_http_requests_total{route="/api/v1/auth/login",status="401"}` (failed attempts are not audit entries) | Edge rate limiting; alert on the metric |
| Audit logging of security events | CC7.2, CC4.1 | 3.3.1, 3.3.2 | A.8.15 | `record_audit()` on login, key lifecycle, authorization, scope, runs, actions, settings, role changes; actor, action, subject, detail, request id, timestamp | `GET /api/v1/audit` | Define retention |
| Audit record integrity and protection | CC7.2 | 3.3.8, 3.3.9 | A.8.15, A.8.16 | Per-tenant hash chain with HMAC (`AUDIT_SIGNING_KEY`); append-only mirrors (JSONL, S3 Object Lock compliance mode, Azure immutable blob); write-only IAM policy in the Terraform skeleton | `GET /api/v1/audit/verify` result; bucket/container immutability settings | Set signing key; enable an object-lock sink; protect the DB role |
| Time synchronization for audit | CC7.2 | 3.3.7 | A.8.17 | Timestamps are UTC from the application host | Audit `created_at` | NTP on hosts (managed platforms do this) |
| Review of audit logs / alerting | CC7.2, CC7.3 | 3.3.3, 3.3.5 | A.8.16 | Prometheus metrics and alert rules (`infra/prometheus/rules/sentinel.yml`), Grafana dashboard | Alert history | Route alerts to on-call |
| Vulnerability and configuration monitoring | CC7.1 | 3.11.2, 3.12.1 | A.8.8 | Test adapters (Trivy, Nuclei, ZAP, Prowler, Semgrep, Gitleaks, web baseline) normalized into findings; collectors inventory cloud, identity, code, K8s, endpoint | `test_runs`, `test_results`, `findings`, `collector_runs` | Install tools; authorize assets; schedule plans |
| Remediation tracking | CC7.4 | 3.11.3 | A.8.8 | Finding lifecycle (`open`, `investigating`, `resolved`, `accepted`, `false_positive`), occurrences, assignee, CVE/CVSS/EPSS/KEV fields | `findings`; `GET /findings/export.csv` | Define SLAs per severity |
| Incident detection | CC7.2, CC7.3 | 3.6.1, 3.14.6, 3.14.7 | A.5.24, A.8.16 | Detection engine with 12 rules (swarm, identity, cloud, k8s, code, canary, anomaly, agentic), baselines, canaries | `detections`, `detection_runs`, `canary_hits` | Tune rule parameters per tenant |
| Incident response procedures | CC7.4, CC7.5 | 3.6.1, 3.6.2 | A.5.26 | Runbooks (`docs/RUNBOOKS.md`), investigations and agent runs persisted with steps, action broker with rollback and kill switch | `investigations`, `agent_runs`, `agent_steps`, `action_runs` | Exercise runbooks; staff on-call |
| Authorized testing only | CC6.6 (deliberate change) | 3.1.3 | A.5.8, A.8.29 | Asset authorizations with attestation and scope document reference; scopes with tiers, environments, windows, rates; re-check at execution; intrusive only in staging/lab | `asset_authorizations`, `test_scopes`; audit `testing.scope.created`, `testing.run.denied`, `assets.authorized` | Maintain signed scope documents |
| Change management for production actions | CC8.1 | 3.4.3, 3.4.5 | A.8.32 | Typed actions with dry run, blast radius, approvals, execution record and rollback payload; maintenance windows (`ACTIONS_MAINTENANCE_WINDOW`) | `action_requests`, `action_runs`; audit `actions.*` | Define action policy per tenant |
| Secrets management | CC6.1 | 3.5.10, 3.13.16 | A.8.24 | Only `secret_ref` stored for collectors/integrations; `redact()` before persistence; secrets injected from Secrets Manager / Key Vault / Kubernetes Secret in the provided infrastructure | Config; Terraform state showing injection method | Use a secret manager; rotate per runbook |
| Encryption in transit | CC6.1, CC6.7 | 3.13.8 | A.8.24 | TLS termination in Caddy/ALB/Front Door/ingress; `COOKIE_SECURE`; HSTS header; DB `sslmode=require`, Redis `rediss://` in Terraform | Edge configuration | Enforce TLS 1.2+ at the edge |
| Encryption at rest | CC6.1 | 3.13.16 | A.8.24 | Terraform: RDS/S3/logs with CMK, Azure platform encryption | Cloud configuration | Enable on self-managed stores |
| Boundary protection / network segmentation | CC6.6 | 3.13.1, 3.13.5 | A.8.20, A.8.22 | API bound to loopback in compose; Kubernetes default-deny NetworkPolicy with egress allowlist; private subnets and security groups in AWS; internal Container Apps environment in Azure; WAF in both | Infrastructure code | Narrow egress to known destinations |
| Protection against malicious inputs to models | CC7.1 (new risk) | 3.14.2 (analogous) | A.8.28 (secure coding) | Untrusted-data wrapping, redaction, closed tool schemas, no execution tools, budgets, prompt-injection eval suite | `eval_runs` for suite `prompt_injection`; `agent_steps` | Run evals per model; review results |
| Multi-tenant data segregation | CC6.1, C1.1 | 3.1.3 | A.5.14, A.8.3 | `tenant_id` on every domain table; scoped query helper; cross-tenant tests per endpoint | Test suite results; code review | Separate databases for highest-assurance tenants if required |
| System monitoring and capacity | A1.1, A1.2 | 3.14.6 | A.8.6, A.8.16 | `/health`, `/ready`, `/metrics`, HPA, alarms | Dashboards | Capacity reviews |
| Backup and recovery | A1.2, A1.3 | 3.8.9 | A.8.13 | Terraform: RDS automated backups and final snapshot, Redis snapshots, S3 versioning; compose volumes | Backup configuration | Test restores |
| Supply chain and software integrity | CC8.1, CC7.1 | 3.14.1, 3.14.2 | A.5.21, A.8.9 | CI: pytest on two Python versions and Postgres, `pip-audit`, `bandit`, Docker build smoke test; release: SBOM (SPDX via syft), cosign keyless signatures, build provenance attestation; Dependabot | CI logs, release assets, registry signatures | Verify signatures before deploy |
| Secure configuration baseline | CC6.8 | 3.4.1, 3.4.2 | A.8.9 | `assert_safe_config()` refuses unsafe production settings; non-root, read-only containers; `.env.example` documents every setting | Startup log, image config | Review `values.yaml` / tfvars in change control |
| Data retention and disposal | C1.2, P4.2 | 3.8.3 | A.8.10 | Object-lock retention is explicit infrastructure configuration; Finding and event tables are retained until you delete | Infra config | Define retention; implement purge jobs where required |

## How to assemble an evidence package

1. Export the configuration in effect (Helm values or `terraform show` without secrets, plus the non-secret environment).
2. Pull `GET /api/v1/audit/verify` per tenant and archive the result with a timestamp.
3. Export the audit log for the period (`GET /api/v1/audit?since=...`) and, for WORM evidence, list the mirror objects for the same id range.
4. Export access records: memberships and API keys with roles and scopes.
5. Export authorizations and scopes to show testing was bounded; export test runs and findings to show monitoring and remediation.
6. Export action requests, approvals and runs to show change control for automated response.
7. Export eval runs for `prompt_injection`, `triage_precision` and `hunt_recall` for the models in use.
8. Attach CI and release artifacts (SBOM, signature verification output) for the image digest deployed.

`GET /api/v1/reports/compliance/{framework}` automates the per-control status for steps 2
through 7 from the same tables; attach its JSON output alongside the raw exports so an
assessor can see both the summary and the underlying records. Controls marked `manual` in that
report are organizational and cannot be evidenced by Sentinel.
