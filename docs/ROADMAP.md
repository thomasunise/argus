# Roadmap from working MVP to enterprise autonomous defensive security

## Implemented
- [x] Secure basic administrator login and CSRF session control
- [x] Asset inventory with authorization attestation
- [x] HTTPS baseline scanner, TLS validation, expiration checks
- [x] Optional local Trivy repository scanning
- [x] Wazuh / Falco event ingestion and Trivy report ingestion
- [x] Wazuh indexer polling with configurable CA validation
- [x] Findings correlation, lifecycle and exports
- [x] Rules-based and optional Ollama / OpenAI / Anthropic investigations
- [x] Read-only LLM boundary and recorded approval decisions
- [x] Hash-linked event audit and a responsive UI
- [x] Optional approved-web-only scan scheduler

## Next: production foundation
- [ ] OIDC/SAML SSO, MFA, RBAC, multi-tenant isolation
- [ ] PostgreSQL + Alembic migrations + Redis/queue + distributed scanning workers
- [ ] Native inventory collectors for AWS, Azure, GCP, Kubernetes, Linux and Windows
- [ ] Event streaming, retention management, observability, delivery retries
- [ ] Scanner sandbox with pinned DNS and egress enforcement
- [ ] OpenTelemetry, Prometheus metrics, runbooks and error budgets
- [ ] Durable job leases, cancellation, scheduling windows and rate limits
- [ ] Independent model evaluation and anti-prompt-injection tests
- [ ] Offline incident test datasets, quantitative false-positive measurements

## Next: richer authorized assessments
- [ ] Nuclei reviewed non-destructive template catalog, scope/rate enforcement
- [ ] Prowler CLI JSON/SARIF adapter with read-only role credentials
- [ ] Semgrep / Gitleaks / code scanning CI adapters
- [ ] Authenticated OWASP ZAP API testing in staging
- [ ] CALDERA adversary emulation in isolated lab environments only
- [ ] Attack path graph combining identities, public exposure and asset/data relationships
- [ ] Secrets and PII data lineage discovery with carefully scoped collectors
- [ ] Knowledge base of CVEs/KEV/EPSS and changelog monitoring
- [ ] Formal validation tests to compare model triage precision and latency

## Finally: controlled response
- [ ] Separate short-lived privileged action broker
- [ ] Typed actions with independent policy engine and dual approval
- [ ] Dry runs, blast-radius checks, rollback and validation
- [ ] Guided patch PR creation with gated CI and signed deployment artifacts
- [ ] Automatic reversible containment only for heavily validated cases
- [ ] SOC 2 / NIST mapping using verifiable evidence (not a certification promise)
