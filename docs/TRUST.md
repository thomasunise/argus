# Vendor Trust Package, SLA & Security Questionnaire Summary (CAIQ / SIG Lite)

**Vendor:** eeko systems  
**Product:** Argus — Governed Defensive Security Platform  
**Support & Security Contact:** `security@eeko.systems`

---

## 1. Service-Level Agreement (SLA) & Incident Notification Terms

> **Status: target terms.** These apply under a signed support agreement with eeko systems. Argus itself is
> MIT-licensed open-source software and carries no SLA when self-hosted without one.

| Commitment | Standard Enterprise Tier | Regulated Critical Tier (Banking / Healthcare / Gov) |
|---|---|---|
| **Platform Availability Target** | 99.9% monthly uptime | 99.95% monthly uptime (Multi-AZ deployment) |
| **Confirmed Security Incident Notification** | Within **24 hours** of confirmation | Within **12 hours** (supports NYDFS 23 NYCRR 500.17 72h, DORA Art. 19, and HIPAA breach notification windows) |
| **Critical Vulnerability Remediation (CVSS >= 9.0)** | Within **7 calendar days** | Within **72 hours** (hotfix release + signed image digest) |
| **High Vulnerability Remediation (CVSS 7.0–8.9)** | Within **14 calendar days** | Within **7 calendar days** |
| **P1 Production Outage Response** | < 1 hour (24x7 on-call) | < 15 minutes (24x7 dedicated escalation) |

---

## 2. Security Questionnaire Summary (CSA CAIQ v4 / SIG Lite Mapping)

Each answer states what the code does today and where it stops. Answers were checked against the implementation
on 2026-11-18; the tests named are in `tests/`.

| Domain | Question Summary | Argus Answer & Technical Evidence |
|---|---|---|
| **IAM & Authentication** | Does the platform enforce MFA, SSO (OIDC/SAML), and automated provisioning (SCIM 2.0)? | **Yes, with the limits noted.** Local logins require TOTP or a WebAuthn credential (`TOTP_REQUIRED=true`, and always in production when OIDC is configured) and can be disabled except for one break-glass account (`LOCAL_LOGIN_DISABLED`, `BREAK_GLASS_EMAIL`). WebAuthn ceremonies are verified by the `webauthn` library (origin, RP ID, user verification, signature, counter). OIDC rejects a sign-in whose `acr`/`amr` does not meet `OIDC_REQUIRED_ACR`. SAML 2.0 is SP-initiated only and verified by `python3-saml` in strict mode against the pinned IdP certificate; IdP-initiated responses are refused. IdP groups map to tenants and roles (`OIDC_GROUP_ROLE_MAP`). SCIM 2.0 (`/api/v1/scim/v2`) supports Users create, get, list with `userName eq` filter, PATCH `active` and DELETE, authenticated by `SCIM_BEARER_TOKEN`; Groups, PUT and bulk are not implemented. Tests: `test_identity_hardening.py`. |
| **Access Control & Separation of Duties** | Can a single administrator create an account and approve their own high-risk action? | **Not when approvers come from the identity provider.** With `APPROVERS_MUST_BE_FEDERATED` (on by default in production when OIDC is configured), an approval counts only from an account linked to the IdP, so accounts created inside Argus cannot fill approval slots. Independently of that: nobody can grant a permission they do not hold or edit their own permissions, a requester cannot approve their own request through any of their keys, an account cannot approve for an account it created or that created it, and accounts younger than 24 hours cannot approve. **Limit:** on a deployment that uses only local accounts, an administrator who can create accounts can still staff an approver pool after the cooling-off period. Two-person control there depends on having two trustworthy administrators and on reviewing the audit log. |
| **Tenant Isolation** | How is multi-tenant data isolated in the database and secrets store? | **Row-level security, tenant-scoped secret names, per-tenant data keys.** Every tenant-scoped table enforces PostgreSQL `FORCE ROW LEVEL SECURITY` keyed on `current_setting('app.tenant_id', true)`. Secret references a tenant configures (integrations, collectors, action credentials) must carry that tenant's prefix once a second tenant exists (`TENANT_SECRET_ISOLATION`, default automatic). Encrypted columns on tenant-scoped tables are sealed under a key derived per tenant from the platform key (HMAC-SHA256), or under a per-tenant KMS-wrapped data key when `KMS_PROVIDER` is set. **Limit:** the KMS integrations (AWS KMS, Azure Key Vault, Vault Transit) are exercised with mocks in tests, not against the live services. |
| **Encryption at Rest & in Transit** | How are sensitive columns and backups encrypted? | **AES-256-GCM.** Finding evidence, event metadata and agent step input/output are encrypted and bound to tenant, table and column through the GCM associated data. Integration and collector secret references and action rollback payloads are encrypted under the tenant key. TOTP secrets are account-level and use the platform key. Rows are not individually bound, so a ciphertext could be moved between rows of the same column by someone with database write access. Backups use authenticated AES-256-GCM framing. `FIPS_MODE=true` switches password hashing to PBKDF2-HMAC-SHA256; Argus does not ship a FIPS 140-3 validated cryptographic module, so a validated OpenSSL provider must come from the deployment's base image. |
| **Audit Logging & Immutability** | Are audit logs tamper-evident and exported to external WORM storage and SIEM? | **Yes.** Each entry is linked in a per-tenant SHA-256 hash chain (length-prefixed fields including `actor_kind`, `request_id`, `source_ip`, `user_agent`, `session_id`) and signed with HMAC-SHA256. Failed logins, lockouts, permission denials, exports, and views of findings, events and agent transcripts are audited. Entries are written to `audit_outbox` in the same transaction and delivered to S3 Object Lock, Azure immutable blob, an HTTPS collector or syslog. The worker retries undelivered records every 10 minutes and writes the chain head to the sink hourly; `argus_audit_outbox_backlog` should be alerted on. **Limit:** the signing key is held by the application, so the external sink is what makes tampering by someone with application access detectable. |
| **Supply Chain & Offensive Code Separation** | Is offensive/pentest code absent from the defensive production image? | **Yes for the default build.** With `INCLUDE_OFFENSIVE=0` the offensive modules are removed in a separate build stage before the application is copied into the runtime image, so they are in no layer of it. Dependencies install with `pip --require-hashes` from `requirements.hashes.txt`. The release workflow signs images with Sigstore Cosign and attaches a CycloneDX SBOM and build provenance. **Limit:** no tagged release has been published yet, so there is no signed image to verify today. |
| **Business Continuity & DR** | What are the documented RPO and RTO targets? | **Targets, not measurements.** With managed Multi-AZ PostgreSQL and point-in-time recovery the target is RPO under 5 minutes and RTO under 15 minutes; both depend on the deployer's database service. Argus's own logical backup runs every 24 hours by default (`BACKUP_INTERVAL_HOURS`). A backup-and-restore drill runs in CI against PostgreSQL; no production recovery has been timed. See `docs/BACKUP.md`. |

## 3. Evidence not yet in this package

- A third-party penetration test report.
- A SOC 2 or ISO 27001 report covering eeko systems.
- Performance figures from a production topology (`docs/SCALE.md` has an in-process baseline only).
