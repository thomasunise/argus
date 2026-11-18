# Vendor Trust Package, SLA & Security Questionnaire Summary (CAIQ / SIG Lite)

**Vendor:** eeko systems  
**Product:** Argus — Governed Defensive Security Platform  
**Support & Security Contact:** `security@eeko.systems`

---

## 1. Service-Level Agreement (SLA) & Incident Notification Terms

| Commitment | Standard Enterprise Tier | Regulated Critical Tier (Banking / Healthcare / Gov) |
|---|---|---|
| **Platform Availability Target** | 99.9% monthly uptime | 99.95% monthly uptime (Multi-AZ deployment) |
| **Confirmed Security Incident Notification** | Within **24 hours** of confirmation | Within **12 hours** (supports NYDFS 23 NYCRR 500.17 72h, DORA Art. 19, and HIPAA breach notification windows) |
| **Critical Vulnerability Remediation (CVSS >= 9.0)** | Within **7 calendar days** | Within **72 hours** (hotfix release + signed image digest) |
| **High Vulnerability Remediation (CVSS 7.0–8.9)** | Within **14 calendar days** | Within **7 calendar days** |
| **P1 Production Outage Response** | < 1 hour (24x7 on-call) | < 15 minutes (24x7 dedicated escalation) |

---

## 2. Pre-Filled Security Questionnaire Summary (CSA CAIQ v4 / SIG Lite Mapping)

| Domain | Question Summary | Argus Answer & Technical Evidence |
|---|---|---|
| **IAM & Authentication** | Does the platform enforce MFA, SSO (OIDC/SAML), and automated provisioning (SCIM 2.0)? | **Yes.** Local logins enforce TOTP or WebAuthn passkeys (`TOTP_REQUIRED=true`) and can be disabled entirely except for a single break-glass account (`LOCAL_LOGIN_DISABLED=true`, `BREAK_GLASS_EMAIL`). OIDC checks the IdP's `acr`/`amr` claim (`OIDC_REQUIRED_ACR`), SAML 2.0 assertions are verified at `/api/v1/auth/saml/acs`, IdP groups map to tenants/roles (`OIDC_GROUP_MAP`), and SCIM 2.0 (`/api/v1/scim/v2/Users`) immediately revokes sessions and API keys upon deprovisioning. |
| **Access Control & Separation of Duties** | Can a single administrator create an account and approve their own high-risk action? | **No.** Permissions are assignable per role/membership (`user_admin` lacks `actions:approve`; `approver` lacks `admin:users`). The action broker enforces distinct human identities across users and API keys, blocks keys without a creator, and enforces a 24-hour cooling-off rule on newly created accounts and accounts created by the requester (`app/actions/identity.py`). |
| **Tenant Isolation** | How is multi-tenant data isolated in the database and secrets store? | **Row-Level Security + Per-Tenant Keys.** Every tenant-scoped table enforces PostgreSQL `FORCE ROW LEVEL SECURITY` keyed on `current_setting('app.tenant_id', true)`. Secret references (`env:` / `secrets:`) require a tenant slug prefix, and envelope encryption derives a distinct HKDF data key per tenant (`app/core/crypto.py`). |
| **Encryption at Rest & in Transit** | How are sensitive columns and backups encrypted? | **AES-256-GCM Envelope Encryption with Context AAD.** Credentials, TOTP secrets, finding evidence, raw security events, and agent transcripts are encrypted with per-tenant keys and bound to `tenant\|table\|column\|row` via AES-256-GCM AAD (`enc:v2:`). Backups use authenticated STREAM AES-256-GCM framing. FIPS 140-3 deployments enable `FIPS_MODE=true` (`PBKDF2-HMAC-SHA256`). |
| **Audit Logging & Immutability** | Are audit logs tamper-evident and exported to external WORM storage and SIEM? | **Yes.** Every audit entry is linked in a per-tenant SHA-256 hash chain (`v2:` length-prefixed format including `actor_kind`, `request_id`, `source_ip`, `user_agent`, `session_id`) signed with HMAC-SHA256. Failed logins, lockouts, permission denials, and sensitive data reads are audited. Entries are persisted in `audit_outbox` in the same DB transaction and delivered with retries to S3 Object Lock, Azure Immutable Blob, HTTPS SIEM, or Syslog, with periodic chain-head anchoring. |
| **Supply Chain & Offensive Code Separation** | Is offensive/pentest code absent from the defensive production image? | **Yes.** The default image builds with `INCLUDE_OFFENSIVE=0` (`CORE_ONLY_BUILD=true`), physically omitting `app/pentest`, `app/exploit`, `app/discovery`, and `app/testing/autopilot.py`. Release images are signed with Sigstore Cosign and attested with CycloneDX SBOMs. |
| **Business Continuity & DR** | What are the documented RPO and RTO targets? | **RPO < 5 minutes / RTO < 15 minutes** with managed Multi-AZ PostgreSQL + WAL PITR; **0 committed audit entries lost** via transactional WORM outbox; **< 30 minutes** full logical restore verified on every CI push (`docs/BACKUP.md`). |
