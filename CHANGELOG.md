# Changelog

All notable changes to Argus are documented in this file.

## [Unreleased]

### Security
- **WebAuthn rewritten on the `webauthn` library.** The previous endpoints stored any string as a public key and accepted an HMAC of it, which let a password-only session satisfy MFA. Registration and assertion are now verified for origin, RP ID, user verification, signature and counter. Adding an authenticator needs an MFA-satisfied session, or the administrator's enrolment code for a first factor. Request bodies changed: both `complete` endpoints take the browser's `credential` object. Credentials registered through the old endpoints will not verify and must be re-registered.
- **SAML rewritten on `python3-saml`.** The previous endpoint checked a detached signature over the base64 body, which no identity provider produces. SP-initiated sign-in starts at `GET /api/v1/auth/saml/login`; assertions must carry an XML signature from `SAML_IDP_CERT_PEM`. `SAML_SIGNING_SECRET` is removed. New: `SAML_GROUP_ATTRIBUTE`, `SAML_REQUIRED_AUTHN_CONTEXT`. Disabled accounts can no longer sign in through SAML.
- **Custom permissions are capped.** Nobody can grant a permission they do not hold, restore one by lifting a deny, or edit their own permissions; unknown permission names are rejected. Previously a `user_admin` could grant itself every owner permission.
- **Approver rules.** An account cannot approve a request from an account it created. `APPROVERS_MUST_BE_FEDERATED` (on by default in production when OIDC is configured) counts approvals only from IdP-linked accounts.
- `OIDC_REQUIRED_ACR` is enforced on its own; it previously applied only when `TOTP_REQUIRED=true`.
- A registered passkey is now required at sign-in the same way TOTP is.
- SCIM authenticates only with `SCIM_BEARER_TOKEN` (32 characters minimum; signed-in sessions previously hit a 500), supports `filter=userName eq "..."`, paging, `GET /Users/{id}` and `/ServiceProviderConfig`, refuses to deprovision a tenant's last owner, and no longer disables an account that still belongs to another tenant.
- **Tenant-scoped secret references.** Once a second tenant exists, `env:` and `secrets:` references in integrations, collectors and action credentials must carry the tenant's prefix (`ARGUS_SECRET_<TENANT>_...`). Set `TENANT_SECRET_ISOLATION=false` to keep the old behaviour, or `true` to enforce it on a single-tenant deployment. **Multi-tenant upgrades: rename shared secrets or set the flag before deploying.**
- Encrypted columns on tenant-scoped tables are sealed under a per-tenant derived key. Existing ciphertext stays readable.
- Audit sink retries and hourly chain-head anchoring now run from the worker scheduler; new metric `argus_audit_outbox_backlog`. Views of individual events are audited.
- The console's HTML sanitizer parses markup into an inert DOM instead of pattern-matching the source text (which let `<svg/onload=...>` through). New Trusted Types policy name `argus-parse` in the CSP.

### Build
- The image installs dependencies with `pip --require-hashes` from `requirements.hashes.txt` (`scripts/lock_hashes.py`; CI checks it matches the lock).
- Offensive modules are removed in a separate build stage, so the default image carries them in no layer.
- New dependencies: `webauthn`, `python3-saml` (with `lxml`, `xmlsec`, `isodate`, `cbor2`, `pyOpenSSL`, `pyasn1`).

### Docs
- `docs/SCALE.md` now holds only figures the benchmark script produces; the previous table could not be reproduced and its PostgreSQL column had no source. `scripts/benchmark_scale.py` no longer crashes on its own ingest key.
- `docs/TRUST.md` answers corrected to match the code, with limits stated.

## [0.9.0] - 2026-11-17

### Security (Phase 0 & Phase 1–6 Hardening)
- Closed API-key approval bypass: keys minted by another key inherit the minting key's creator, and keys with no creator are refused in `identity_of` and `broker.approve`.
- Closed stale-session MFA bypass: `totp_confirm` uses only `user.totp_secret` once `totp_enabled` is true, sets `sessions_invalidated_at` when TOTP is first enabled, and re-issues the enrolling session.
- Fixed audit hash truncation and delimiter collisions: `record_audit` truncates fields before hashing, length-prefixes fields in the `v2` hash format (including `actor_kind`, `request_id`, `source_ip`, `user_agent`, `session_id`), preserves `v1` verification, and reports all chain breaks in `verify_chain`.
- Refreshed `requirements.lock.txt` (`opentelemetry-api==1.45.2`) and pinned optional dependencies, GitHub Actions SHAs, and Docker base image digests.
- Replaced blind `FORWARDED_ALLOW_IPS="*"` client IP resolution with `TRUSTED_PROXY_HOPS` (taking the Nth hop from the right of `X-Forwarded-For`).
- Separated core defensive operations from optional offensive modules (`CORE_ONLY_BUILD` / `INCLUDE_OFFENSIVE=0` in the default container build).
- Added MFA enforcement on local login, `OIDC_REQUIRED_ACR`, WebAuthn second-factor support, SAML/SCIM 2.0 endpoints, API key expiry & IP allowlists, separation-of-duty roles (`user_admin`, `approver`), 24-hour approval cooling-off, durable audit outbox & SIEM forwarding, per-tenant secret namespacing & KMS envelope encryption, signed queue jobs, and sector control mappings (PCI DSS, GLBA, FFIEC, NYDFS Part 500, DORA, HIPAA, NIST 800-53).
