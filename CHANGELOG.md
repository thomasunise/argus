# Changelog

All notable changes to Argus are documented in this file.

## [0.9.0] - 2026-11-17

### Security (Phase 0 & Phase 1–6 Hardening)
- Closed API-key approval bypass: keys minted by another key inherit the minting key's creator, and keys with no creator are refused in `identity_of` and `broker.approve`.
- Closed stale-session MFA bypass: `totp_confirm` uses only `user.totp_secret` once `totp_enabled` is true, sets `sessions_invalidated_at` when TOTP is first enabled, and re-issues the enrolling session.
- Fixed audit hash truncation and delimiter collisions: `record_audit` truncates fields before hashing, length-prefixes fields in the `v2` hash format (including `actor_kind`, `request_id`, `source_ip`, `user_agent`, `session_id`), preserves `v1` verification, and reports all chain breaks in `verify_chain`.
- Refreshed `requirements.lock.txt` (`opentelemetry-api==1.45.2`) and pinned optional dependencies, GitHub Actions SHAs, and Docker base image digests.
- Replaced blind `FORWARDED_ALLOW_IPS="*"` client IP resolution with `TRUSTED_PROXY_HOPS` (taking the Nth hop from the right of `X-Forwarded-For`).
- Separated core defensive operations from optional offensive modules (`CORE_ONLY_BUILD` / `INCLUDE_OFFENSIVE=0` in the default container build).
- Added MFA enforcement on local login, `OIDC_REQUIRED_ACR`, WebAuthn second-factor support, SAML/SCIM 2.0 endpoints, API key expiry & IP allowlists, separation-of-duty roles (`user_admin`, `approver`), 24-hour approval cooling-off, durable audit outbox & SIEM forwarding, per-tenant secret namespacing & KMS envelope encryption, signed queue jobs, and sector control mappings (PCI DSS, GLBA, FFIEC, NYDFS Part 500, DORA, HIPAA, NIST 800-53).
