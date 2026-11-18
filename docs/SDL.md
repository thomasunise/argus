# Security Development Lifecycle (SDL) & Supply-Chain Governance

**Organization:** eeko systems  
**Product:** Argus — Governed Defensive Security Platform

This document defines the Secure Software Development Lifecycle (SDL), threat-modeling cadence, supply-chain pinning, and vulnerability disclosure governance for Argus (aligned with NIST SP 800-218 SSDF and SOC 2 CC8.1).

---

## 1. Threat Modeling & Architecture Review Per Release

Every minor and major release of Argus requires a documented threat-model review before a release tag (`v*`) is cut:

1. **Trust-Boundary Review**:
   - Verify all ingress paths (`/api/v1/*`, `/api/v1/ingest/*`, `/api/v1/scim/v2/*`, `/api/v1/ai-gateway/*`, `/c/*` canary endpoints) enforce tenant scoping (`set_tenant_context` + PostgreSQL RLS), rate limiting, and body-size bounds.
   - Verify proxy hop handling (`TRUSTED_PROXY_HOPS`) and outbound SSRF/DNS pinning (`app/integrations/egress.py`).
2. **Separation-of-Duties & Approval Review**:
   - Confirm no single principal, API key, or administrator can unilaterally approve and execute a high- or critical-risk action (`app/actions/broker.py`, `app/actions/identity.py`).
   - Confirm cooling-off rules (24-hour hold on newly created accounts and creator-requester separation) and RBAC role boundaries (`user_admin` vs `approver`).
3. **Core-Only Build Boundary**:
   - Confirm the default container build (`INCLUDE_OFFENSIVE=0`, `CORE_ONLY_BUILD=true`) excludes offensive modules (`app/pentest`, `app/exploit`, `app/discovery`, `app/testing/autopilot.py`) from the image filesystem and API router graph.

---

## 2. Automated CI Gates on Every Pull Request

Every change to `main` must pass the following automated gates in `.github/workflows/test.yml` and `.github/workflows/codeql.yml`:

| Gate | Tool | Failure Threshold |
|---|---|---|
| **Static Application Security Testing (SAST)** | Ruff (`S` bandit rules) + GitHub CodeQL (`python`, `javascript-typescript`, `actions`) | Any violation fails CI |
| **Secret Scanning** | Gitleaks + GitHub Push Protection | Any committed secret fails CI |
| **Dependency Vulnerability Audit** | `pip-audit -r requirements.lock.txt --strict` | Any known CVE in locked dependencies fails CI |
| **Type & Complexity Ratchet** | `mypy app` (`docs/mypy-baseline.txt` = `0`) + McCabe `C901` (`max-complexity = 18`) | Zero unannotated regressions; zero complexity exemptions on core paths |
| **Container Vulnerability Scan** | Trivy (`aquasecurity/trivy-action`) | Any `CRITICAL` or `HIGH` OS/library CVE with an available fix fails CI |
| **Unit, Abuse, & PostgreSQL RLS Suite** | `pytest` (SQLite + real PostgreSQL 16 with `FORCE ROW LEVEL SECURITY`) | Coverage < 80% overall or any failed test blocks merge |

---

## 3. Supply-Chain Pinning, Signing, SBOM & VEX

1. **Deterministic Builds**:
   - Base images in `Dockerfile` and `sandbox/*.Dockerfile` are pinned by immutable SHA-256 digest.
   - All GitHub Actions in `.github/workflows/*.yml` are pinned by full 40-character commit SHA.
   - Python dependencies in `requirements.lock.txt` and `requirements-optional.txt` are pinned to exact versions (`==`).
2. **Artifact Signing & Provenance**:
   - Release images (`ghcr.io/eeko-systems/argus:<tag>` and `<tag>-extras`) are signed keyless with Sigstore Cosign OIDC in `.github/workflows/release.yml`.
   - Build provenance attestations (`actions/attest-build-provenance`) and CycloneDX SBOMs (`syft` + `cosign attest --type cyclonedx`) are attached to every published digest.
3. **VEX (Vulnerability Exploitability eXchange)**:
   - When an upstream base-image CVE is unexploitable in Argus (e.g., an unused binary in Debian slim), a signed OpenVEX statement is published alongside the release notes and reviewed within 7 days.

---

## 4. Repository Governance & Dual-Control Merge Policy

- **Branch Protection**: `main` requires signed commits, at least one independent maintainer review (`CODEOWNERS`), and all status checks green before merge.
- **Vulnerability Disclosure**: Security reports are triaged within 48 hours and remediated on the SLA published in [docs/SECURITY.md](file:///C:/Users/thoma/OneDrive/Desktop/sentinel-agentic-security/docs/SECURITY.md).
