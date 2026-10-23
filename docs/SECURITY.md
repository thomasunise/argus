# Security model and release limitations

**Default deny is intentional.** This is a pilot, not a production-hardened or independently audited security product.

## Authorization

- Scan targets must be in the asset inventory and separately approved by an administrator attesting authorization.
- Only `web-baseline` for HTTPS origins and `trivy-repo` for repositories are executable.
- Only ports 443 or 8443 are accepted for HTTPS checks; no arbitrary path or query.
- Never allow a language model, untrusted finding, SIEM event or website content to choose tool commands, scan ranges or execution privileges.
- Private addresses require opt-in plus an explicit CIDR allowlist; loopback and link-local remain prohibited.
- Follow redirects is disabled. **DNS pinning is not implemented:** use a dedicated egress proxy/firewall with DNS rebinding protection and reject access to cloud metadata IPs.

## Threats and mitigations

| Threat | Present defense | Required for production |
| --- | --- | --- |
| Prompt injection via logs | Model is read-only; input minimized | Red-team prompt injection and rigid schemas |
| SSRF / internal network probing | Destination checks, no redirects, no HTTP | Enforced egress ACLs; DNS/IP pinning |
| Unauthorized scanning | Admin auth, explicit asset approval | Proof of ownership and signed scope documents |
| Stolen admin session | HttpOnly SameSite cookie, CSRF header | MFA/SSO, conditional access, session revocation |
| Brute force password attack | Limited in-memory throttling | Edge rate limiting and detection |
| Raw secret leakage | Trivy secret content excluded from finding imports | Scanning workers with DLP, secrets inventory and strict data retention |
| Database tampering | Local hash chaining | Signed, externally anchored write-once audit storage |
| Excessive scanner privilege | Fixed arguments, no shell, repo-root restriction | Sandbox per invocation, seccomp and network isolation |
| Supply-chain attack | Minimal dependencies | Signed images, SBOM, pinned hashes and routine patching |

## Incident handling

The current application cannot isolate machines, patch hosts, change firewall rules, revoke credentials, deploy changes or prevent incidents. An approval record is **not** proof that remediation was performed. Production remediation requires a separately implemented change executor with identity-scoped permissions, rollback, blast-radius limits, preconditions, change window support, independent logs and tests.

## Safe deployment

Set strong `.env` secrets. Keep the API behind an HTTPS proxy with restrictive allowlists or an authenticated tunnel; do not forward the dashboard port to the public internet. Use dedicated non-root workers. Do not mount `/var/run/docker.sock`, SSH private keys, cloud administrator credentials or arbitrary host files into the API service. Protect the database, back it up, and test restores.

## Responsible security testing

Use this only on systems you own or where you have explicit written permission. Active security testing can affect production reliability. The built-in web checks are intentionally limited and non-invasive. For deeper testing, create a written scope, rate limits and a testing window and operate in a sandbox or staging environment.
