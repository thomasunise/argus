# Architecture

```text
                   ┌──────────────────────────┐
Browser (auth) ───►│   FastAPI + static UI    │
                   │ HTTPS via reverse proxy  │
                   └────────────┬─────────────┘
                                │
                     Auth + CSRF + policy
                                │
                ┌───────────────┼─────────────────────┐
                ▼               ▼                     ▼
           Asset registry   Event ingestion       Scan dispatcher
                │           Wazuh/Falco/Trivy         │
                │               │                Only typed tools
                │               ▼                     │
                │        Normalizer + rules       HTTPS baseline
                │               │                Optional Trivy
                └───────────────┼─────────────────────┘
                                ▼
                           Findings DB
                                │
                    Read-only AI investigation
                      Ollama / OpenAI / Claude
                                │
                    Evidence-backed remediation
                                │
                     Human approval recording
                      (NO privileged executor)
                                │
                         Audit + reports
```

## Security boundaries

- Browser sessions identify the administrator; ingestion API credentials are separate.
- A scanner accepts a **server-side registered, approved asset ID**, never a raw user-command string.
- A policy module must reauthorize the request when the scan job executes.
- The built-in HTTPS scanner disallows plaintext HTTP, arbitrary URL paths/ports, local addresses and redirects.
- AI only receives minimized metadata; outputs are never interpreted as commands.
- No tool execution is routed through an LLM; a worker's available commands are fixed in code.
- Approval state changes cannot trigger privileged operations.

## Schema

`assets`: authorized targets and their environments.

`events`: deduplicated, selected normalized event metadata with a source event ID.

`findings`: deduplicated issues with severity, status, evidence metadata and remediation advice.

`runs`: scan queue state and outcome.

`investigations`: model name, summary, confidence and proposed actions.

`approvals`: reviewed plans; actions are **record-only**.

`audit`: hash-linked history. For trustworthy immutability, export hashes to an external write-once store.

## Why not one unrestricted agent?

LLM output is probabilistic and evidence can contain attacker-supplied prompt injection. The model therefore cannot acquire privileges, expand target scope or directly operate production systems. Policy enforcement is independent and deterministic. Any future executor should use short-lived, service-specific credentials and allowlisted operations that are verified before and after execution.

## Next steps for scaling

Move scan execution into isolated workers; use a persistent queue with per-asset rate limits and leases; add PostgreSQL, Alembic migrations, customer/tenant isolation, OIDC/RBAC, centralized immutable logs, hosted secrets, SIEM connectors, evidence retention controls, and robust SSRF-resistant egress routing. Provide sandboxed scanner runners and a reviewed protocol for integrations such as Prowler, ZAP/Nuclei and CALDERA.
