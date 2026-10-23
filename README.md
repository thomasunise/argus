# Sentinel — Agentic Security Operations

**A runnable, self-hosted security operations MVP** combining an asset registry, authorized checks, external alert ingestion, AI-assisted findings analysis, approval records, audited workflows and a polished operations dashboard.

Sentinel is **not** a finished autonomous penetration-testing suite, enterprise SIEM, managed EDR, compliance certification platform or guaranteed intrusion prevention tool. Real built-in scanning in this version is limited to HTTPS baseline checks and optional local repository analysis with Trivy. Wazuh, Falco and Trivy event ingestion are implemented. Prowler, Nuclei, CALDERA and arbitrary remediation execution are future adapters, not included integrations.

## Quick start (Python)

Prerequisites: Python 3.11+ and a system where you can safely run services on loopback.

```bash
cp .env.example .env
python scripts/generate_secrets.py
# Replace the three REPLACE_ values in .env with three generated secrets.
python -m venv .venv
source .venv/bin/activate              # Windows: .venv\\Scripts\\activate
pip install -r requirements.txt
uvicorn app.main:app --host 127.0.0.1 --port 8080
```

Open **http://127.0.0.1:8080**. Sign in using the `ADMIN_PASSWORD` you configured.

For an isolated demonstration with synthetic, explicitly labeled records:

```bash
python scripts/seed_demo.py
```

`seed_demo.py` never scans an actual target and does not authorize its demo assets. To remove demo data, use a fresh database. Do **not** run it in a real production environment.

## Docker quick start

```bash
cp .env.example .env
python scripts/generate_secrets.py
# Put secrets in .env. Ensure DATABASE_URL=sqlite:///./data/sentinel.db
# When using Docker keep SCAN_ROOT=/app/targets
# With Docker, OLLAMA_URL must be reachable from inside the container, not localhost on host.
docker compose up --build -d
```

Docker exposes Sentinel **only on 127.0.0.1:8080**. Access remotely using an SSH tunnel or HTTPS reverse proxy with access restrictions. The container runs as an unprivileged user, without root privileges, added capabilities, or host Docker socket access. Trivy is not bundled in the default image.

### What actually works

- Password-protected dashboard (signed HttpOnly session cookie + per-session CSRF token)
- Asset inventory and auditable explicit scan-authorization attestation
- Limited HTTPS scan for verified TLS, certificate expiry, HSTS, CSP, MIME-sniffing and referrer policy
- Repo scanning via local `trivy fs` CLI when `ENABLE_TRIVY=true`, installed in the execution environment
- Native Wazuh and Falco alert JSON ingestion with deduplication and severity mapping
- Trivy JSON report ingestion with removal of secret contents
- Optional pull of recent Wazuh alerts from the **Wazuh indexer** over TLS
- Finding triage and status management; rule-based review without an AI provider
- AI-assisted read-only investigations using Ollama, OpenAI, or Anthropic
- Recorded high-impact approval decisions (approval **does not execute** remediation)
- Findings CSV/JSON export, scan run history, local hash-chained audit records
- Optional scheduling for **approved HTTPS assets only**, disabled by default
- Synthetic demo fixture script and automated tests

### Important limitations

1. **Only scan systems you control or have explicit authorization to test.** The confirmation checkbox records a declaration; the system cannot independently verify ownership.
2. The HTTPS scanner performs DNS/IP checks and disallows redirects, but DNS rebinding and network routing are not fully controlled at the Python application layer. **Use independent egress firewall policy** to prevent metadata endpoint, loopback, internal address, and unintended target access. Test this before production.
3. Never expose the interface directly to the public internet. In production use HTTPS, network allowlists, identity-aware gateway/SSO, edge rate limiting, monitoring, backups, proper secret management, and a managed data store.
4. The single administrator role and SQLite implementation are for a single-node pilot only. Introduce RBAC, multi-tenant isolation, migrations, a task queue and external WORM audit storage before commercial multi-customer operations.
5. The LLM has **no tools**: it analyzes minimized finding metadata and returns advisory steps. Do not forward highly sensitive metadata to hosted providers without additional data governance.
6. Trivy local execution requires a trusted binary, a warmed vulnerability DB (`trivy image --download-db-only` or equivalent), a sandboxed worker and read-only repository access. The default Docker image intentionally leaves this optional scanner disabled.
7. No autonomous exploitation, DAST fuzzing, adversary emulation or privileged remediation is implemented in this version. These require separately reviewed tool adapters, sandboxing, change control and testing.
8. For a persistent, high-volume deployment, offload event processing and scanning to independent workers rather than a FastAPI process and back event ingestion with a queue.

## Asset workflow

1. Select **Asset inventory → Register asset**.
2. Specify an `https://` **origin** URL (no path, credentials or query parameters; only ports 443/8443) or a relative repo folder under `SCAN_ROOT`.
3. Select **Authorize** and explicitly attest administrative control. The platform checks the target against the server-side address policy.
4. Select **Scan** to enqueue the matching approved scanner.
5. View detected items under **Findings**, generate a rules-based/AI investigation, and record resolution status.

Host, cloud and database assets can be registered for inventory, but require external sensors; the built-in scanner does not directly inspect them.

## External telemetry: POST ingestion

**Use a distinct ingestion API key. Never put this key in frontend code or commit it.**

```bash
curl -fsS 'http://127.0.0.1:8080/api/ingest/falco' \
  -H "X-Ingest-Key: $INGEST_API_KEY" \
  -H 'Content-Type: application/json' \
  --data-binary @examples/falco-alert.json

curl -fsS 'http://127.0.0.1:8080/api/ingest/wazuh' \
  -H "X-Ingest-Key: $INGEST_API_KEY" \
  -H 'Content-Type: application/json' \
  --data-binary @examples/wazuh-alert.json

curl -fsS 'http://127.0.0.1:8080/api/ingest/trivy' \
  -H "X-Ingest-Key: $INGEST_API_KEY" \
  -H 'Content-Type: application/json' \
  --data-binary @examples/trivy-report.json
```

These sample event files are **synthetic**. In real setups configure your monitoring agents to securely forward actual JSON events to an ingress service. Ingestion must pass through an HTTPS endpoint or a private tunnel, not plaintext over the public internet. Falco's HTTP output can send JSON to `/api/ingest/falco` but does not natively add custom auth headers in all configurations; use an authenticated relay to insert `X-Ingest-Key` where needed.

### Wazuh indexer polling

Set `WAZUH_INDEXER_URL=https://your-indexer:9200`, the read-only `WAZUH_INDEXER_USER` / `WAZUH_INDEXER_PASSWORD` and optionally `WAZUH_CA_BUNDLE=/path/to/trusted/ca.pem`. Click **Integrations → Sync Wazuh alerts**. The connector reads up to 200 recent records from `wazuh-alerts-*` within a rolling 30-minute window. It does not use the Wazuh manager API. The indexer user should have access to read only the intended alert indices.

### Trivy integration

For external CI jobs, ingest a JSON Trivy report using `/api/ingest/trivy`. Add `X-Asset-ID` if you want to associate the findings with an inventory asset. Only the identifier, affected package, fix version and safe metadata are imported; no raw secret matches are retained.

For local repo scanning, install Trivy from its official documentation, predownload its vulnerability DB, set `ENABLE_TRIVY=true`, and make the repository available within `SCAN_ROOT` (set to a read-only mount in production). The CLI execution uses fixed arguments and a 120-second timeout; no user commands or shell interpretation.

## AI configuration

Select one in `.env` and restart. All models receive **only minimized finding metadata**, not raw logs or source code. The LLM cannot trigger scans, change configurations, execute commands or approve actions.

```ini
AI_PROVIDER=ollama
OLLAMA_URL=http://127.0.0.1:11434
OLLAMA_MODEL=gpt-oss:20b
```

Or:

```ini
AI_PROVIDER=openai
OPENAI_API_KEY=...
OPENAI_MODEL=<model supporting the Chat Completions API>
```

Or:

```ini
AI_PROVIDER=anthropic
ANTHROPIC_API_KEY=...
ANTHROPIC_MODEL=<supported messages API model>
```

The `.env.example` model names are illustrative and can become outdated; choose a model actually supported by your account/provider. No vendor API calls are made until you select a hosted provider and request an investigation.

Ollama can run on a separate inference host behind a private network; configure URL access from inside the container. Set `AI_PROVIDER=none` to use deterministic, offline-only investigations.

## Automated scans

`AUTOSCAN_ENABLED=false` by default. Setting it to true enables HTTPS baseline checks on approved web assets roughly every `AUTOSCAN_MINUTES` (default 360). It does **not** enable repository scanning, intrusive testing or incident response. Run exactly **one** API worker for this initial scheduler; multi-worker scheduling requires a distributed queue and leases.

## Internal assets

Private ranges are denied by default, including RFC1918. For an approved internal staging network, set `ALLOW_PRIVATE_TARGETS=true` and an explicit narrow value such as `PRIVATE_TARGET_CIDRS=10.23.45.0/24`. Loopback, link-local and multicast targets are always denied. Pair this with a dedicated scanner worker network and egress ACLs; config changes alone do not provide complete SSRF protection.

## Project layout

```text
app/
  main.py           FastAPI, auth, asset/scan/event/finding APIs
  models.py         Database models
  policy.py         Enforcement of scan scope and allowed targets
  scanners.py       Limited HTTPS and repository checks
  findings.py       Event normalization, deduplication, correlation
  intelligence.py   Read-only model analysis (Ollama/OpenAI/Claude)
  audit.py          Local hash-chained audit events
  static/           Responsive security dashboard
examples/           Explicitly synthetic telemetry payloads
scripts/            Secret generator and optional demo loader
tests/              Auth, policy, ingestion and scanner integration tests
docs/               Security and architectural details
```

## Validate locally

```bash
pip install pytest
pytest -q
```

## Architecture and roadmap

See `docs/ARCHITECTURE.md`, `docs/SECURITY.md` and `docs/ROADMAP.md`.

**License:** MIT, for this generated Sentinel source code. Third-party integrations and models are governed by their own licenses.
