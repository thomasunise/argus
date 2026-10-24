# AI gateway and shadow-AI discovery

Two related controls for AI use inside the organization:

- **AI gateway**: Argus acts as a governed proxy in front of OpenAI and Anthropic. People and
  agents call models with an Argus API key; Argus applies the tenant policy, forwards the call
  with the organization's provider key, and records metadata about every call.
- **Shadow-AI discovery**: Argus scans the events it already ingests for use of known AI
  services (network traffic, managed model APIs in cloud accounts, OAuth grants to AI apps)
  and keeps an inventory you review. Unreviewed or blocked services raise a detection.

Code: `app/ai/` (gateway, DLP, catalog, discovery), `app/api/ai_gateway.py`,
`app/api/ai_inventory.py`, rule `app/detections/rules/ai.py`, agent tool `app/agents/tools/ai.py`,
tables in `app/models/ai.py`.

## Gateway

### Enable it

```env
AI_GATEWAY_ENABLED=true
AI_GATEWAY_OPENAI_API_KEY=env:ARGUS_SECRET_OPENAI_KEY        # a value or a secret reference
AI_GATEWAY_ANTHROPIC_API_KEY=file:/run/secrets/anthropic_key
# optional
AI_GATEWAY_OPENAI_BASE_URL=https://api.openai.com             # must be https (checked at startup)
AI_GATEWAY_ANTHROPIC_BASE_URL=https://api.anthropic.com
AI_GATEWAY_TIMEOUT_SECONDS=120
AI_GATEWAY_MAX_REQUEST_BYTES=2097152
AI_GATEWAY_REQUESTS_PER_MINUTE=120                            # per API key; tenant policy can override
AI_GATEWAY_MODEL_PRICES=gpt-4.1=2:8,gpt-4.1-mini=0.4:1.6       # USD per million input:output tokens
```

A provider without a key is reported as not configured (503) instead of being called.

### Use it

Create an API key with role analyst or higher, ideally scoped to `ai_gateway:use` only:

```bash
curl -X POST https://argus.example.com/api/v1/auth/api-keys -H 'X-CSRF-Token: ...' \
  -d '{"name": "ai-gateway alice", "role": "analyst", "scopes": ["ai_gateway:use"]}'
```

Point the SDKs at Argus. The Argus key goes where the provider key normally goes; it is never
forwarded upstream.

```python
from openai import OpenAI
client = OpenAI(base_url='https://argus.example.com/api/v1/ai-gateway/openai/v1', api_key='argus_...')

import anthropic
client = anthropic.Anthropic(base_url='https://argus.example.com/api/v1/ai-gateway/anthropic', api_key='argus_...')
```

Supported routes: OpenAI chat completions, embeddings and models; Anthropic messages and
models. Streaming (`stream: true`) is passed through byte for byte. For OpenAI streaming
requests the gateway adds `stream_options.include_usage=true` so the final chunk carries token
counts for metering.

### Tenant policy

`GET/PUT /api/v1/ai-gateway/policy` (`PUT` needs `ai:write`, replaces the whole policy, audited).
Stored in `Tenant.settings_json['ai_gateway']`.

| Field | Default | Meaning |
|---|---|---|
| `enabled` | `true` | tenant-level switch |
| `allowed_providers` | `[]` (all configured) | subset of `openai`, `anthropic` |
| `allowed_models` | `[]` (any) | model names or globs, e.g. `["claude-*", "gpt-4.1*"]` |
| `dlp_mode` | `block` | `block` the request, `redact` matches before forwarding, or `log` only |
| `dlp_types` | secrets + `credit_card` + `us_ssn` | which detected types the mode applies to; others are recorded only |
| `block_prompt_injection` | `false` | block requests whose user/tool content trips the injection heuristics |
| `max_request_bytes` | `AI_GATEWAY_MAX_REQUEST_BYTES` | body size cap |
| `requests_per_minute` | `AI_GATEWAY_REQUESTS_PER_MINUTE` | per API key |
| `monthly_budget_usd` | none | once the calendar month's recorded spend reaches it, calls get 429 |

DLP types: `aws_access_key`, `private_key`, `api_key` (OpenAI, Anthropic, GitHub, Slack, Google,
GitLab, Hugging Face, Argus key shapes), `jwt`, `credential_assignment` (`password=...`),
`secret_other` (anything `core.security.redact` masks that no typed pattern named),
`credit_card` (Luhn-checked), `us_ssn`, `email`, `iban`. Structural JSON fields (`model`, `role`,
`type`, ids, base64 `data`) are not scanned.

Prompt-injection detection reuses the agents' deterministic heuristics
(`injection_signals`). It runs over user and tool content only, never system or assistant
messages. The heuristics are broad (phrases like "act as" match), so the default is to flag
(`prompt_injection=true` on the record) rather than block.

Blocked calls get a provider-shaped error body (`{"error": {"message", "type": "argus_policy"}}` for
OpenAI, `{"type": "error", "error": {...}}` for Anthropic) so SDKs show the reason, and they are
audited as `ai_gateway.blocked`.

### What is recorded

`ai_gateway_requests`: API key, owning user, actor, provider, endpoint, model, stream flag, status
(`allowed` / `blocked` / `error`), block reason, DLP hit types and counts, DLP action,
prompt-injection flag, input/output tokens, estimated cost, latency, upstream status, request
size. Prompts, completions and keys are never stored or logged.

Cost uses the agent price table (`app/agents/providers.py`), `AGENT_MODEL_PRICES` and
`AI_GATEWAY_MODEL_PRICES`; dated snapshots fall back to the longest known prefix. Models with
no price are recorded at $0 and do not count toward `monthly_budget_usd`.

Successful gateway use also adds an inventory row (`channel=gateway`, `status=sanctioned`).

## Shadow-AI discovery

The `ai.discover` job scans `SecurityEvent` rows received since the tenant's cursor
(`ai_discovery_state`, first run looks back 30 days, at most 20,000 events per run) and matches:

1. **Cloud API signatures**: CloudTrail `bedrock.*` actions or `bedrock.amazonaws.com` event
   source; Azure `Microsoft.CognitiveServices` operations; GCP `aiplatform` / Vertex and
   `generativelanguage` methods. Channel `cloud_api`.
2. **OAuth / SaaS grants**: identity events (Okta, Entra, Google Workspace, generic) whose action
   or title is a consent, grant or app assignment, and whose app name is a known AI app
   (ChatGPT, Claude, Copilot, Gemini, Otter.ai, Fireflies, Cursor, ...). Channel `oauth_app`.
3. **Hostnames**: hostnames in the event entity or metadata (`host`, `domain`, `sni`, `query`,
   `url`, `top_destination`, ...) matched by suffix against the catalog (`api.openai.com`,
   `claude.ai`, `generativelanguage.googleapis.com`, `api.groq.com`, `openrouter.ai`, ...).
   Channel `network`.

Each match upserts one `ai_services` row per (service, channel, actor) with first/last seen,
event count, asset and the matched evidence (domain, API action or app name only). A new actor
of a service that was already reviewed inherits the decision (`blocked` wins over `sanctioned`).

The job runs every `AI_DISCOVERY_INTERVAL_MINUTES` (default 15) for each active tenant when
`AI_DISCOVERY_ENABLED=true`, and on demand with `POST /api/v1/ai/discover`.

Review with `PATCH /api/v1/ai/services/{id}` (`ai:write`): `sanctioned`, `blocked` or back to
`unreviewed`, plus notes. By default the status applies to every actor and channel of that
service (gateway rows are left alone).

### Detection rule

`agentic.unsanctioned_ai_service` reads the inventory and raises one detection per (service,
channel, status) seen in the run window: `high` for blocked services, `medium` for unreviewed
OAuth grants and cloud model APIs, `low` for unreviewed network use. Gateway rows never fire.
Parameters: `bucket_minutes` (1440), `include_unreviewed` (true), `ignore_services` (catalog
keys), `min_events` (1). Disable or tune it per tenant like any rule.

The read-only agent tool `ai_inventory` gives the specialists the same inventory and the
gateway's 30-day totals.

## Permissions

| Permission | Role | Grants |
|---|---|---|
| `ai:read` | viewer+ | inventory, catalog, gateway status, policy, records, stats |
| `ai_gateway:use` | analyst+ | calling the proxy routes (API keys only) |
| `ai:write` | admin+ | gateway policy, inventory review, on-demand discovery |

## Limits

- The gateway covers the OpenAI and Anthropic HTTP APIs named above. Other providers, the
  OpenAI Responses/Assistants/Realtime APIs and file uploads are not proxied.
- Discovery only sees what Argus ingests. Without DNS, proxy, netflow or SNI telemetry it cannot
  see browser use of AI assistants; the inventory is a lower bound.
- DLP is pattern-based. It catches well-formed secrets and common PII, not confidential prose.
- The rate limiter is per process (like the rest of Argus); run one gateway replica or put an
  edge limiter in front until Redis-backed limits land.
