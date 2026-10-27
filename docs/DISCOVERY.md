# Discovery loop

Discovery finds what exists on an authorized web asset, stores it as facts, and queues bounded
follow-up tests. It is the first half of what makes an offensive platform useful - knowing where
to look - and it is deliberately the least aggressive half: no payloads, no brute force, no
exploitation.

## Flow

```
POST /api/v1/discovery/runs {asset_id, scope_id}
  -> gate: DISCOVERY_ENABLED, kill switch, tenant opt-in (settings.discovery.enabled)
  -> scope.check(recon, tier=active): asset in scope, authorization allows active, window, target valid
  -> engine job in the executor (egress pinned to the asset origin)
  -> ARGUS_DISCOVERY lines parsed -> discoveries table (deduped per tenant+asset+kind+value)
  -> up to DISCOVERY_FOLLOW_UP_LIMIT new endpoints -> testing.service.launch_scan(adapter='nuclei')
       (which re-checks the scope at request time)
  -> audit: discovery.run.started / completed / denied, discovery.followup.queued
```

## What recon does

`sandbox/recon_runner.py` requests `/`, `robots.txt`, `sitemap.xml`, a small fixed path list and
`/.well-known/security.txt`, then extracts same-origin links and inline JS paths. It records
technology hints from `Server`/`X-Powered-By`-style headers. It never sends a payload, never uses a
wordlist, and never follows a redirect off the origin.

## API

| method | path | permission | purpose |
|---|---|---|---|
| `POST` | `/api/v1/discovery/runs` | `tests:run` | start a pass for one asset + scope |
| `GET` | `/api/v1/discovery/runs` | `tests:read` | list passes |
| `GET` | `/api/v1/discovery/runs/{id}` | `tests:read` | one pass with the facts it produced |
| `GET` | `/api/v1/discovery/facts` | `tests:read` | all facts, filter by asset or kind |

## Configuration

```yaml
config:
  DISCOVERY_ENABLED: "true"
  DISCOVERY_IMAGE: "ghcr.io/thomasunise/argus-recon@sha256:<digest>"
  DISCOVERY_MAX_ENDPOINTS: "100"
  DISCOVERY_FOLLOW_UP_LIMIT: "5"
  DISCOVERY_MAX_WALL_SECONDS: "900"
sandbox:
  engineImages: "ghcr.io/thomasunise/argus-recon@sha256:<digest>"   # executor allowlist
```

## Limits

- **Recon is shallow on purpose.** It does not fuzz parameters, brute-force directories or parse
  JavaScript bundles deeply. Those belong to a later phase with their own caps.
- **Follow-ups are ordinary test runs.** If the scope, authorization or window no longer permits
  active testing, `launch_scan` denies them and the discovery run still completes with fewer tests.
- **Facts are not findings.** A discovered `/admin` is a fact with `confidence`, not a vulnerability;
  only the test harness (nuclei, ZAP, Strix) produces findings.

## Browser phase (rendered discovery)

When `DISCOVERY_BROWSER_IMAGE` is set, a discovery run executes two engines in order, both inside
the same pinned-egress envelope:

1. **browser** (`sandbox/browser_runner.py`): loads the asset in headless Chromium, records every
   same-origin request the page issues (the passive equivalent of an interception proxy), and
   extracts same-origin links from the rendered DOM. Every request to another origin is aborted, so
   a third-party script cannot pull the engine off the asset.
2. **recon** (`sandbox/recon_runner.py`): the raw crawl and probe pass.

Facts from both phases are merged and deduplicated per (asset, kind, value), so `/admin` found by
both engines is stored once. The two engine jobs are named `argus-engine-<id>b` and
`argus-engine-<id>r`; the executor resolves them by job name, not by reconstructing one.

## Fuzzing (separate adapters, separate tiers)

Fuzzing is not part of the recon image: it sends input, so it belongs to the test harness where the
tier rules already apply.

| adapter | tier | what it sends | what it reports |
|---|---|---|---|
| `param_probe` | active | a random marker value in common query parameters | reflected parameters (low) |
| `payload_fuzz` | intrusive | a curated set: quotes, `"><argus>`, a traversal path | SQL error signatures (high), unencoded reflection (medium), readable passwd (critical) |

`param_probe` runs anywhere active testing is authorized. `payload_fuzz` is intrusive, so the
existing scope rules restrict it to staging/lab assets whose authorization permits intrusive
testing. Neither sends stacked queries, writes, time-based payloads or shell commands.

## Capture and replay (the proxy half)

The browser phase records every same-origin request it issues: method, path, status, content type,
and whether an `Authorization` or `Cookie` header was present. Values are never stored, so a
transcript cannot leak a session token.

`POST /api/v1/discovery/requests/{id}/replay` re-issues one captured request:

- **GET/HEAD only.** Anything else is downgraded to GET, so a replay can never mutate the target.
- **Same origin.** The URL is rebuilt from the asset's origin plus the captured path; a path with
  `..` is replaced by `/`.
- **Scope re-checked** at replay time with the capture's scope (`tier=active`), so a revoked
  authorization stops replay immediately.
- **The response body is never returned** - only status, size and content type are recorded, and the
  replay is audited (`discovery.request.replayed`).

This is capture-and-replay, not a full interactive proxy: there is no in-flight interception UI and
no Caido/mitmproxy integration. That remains the one unimplemented piece of the proxy story.

## Native testing tools (fuzzing and inspection)

| adapter | tier | what it does | what it reports |
|---|---|---|---|
| `dir_probe` | active | requests 45 curated paths (backups, VCS metadata, actuator, debug consoles) | reachable sensitive paths (high), reachable paths (medium), protected paths (low) |
| `js_analyze` | passive | reads the page and up to 10 same-origin bundles | hardcoded AWS/Google/Slack/private-key/JWT patterns (masked, never stored), the API paths the bundle references |
| `jwt_analyze` | active | decodes JWTs issued in cookies, headers or bodies | `alg: none` (high), expired token issued (medium), no expiry (medium), >30-day lifetime (low) |
| `port_probe` | active | connect-only scan of 17 web/database/management ports | open redis/mongo/docker/memcached/elasticsearch (high), other database/management ports (medium), alternate web ports (informational) |

All four respect the run's rate limiter and, where a request is made, send the asset's stored testing
credentials. None of them exploit anything: they collect evidence for a human or for the PoC verifier.

## Reconnaissance and detection (second batch)

| adapter | tier | what it does | reports |
|---|---|---|---|
| `subdomain_enum` | passive | DNS-resolves 38 common names under the asset's registered domain | resolving subdomains as *out-of-scope* hosts (informational) - never sends them traffic |
| `js_libs` | passive | recognises jQuery/Bootstrap/lodash/moment versions in bundles | versions below the first fixed release, with CVE (medium/high) |
| `waf_detect` | active | one benign request, signature match on headers/cookies/body | Cloudflare, Akamai, Imperva, AWS WAF, F5, Sucuri, ModSecurity, Fastly, Front Door, generic block page |
| `dir_probe` + `wordlist` | active | `plan_params.wordlist` names a file under `SCAN_ROOT`, capped at 500 paths | same classification as the built-in 45 |

`subdomain_enum` is deliberately inert: a host outside the authorized asset is reported, not tested.

## Out-of-band verification (blind SSRF, XXE, blind XSS)

Some findings only prove themselves when the target calls back. Argus runs its own listener:

| method | path | auth | purpose |
|---|---|---|---|
| `GET` | `/api/v1/oob/{token}` | none (the token is the secret) | records the hit, returns a 1x1 GIF so `<img>` payloads still render |
| `POST` | `/api/v1/oob/{token}` | none | same, for payloads or webhooks that POST |

`oob_probe` (intrusive) issues a single-use token per probe, places
`<oob_base_url>/api/v1/oob/<token>` in parameters that commonly cause a server-side fetch (`url`,
`next`, `callback`, `redirect`, `file`, `target`, `dest`, `continue`), then watches the token table
for `OOB_WAIT_SECONDS`. A hit is recorded with the source address and user agent, and reported as a
high-severity `oob:ssrf:<param>` finding - proof the server fetched a client-controlled URL.

Configuration:

```yaml
config:
  OOB_ENABLED: "true"
  OOB_BASE_URL: "https://argus.example.com"   # must be reachable by the target
  OOB_WAIT_SECONDS: "5"
```

Operational notes:

- the listener is unauthenticated by design; put it behind the same edge rate limiting as the rest
  of the API and do not expose it on a hostname the targets cannot reach;
- tokens are random, asset-scoped and single-use in practice (a second hit only increments a counter);
- a token with no hit proves nothing: absence of a callback is not evidence of safety, so the
  adapter reports nothing rather than a false negative.
