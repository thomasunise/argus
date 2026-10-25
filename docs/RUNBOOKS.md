# Runbooks

Each runbook: symptoms, impact, diagnosis, action, verification, follow-up. Commands assume
the compose stack (`docker compose exec api ...`) or Kubernetes (`kubectl -n argus ...`);
adapt for ECS (`aws ecs execute-command` is disabled by default; use CloudWatch logs) or
Container Apps (`az containerapp logs show`). API calls need an operator or admin session or
API key (`X-API-Key`), and session calls need `X-CSRF-Token`.

Severity scale used below: S1 (security control failed or evidence integrity in doubt),
S2 (platform degraded), S3 (single feature degraded).

## Index

1. [API unavailable](#api-unavailable)
2. [Lost worker](#lost-worker)
3. [Redis down](#redis-down)
4. [Audit chain verification failure](#audit-chain-verification-failure)
5. [Revoking a compromised API key](#revoking-a-compromised-api-key)
6. [Rotating the audit signing key](#rotating-the-audit-signing-key)
7. [Rotating other secrets](#rotating-other-secrets)
8. [Disabling actions via the kill switch](#disabling-actions-via-the-kill-switch)
9. [Handling a canary hit](#handling-a-canary-hit)
10. [Rolling back an action](#rolling-back-an-action)
11. [Suspicious agent run](#suspicious-agent-run)
12. [Stopping an in-flight test run](#stopping-an-in-flight-test-run)

---

## API unavailable

**Symptoms.** `up{job="argus-api"} == 0`, load balancer health checks failing, 5xx from the edge. S2.

**Diagnosis.**

```bash
curl -s http://127.0.0.1:8080/health            # process alive?
curl -s http://127.0.0.1:8080/ready             # database reachable? returns 503 "database unavailable: <ExcType>"
docker compose logs --tail=200 api              # startup errors from assert_safe_config are explicit RuntimeErrors
```

Common causes: a config violation at startup (`SESSION_SECRET`, `ADMIN_PASSWORD`, production
requirements), database unreachable or credentials rotated, migrations failing
(`RUN_MIGRATIONS=true` runs `scripts/migrate.py` before uvicorn), disk full on SQLite volumes.

**Action.** Fix the cause and restart (`docker compose up -d api`, `kubectl rollout restart deploy/argus-api`). If a new image is the cause, roll back to the previous digest.

**Verification.** `/ready` returns 200 with `{"status":"ready"}`; the Grafana "API up" stat is 1.

---

## Lost worker

**Symptoms.** `argus_jobs_total{status="queued"}` grows while `completed` is flat
(`ArgusNoJobsCompleting`), `GET /api/v1/ops/jobs?status=running` shows jobs whose
`started_at` is older than their lease, worker logs stopped. S2 (S1 if detection or action
jobs are affected).

**How the system self-heals.** With Redis, each running job holds a lease key
(`argus:lease:<id>`, TTL `lease_seconds`, default 600). Handlers extend it with
`ctx.heartbeat()`. The reaper loop (runs in every process with the queue started, every 5 s)
requeues jobs whose lease expired with `error="lease expired; worker lost"`, up to
`max_attempts`; beyond that the job is `failed`.

**Diagnosis.**

```bash
docker compose ps worker; docker compose logs --tail=200 worker
kubectl -n argus get pods -l app.kubernetes.io/component=worker
curl -s -H "X-API-Key: $KEY" 'http://127.0.0.1:8080/api/v1/ops/jobs?status=running'
redis-cli -u "$REDIS_URL" SCARD argus:running; redis-cli -u "$REDIS_URL" LLEN argus:q:5
```

**Action.**

1. Restart or scale the worker (`docker compose up -d worker`, `kubectl scale deploy/argus-worker --replicas=2`).
2. Wait one reaper cycle plus the lease time for orphaned jobs to be reclaimed. To force a specific stuck job: `POST /api/v1/ops/jobs/{id}/cancel` (admin) and re-trigger the originating action (collector run, detection run, test plan run).
3. If the worker crash-loops on a specific job kind, check the handler error in `GET /api/v1/ops/jobs/{id}` (`error` field, truncated to 1000 chars) and the worker log; cancel the job if it is the cause.

**Verification.** `completed` rate recovers; `SCARD argus:running` matches the number of genuinely running jobs.

**Follow-up.** Idempotency is a handler requirement; if a job produced duplicate side effects after reclaim, file it against the owning package.

---

## Redis down

**Symptoms.** Worker logs `claim failed` every second, API logs connection errors on enqueue (job-creating endpoints return 500), `/ready` still 200 (it checks the database only). S2.

**Impact.** No new jobs; running jobs continue until they call `heartbeat()` and then fail. The API, reads and writes that do not enqueue keep working. Detections and collectors do not run.

**Action.**

1. Restore Redis (compose: `docker compose up -d redis`; AOF replays). Managed Redis: check failover status.
2. Workers reconnect on their next claim attempt; no restart needed. If the API's connection pool is wedged, restart the API.
3. If Redis data was lost: queued jobs are gone. Re-trigger scheduled work manually: `POST /api/v1/detections/run` per tenant, `POST /api/v1/collectors/{id}/run`, `POST /api/v1/tests/plans/{id}/run`. Test runs that were `running` stay `running` in the database; mark them manually via the database or leave them and rely on `started_at` for triage.

**Verification.** `redis-cli PING` returns PONG; a `POST /api/v1/detections/run` job reaches `completed` in `GET /api/v1/ops/jobs/{id}`.

**Prevention.** `appendonly yes`, `noeviction`, replication (ElastiCache Multi-AZ, Azure Standard+), `REDIS_URL` with TLS.

---

## Audit chain verification failure

**Symptoms.** `GET /api/v1/audit/verify` returns `{"valid": false, "checked": N, "broken_at": <id>, "reason": "signature"?}`. Check it on a schedule (there is no metric for it; a cron job calling the endpoint with a read-only API key is enough). S1: treat as potential tampering until explained.

**What it means.** Entry `broken_at` either does not link to its predecessor (`previous_hash` mismatch), its content hash does not recompute (a column was edited), or (with `reason: signature`) the HMAC does not match the current `AUDIT_SIGNING_KEY`.

**Diagnosis.**

1. Was the signing key rotated without following the rotation runbook? A `signature` failure on every entry up to a point in time means the key changed; see below.
2. Was the database restored from a backup, migrated, or edited? (`backup_records` and `ops.backup.*` audit entries show
   recent backups; `docs/BACKUP.md` has the restore procedure.) Compare the entry with the mirror:
   - JSONL: `grep '"id": <broken_at>' /app/data/audit.jsonl`
   - S3: `aws s3 cp s3://<bucket>/argus-audit/<tenant>/<id padded to 12>.json -`
   - Azure: `az storage blob download --container-name argus-audit --name <tenant>/<id>.json`
   The mirror record carries `entry_hash`, `previous_hash`, `signature` and the detail text as written at the time.
3. Check the database audit logs (RDS `postgresql` log export, Azure diagnostic logs) for writes to the `audit` table from anything other than the application role.

**Action.**

- Declare a security incident. Preserve the database snapshot and the mirror as evidence.
- Do not "repair" the chain in place. The mirror is the authoritative record from the break point onward; export both and reconcile offline.
- If the explanation is benign (restore from a backup older than the mirror), document it, and accept that verification will report the break from that id; subsequent entries chain correctly from the restored state.

**Verification.** For a benign cause, document the `broken_at` id; later runs must report the same id and no new breaks.

---

## Revoking a compromised API key

**Symptoms.** A key appeared in a repository, log, ticket or public paste; unexpected `last_used_at`; ingest from an unknown source. S1.

**Action.**

1. Identify the key by prefix: the plaintext is `argus_<8 hex prefix>_<body>`; `GET /api/v1/auth/api-keys` lists `prefix`, `name`, `role`, `scopes`, `last_used_at`.
2. Revoke: `DELETE /api/v1/auth/api-keys/{key_id}` (admin, `admin:api_keys`). Revocation is immediate: `_principal_from_api_key` ignores rows with `revoked_at` set. The audit entry `auth.api_key_revoked` is recorded.
3. If the compromised key is the bootstrap `INGEST_API_KEY`: revoke it as above and also remove or change `INGEST_API_KEY` in the environment, because `bootstrap()` re-creates a key for that value on the next start if its hash is absent.
4. Issue a replacement with the least role and scopes (`POST /api/v1/auth/api-keys` with `{"name": ..., "role": "viewer", "scopes": ["ingest"]}`) and deliver it out of band.
5. Review what the key did: `GET /api/v1/audit?actor=api_key:<id>` and events with the key's source during the exposure window. Look for new assets, authorizations, scopes, action requests.

**Verification.** A request with the old key returns 401 `Invalid API key`.

---

## Rotating the audit signing key

**Background.** `AUDIT_SIGNING_KEY` is an HMAC key over `entry_hash`, stored per entry in
`signature`. `verify_chain` checks every entry against the *current* key, so a naive rotation
makes every historical entry fail with `reason: signature`.

**Procedure.**

1. Run `verify_chain` for every tenant and record the result (`checked` count, `valid: true`). Export the chain head (`id`, `entry_hash`) per tenant and store it with the change ticket. This is your attestation that the chain was intact under the old key.
2. Record an audit entry announcing the rotation while the old key is active, e.g. via any audited admin action with a descriptive detail, or directly: `record_audit(db, 'system', 'audit.signing_key_rotated', tenant_id, {'chain_head': <entry_hash>, 'checked': N})`.
3. Change `AUDIT_SIGNING_KEY` in the secret store and restart API and workers (`audit.configure()` reads it at app creation).
4. Expect `verify_chain` to report `valid: false, reason: signature, broken_at: <first id after rotation - 1>` for the pre-rotation segment. The hash linkage itself (`previous_hash`, `entry_hash`) still verifies; only the HMAC segment changes. Keep the old key in the secret store (versioned) so an auditor can re-verify the historical segment with it.
5. Document the rotation id boundary in your compliance evidence.

A code change that stores a key id per entry and verifies segments with the matching key is on the roadmap; until then, rotate rarely and keep old keys.

---

## Rotating other secrets

| Secret | Effect of rotation | Procedure |
|---|---|---|
| `SESSION_SECRET` | All sessions invalidated | Change, restart API. Users log in again. |
| `ADMIN_PASSWORD` | Bootstrap owner password reset on next start (`bootstrap()`) | Change, restart API; prefer OIDC for humans and keep this account for recovery. |
| `OIDC_CLIENT_SECRET` | New logins use the new secret | Rotate at the IdP, change, restart API. |
| Model provider keys | Next agent run uses the new key | Change, restart workers (and API when in-process). |
| Collector / executor secrets | Resolved per run via `secret_ref` | Rotate at the source (env, file, secret manager); no restart when using `file:` or `secrets:` refs. |
| `DATABASE_URL` / `REDIS_URL` passwords | Connections fail until updated | Rotate at the store, update the secret, restart API and workers in that order. |

---

## Disabling actions via the kill switch

**When.** Any doubt about the action broker, its policy, an executor credential, or an ongoing incident where automated change is unsafe. S1 response step; cheap to apply, cheap to undo.

**Global (all tenants).** Set `ACTIONS_KILL_SWITCH=true` in the environment of the API *and* every worker, then restart them (settings are read at process start):

```bash
# compose
sed -i 's/^ACTIONS_KILL_SWITCH=.*/ACTIONS_KILL_SWITCH=true/' .env && docker compose up -d api worker
# kubernetes
kubectl -n argus set env deploy/argus-api deploy/argus-worker ACTIONS_KILL_SWITCH=true
# ECS: update the task definition environment and force a new deployment; Container Apps: az containerapp update --set-env-vars ACTIONS_KILL_SWITCH=true
```

**Per tenant (no restart).** `POST /api/v1/actions/kill-switch` with `{"enabled": true, "reason": "..."}` (`actions:kill_switch`, admin or owner). It sets `actions_enabled=false` on the tenant, records who engaged it and why in the tenant settings, writes the audit entry `actions.kill_switch`, and publishes `action.kill_switch` on the event bus (outbound channels can notify). `PATCH /api/v1/admin/tenants/{id}` with `{"actions_enabled": false}` has the same effect.

**Effect.** `request()` and the `actions.execute` handler reject with `policy_denied`; the handler re-checks the switch at execution time, so jobs already queued do not run. Pending approvals stay pending. Agents can still call `propose_action`; the broker rejects it and the agent is told so.

**Verification.** `GET /api/v1/actions/kill-switch` returns `{"global": ..., "tenant_engaged": true, "effective": true, "detail": {...}}`; a test request returns 403 `policy_denied`; the audit log shows `actions.kill_switch`.

**Undo.** `POST /api/v1/actions/kill-switch {"enabled": false}` for the tenant, or reverse the environment variable and restart for the global switch. Review pending requests before re-enabling.

---

## Handling a canary hit

**Symptoms.** `argus_detections_total{rule="canary.tripwire"}` increments
(`ArgusCanaryTripped` alert, critical), a `Detection` with `entity_kind=canary`, a `Finding`
from source `detections`, and `CanaryHit` rows under `GET /api/v1/canaries/{id}/hits`. S1:
a canary is used only by someone who found it where it was planted.

**Immediately.**

1. Read the hit: `source_ip`, `user_agent`, bounded headers and payload (auth headers are dropped on ingestion). Note `received_at` versus the canary's `placement` text, which tells you where it was planted (host, repo, document, bucket).
2. Treat the placement location as compromised. For credential-style canaries (`aws_key`, `credential`, `api_key`) the attacker has read a file or secret store at that location; for `url`, `file`, `document` kinds, a document was opened; for `dns`, a hostname was resolved (exfiltration or scanning).
3. Open an investigation on the finding (`POST /api/v1/findings/{id}/investigate`, or `POST /api/v1/agents/run` with spec `investigate` and the finding id). The agent correlates events for the same source IP and actor; it cannot act.
4. Contain through the action broker if an approved action fits (for example revoking the real credentials that were co-located with the canary); otherwise act manually and record it in the audit log.

**Then.**

- Revoke the tripped canary (`DELETE /api/v1/canaries/{id}`) and plant a new one in the remediated location.
- Check for related hits: other canaries with the same `source_ip`, events from the same actor within the hour (`GET /api/v1/events?actor=...`).
- Record the outcome on the detection: `PATCH /api/v1/detections/{id}` with `status` and a note.

**False positives.** Your own scanners, backup verification or DLP tools can trip file and URL canaries. Confirm the source IP against known tooling before escalating, then add the tooling's identity to the rule parameters where supported or exclude the placement from the scanner.

---

## Rolling back an action

**When.** An executed action (`ActionRun` with `status=succeeded`) had an unintended effect, or an approver asks for reversal. Only actions whose type declares `reversible=true` carry a rollback payload; irreversible actions require `risk>='high'` by contract and must be undone manually.

**Procedure.**

1. Find the run: `GET /api/v1/actions/runs?request_id=...` or from the finding's timeline. Read `summary`, `blast_radius` from the dry run, and `rollback_payload` presence.
2. Roll back: `POST /api/v1/actions/runs/{run_id}/rollback` (`actions:rollback`, operator+). This enqueues `actions.rollback`; the broker calls the action type's `rollback(rollback_payload)` and writes a new `ActionRun` linked to the original, with audit entries `actions.rollback_requested` and `actions.rolled_back` (or `actions.rollback_failed`).
3. If rollback fails, the run records the error; the estate may be partially reverted. Follow the action type's manual reversal notes (`GET /api/v1/actions/catalog` includes the description) and record the manual steps in the audit log through an admin action.
4. If the action should never have executed, apply the kill switch (above) while you review policy settings (`ACTIONS_AUTO_APPROVE_LOW`, thresholds, maintenance window) and the approvals on the request.

**Verification.** The original run shows `rolled_back`; `argus_actions_total{status="rolled_back"}` increments; the target resource is in its previous state (verify out of band, Argus does not re-inspect automatically unless a collector runs).

---

## Suspicious agent run

**Symptoms.** An agent run produced a result that quotes instructions from evidence, proposed an action unrelated to its task, exhausted its budget repeatedly, or its steps show tool arguments that look attacker-chosen. S2 (S1 if an action was proposed and approved).

**Action.**

1. `GET /api/v1/agents/runs/{id}` returns the run and its steps: each step has the tool name, arguments, truncated result, tokens and latency. Identify the step whose `<untrusted_data>` content contains the injected text.
2. Cancel if still running: `POST /api/v1/agents/runs/{id}/cancel`.
3. Check for proposals: `GET /api/v1/actions/requests?agent_run_id=...`. Reject pending ones; if executed, follow the rollback runbook.
4. Add the evidence as a case to `app/agents/evals/suites/prompt_injection.json` and run the suite (`POST /api/v1/evals/run {"suite": "prompt_injection"}`) so the regression is covered.
5. Consider lowering `AGENT_MAX_STEPS` or restricting the specialist's tool list until the eval passes.

---

## Stopping an in-flight test run

**When.** A target owner reports impact, a scope was granted in error, or a tool misbehaves.

**Action.**

1. Revoke the scope: `POST /api/v1/tests/scopes/{id}/revoke`. The harness re-checks scope at execution and at adapter boundaries; new runs are denied immediately.
2. Cancel the job: find it in `GET /api/v1/tests/runs/{id}` (`job_id`) and call `POST /api/v1/ops/jobs/{job_id}/cancel`. The next `heartbeat()` raises `CancelledError`; external tools are killed by `run_tool` on timeout or when the task is cancelled.
3. If the tool process keeps running in the worker, restart the worker; `run_tool` processes are children of the worker and die with it.
4. Record the incident and, if an authorization was wrong, revoke it: `POST /api/v1/assets/{id}/revoke-authorization` (`assets:authorize`).

**Verification.** The run is `denied` or `cancelled`; no new `TestRun` rows appear for the scope.
