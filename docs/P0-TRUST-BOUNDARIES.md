# P0 trust-boundary deployment and verification

This hardening is intentionally **fail closed**. Existing installations must complete
the database and scanner changes before moving to production. Do not represent static
manifest tests as evidence that a real Kubernetes sandbox cannot escape.

## 1. PostgreSQL: privileged migration user vs. restricted runtime

The table-owning migration account must not be used as the running application's
DATABASE_URL. PostgreSQL table owners and BYPASSRLS roles can bypass row-level
security. Runtime startup now refuses such a role.

1. Run the new `b2c3d4e5f607` migration as the migration owner. The default
   Compose stack runs a one-shot `migrate` service before starting the API.
2. Create a dedicated runtime role as the database administrator. Example SQL
   (replace the placeholder password in a secure terminal; do not commit it):

   ```sql
   CREATE ROLE argus_runtime LOGIN PASSWORD 'CHANGE_TO_LONG_RANDOM_VALUE';
   GRANT CONNECT ON DATABASE argus TO argus_runtime;
   GRANT USAGE ON SCHEMA public TO argus_runtime;
   GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO argus_runtime;
   GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO argus_runtime;
   ALTER DEFAULT PRIVILEGES FOR ROLE argus IN SCHEMA public
     GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO argus_runtime;
   ALTER DEFAULT PRIVILEGES FOR ROLE argus IN SCHEMA public
     GRANT USAGE, SELECT ON SEQUENCES TO argus_runtime;
   ```
3. Set `ARGUS_DATABASE_URL` in the Compose environment to a URL with
   `argus_runtime` credentials. Never set `ARGUS_DATABASE_URL` to the
   table owner. The API/worker/scanner connect using this role.
4. Keep `POSTGRES_PASSWORD` accessible only to the PostgreSQL database
   container and the one-shot migration process. The production Compose
   overlay explicitly clears the base `env_file` from runtime containers.
5. Test a direct SELECT with the runtime database role before and after
   `SET LOCAL app.tenant_id`. With the setting absent or empty, tenant tables
   must return zero rows and reject inserts. Confirm separate tenant IDs
   cannot read one another's data. The PostgreSQL-specific regression test
   creates a temporary non-owner role for these checks.

The RLS setting is **defense in depth**, not protection against arbitrary SQL
execution using the runtime role: anyone able to execute arbitrary SQL could
potentially set the custom GUC. Use parameterized queries, least privilege,
no raw SQL based on untrusted inputs, and independent database review.

## 2. Production exploit authorization

A free-form string such as `ROE-2026-01` no longer authorizes exploit
execution. Production requires an HMAC-signed, asset- and tenant-bound token,
containing the approved document SHA-256 and expiration timestamp.

An independent engagement authority signs an approved ROE file offline:

```bash
EXPLOIT_ROE_SIGNING_KEY='your-strong-independent-key' \
python scripts/sign_production_roe.py \
  --tenant-id TENANT_UUID --asset-id ASSET_UUID \
  --target https://authorized.example.com \
  --document ./signed-rules-of-engagement.pdf \
  --expires-epoch 1835568000
```

Set `EXPLOIT_ROE_SIGNING_KEY` in the production app secret manager. Store
the returned token in *both* the asset authorization's `scope_document_ref`
and the test scope's `signed_document_ref`. ARGUS verifies the HMAC and
the exact asset, tenant, target and expiration at authorization and execution.

**Important:** An HMAC token attests that the key-holder approved the
document hash; it does not prove the document's legal validity, actual
signature, or the identity/authority of the signer. Keep this key outside
ordinary operator access, and consider an asymmetric signer+KMS and
external engagement approval for high-trust deployments.

## 3. Scanner workers

In production `WORKERS_INPROCESS=false` is mandatory. Jobs of kind
`testing.run` are placed on `argus:scan:q:<priority>`, not on the general
queue. Only a worker with `WORKER_ROLE=scanner` consumes them. Compose
runs the scanner in a separate container with an independent network,
without the API's env file or cloud-action credentials, and with a
read-only filesystem, capability drop and memory/CPU limits.

**This is process/container separation, not disposable per-test isolation.**
A compromised scanner can still reach permitted services on its network.
Restrict scanner egress at the host, firewall, or Kubernetes NetworkPolicy
to authorized target CIDRs; isolate its DB privileges further if possible,
and run real containment tests before enabling untrusted tools.
If a scanner worker is not deployed, scan jobs will remain queued rather
than run on the general worker. The existing scanner image also may lack
optional third-party binaries; install vetted, pinned tools separately.

## 4. Exploit sandbox executor

Set `SANDBOX_POC_IMAGES` to an explicit comma-separated digest-pinned
allowlist, and `SANDBOX_ENGINE_IMAGES` similarly for engines. Empty
allowlists fail closed. Never enable `SANDBOX_ALLOW_INSECURE_RUNTIME` in
production. Ensure gVisor is actually installed as the `gvisor`
RuntimeClass, NetworkPolicy is enforced by the cluster CNI, namespace
RBAC limits the executor, admission policies prevent sidecar injection,
and resource quotas/PID limits are applied by the cluster.

The executor rejects host/secret/projected volumes, root containers,
unmasked procfs, custom host routing, extra containers, unlimited CPU
or memory, repeated jobs, arbitrary commands, nonallowlisted images,
and malformed or broad outbound CIDRs. Unit tests verify manifest policy,
not enforcement by a live CNI or container runtime.

## 5. Fail-closed change policy and validation

Malformed maintenance windows now deny high/critical actions rather
than disabling the window requirement. Review existing tenant policy
settings for malformed windows before upgrading.

Run:

```bash
python -m pytest tests/test_p0_trust_boundaries.py \
  tests/test_exploit_executor.py tests/test_exploit_strix.py \
  tests/test_exploit_api.py tests/test_actions.py -q
```

In production-like staging also test concurrent requests, role switching,
worker restarts, stale approvals, expired ROE, sandbox pod admission and
network egress, scanner cancellation, and at least one real rollback.
Never enable autonomous testing against an asset without fresh explicit
authorization.
