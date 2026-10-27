# Authenticated testing

Most real applications sit behind a login. Without credentials, discovery finds a login page and
the fuzzers test an unauthenticated surface - so Argus stores per-asset testing credentials and
injects them into the requests its adapters make.

## Storage

Credentials live in `asset_credentials` with the `EncryptedText` column type, so the database holds
ciphertext (`enc:v1:<kid>:...`, AES-256-GCM from `DATA_ENCRYPTION_KEY(S)`). The ORM decrypts
transparently for one run. Nothing serialises the secret: the API returns metadata only, and audit
records carry the id, kind and name.

| kind | `name` | `secret` | header sent |
|---|---|---|---|
| `header` | header name | header value | `<name>: <secret>` |
| `bearer` | ignored | token | `Authorization: Bearer <secret>` |
| `basic` | username | password | `Authorization: Basic base64(user:pass)` |
| `cookie` | ignored | cookie string | `Cookie: <secret>` |

## API

| method | path | permission | purpose |
|---|---|---|---|
| `POST` | `/api/v1/assets/{id}/credentials` | `assets:authorize` | add a credential (`kind`, `name`, `value`) |
| `GET` | `/api/v1/assets/{id}/credentials` | `assets:read` | list metadata (never secrets) |
| `DELETE` | `/api/v1/assets/{id}/credentials/{cid}` | `assets:authorize` | revoke (row kept for the audit trail) |

## Where they are injected

`harness.execute_run` loads the asset's live credentials into the run's `HarnessContext`
(`auth_headers`) and only for that run. Today these adapters send them:

- `param_probe` - reflected-parameter discovery runs authenticated;
- `payload_fuzz` - intrusive payloads run authenticated, so a logged-in-only endpoint is actually
  tested instead of redirecting to the login page.

The scope gate is unchanged: a credential does not widen what you may test, it only lets an
authorized test reach the same asset in an authenticated state.

## Not yet wired (honest list)

- **Engine jobs** (Strix, browser, recon) take credentials only through their own image
  configuration; the tenant's stored credentials are not injected into those containers yet.
- **ZAP/nuclei** use their own authentication configuration (`ZAP_*`, nuclei templates); the stored
  credentials are not passed to them.
- No rotation schedule or expiry: revoke and re-add. `expires_at` on credentials is a follow-up.

## Operational notes

- Credentials are per tenant and per asset; cross-tenant access is impossible through the scoped
  queries.
- A revoked credential stops being injected immediately (the loader filters `revoked_at IS NULL`).
- Do not reuse a human's SSO session as a test credential; create a dedicated test account so
  revocation is unambiguous and audit trails stay readable.
