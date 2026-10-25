# Backups, restore and data retention

Argus backs up its whole database on a schedule, encrypts every backup, keeps copies in up to three places,
restores into an empty database with a single command, and proves each restore by checking row counts and every
tenant's audit chain. Retention prunes old high-volume data per tenant so the database (and the disk under it)
stays a predictable size.

## Turning it on

| Setting | Default | Meaning |
|---|---|---|
| `BACKUP_ENABLED` | `false` (`true` in `compose.prod.yaml` and `compose.coolify.yaml`) | scheduled backups |
| `BACKUP_INTERVAL_HOURS` | `24` | time between scheduled backups |
| `BACKUP_KEEP` | `7` | newest backups kept in every store; older ones are deleted |
| `BACKUP_DIR` | `./data/backups` | local copies, and the staging area for uploads |
| `BACKUP_ENCRYPTION_KEY` | empty | key for backup files; empty uses a key derived from `DATA_ENCRYPTION_KEY` |
| `BACKUP_MIN_FREE_MB` | `1024` | a backup refuses to start with less free disk than this |
| `BACKUP_S3_BUCKET`, `BACKUP_S3_PREFIX` | empty, `argus-backups/` | copy every backup to S3 or S3-compatible storage (`AWS_ENDPOINT_URL_S3`) |
| `BACKUP_AZURE_CONTAINER`, `BACKUP_AZURE_CONNECTION_STRING` | empty | copy every backup to Azure Blob Storage |
| `RETENTION_ENABLED` | `false` (`true` in the production compose files) | nightly pruning |

S3 and Azure need `boto3` / `azure-storage-blob`: build with `ARGUS_EXTRAS=1` or use the `-extras` image.

**Keep the keys somewhere other than the server.** A backup is useless without `BACKUP_ENCRYPTION_KEY` (or, when
that is empty, `DATA_ENCRYPTION_KEY`). The restored database also needs the same `DATA_ENCRYPTION_KEY(S)` to read
stored credentials and TOTP seeds, and the same `AUDIT_SIGNING_KEY(S)` to verify the audit chain. Store all three
in a password manager or secret manager that does not live on the Argus host.

A local-only backup protects against mistakes and bad upgrades, not against losing the server. Add an S3 bucket
(Hetzner Object Storage, Backblaze B2, AWS, MinIO) or an Azure container for that.

## What a backup contains

Every table in the database, every tenant, taken as one consistent snapshot (a read-only `REPEATABLE READ`
transaction on PostgreSQL, the SQLite online backup API in development), plus the Alembic revision it was taken
at. Encrypted columns stay encrypted inside the backup. Job state in Redis is not included: queued jobs are
transient and are re-created by the schedulers.

The file (`argus-<UTC time>Z-<random>.argus-backup`) is gzip-compressed JSON lines, split into 1 MiB frames and
encrypted with AES-256-GCM using the STREAM construction: every frame is authenticated with its position and a
final-frame flag, and the header is bound to every frame. A modified, reordered, truncated or partially written
file fails verification rather than restoring part of the data. A `<name>.json` manifest beside it records size,
SHA-256 and row counts, so you can pick and check a backup without the database it came from.

## Running and checking backups

```bash
python -m app.ops backup create            # back up now, copy to every store, prune
python -m app.ops backup list              # backups in every store, newest first
python -m app.ops backup verify NAME       # decrypt and count everything without restoring
python -m app.ops backup prune             # apply BACKUP_KEEP now
```

In Docker: `docker compose exec worker python -m app.ops backup list`. In Coolify, run the same command in the
worker container's terminal.

Over the API (platform owner only, meaning an owner of the bootstrap tenant, because a backup holds every tenant):

| Route | Purpose |
|---|---|
| `GET /api/v1/ops/backups` | configuration, last successful backup, history with size, SHA-256, rows, stores, errors |
| `POST /api/v1/ops/backups` | start a backup now (`backup.run` job) |

Each run is recorded in `backup_records` and audited as `ops.backup.completed` or `ops.backup.failed`. A
backup whose upload fails is recorded as failed even though the local copy exists, so a broken off-host copy is
never silent. Alert on `last_success_at` being older than about twice `BACKUP_INTERVAL_HOURS`.

## Restoring

Restore is a command-line operation and is not available over HTTP. It only writes into an **empty** database.

1. Stop the API and worker (`docker compose stop api worker`, or scale both to 0).
2. Create an empty database: `DROP DATABASE argus; CREATE DATABASE argus OWNER argus;` or a new database next to
   the old one, which is safer: you can switch `DATABASE_URL` once the restore checks out.
3. Make sure the environment has the same `DATA_ENCRYPTION_KEY(S)`, `AUDIT_SIGNING_KEY(S)` and
   `BACKUP_ENCRYPTION_KEY` as the server that took the backup.
4. Restore:

   ```bash
   python -m app.ops backup restore argus-20261025T020000000000Z-1a2b3c.argus-backup \
       --target-url postgresql+psycopg://argus:...@postgres:5432/argus
   ```

   A name is looked up in every store (and downloaded from S3 / Azure when needed); a path is used as is.
   `--key` supplies the backup key when it is not in the environment.
5. Start the stack. The output's `checks` must show `"ok": true`; the command exits non-zero otherwise.

What restore does, in order: authenticates the entire file before touching the target; refuses a non-empty
target; recreates the schema at the backup's Alembic revision; loads every row in one transaction; resets
PostgreSQL sequences past the restored ids; runs `alembic upgrade head`, so a backup from an older release
restores onto the current schema; then compares row counts with the backup and verifies every tenant's audit
chain (hash links and HMAC signatures).

CI runs this drill on every push against a real PostgreSQL server (`test_postgres_backup_and_restore_drill`):
migrate, fill through the API, back up, restore into a second database, sign in, write, verify the audit chain.
Run your own restore drill into a scratch database at least quarterly.

## Data retention

A nightly job prunes each active tenant's data past its retention period, 500 rows per transaction.

| Policy | Default (days) | What is deleted |
|---|---|---|
| `events_days` | 90 | security events, by received time |
| `detections_days` | 365 | resolved and false-positive detections, by last seen; open ones are kept |
| `agent_runs_days` | 90 | finished agent runs and their steps |
| `runs_days` | 180 | finished detection, collector, simulation, autopilot and eval runs |
| `deliveries_days` | 30 | sent, failed or skipped outbound deliveries; queued ones are kept |
| `ingest_batches_days` | 30 | ingest batch records |
| `ai_gateway_days` | 90 | AI gateway request log |
| `canary_hits_days` | 365 | canary hits |

`0` keeps data forever. Never pruned: the audit log (it is a hash chain; the external audit sink is the long-term
record), findings, assets, authorizations, scopes, action requests and runs, and configuration.

Server defaults come from `RETENTION_*_DAYS`. Each tenant can see and change its own policy:

| Route | Purpose |
|---|---|
| `GET /api/v1/retention` (`admin:settings`) | effective policy, server defaults, overrides, rows due now, last run |
| `PUT /api/v1/retention` `{overrides: {events_days: 30, agent_runs_days: null}}` | set (0 to 3650) or remove (`null`) overrides |
| `POST /api/v1/retention/run` | prune now (`retention.run` job) |

From the command line: `python -m app.ops retention preview [--tenant SLUG]` and
`python -m app.ops retention run [--tenant SLUG]`. Every run that deletes rows is audited as `retention.pruned`
with per-table counts, and policy changes as `retention.policy_updated`.

Deleted rows free space inside PostgreSQL for reuse (autovacuum). To return space to the operating system after a
large first prune, run `VACUUM FULL` on the affected tables during a maintenance window.

## Scheduling details

The API process runs a scheduler that checks every 10 minutes. A backup is due when no backup completed within
`BACKUP_INTERVAL_HOURS` and none is running; a retention run is due for a tenant 24 hours after its last run. Jobs
carry idempotency keys, so several API replicas never start the same run twice. The jobs themselves run on the
worker, which needs `BACKUP_DIR` on a volume it can write to (`argus-data` in the compose files).

For very large databases (hundreds of GB), pair this with your database platform's own physical backups and
point-in-time recovery (RDS, Azure Flexible Server, or `pg_basebackup` with WAL archiving). Logical backups stay
useful there for portable, verifiable copies and for restoring into a different environment.
