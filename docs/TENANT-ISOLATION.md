# PostgreSQL tenant RLS: deployment requirements

The November 3, 2026 RLS migration replaces the earlier fail-open predicates
with fail-closed read AND write policies. It applies to all tenant-owned tables
except bootstrap identity tables (api_keys, memberships, oidc_identities), which
must be accessible before authentication has established a tenant.

## Required: separate migration and runtime roles

PostgreSQL table owners, superusers and BYPASSRLS users can bypass ordinary row
security. ARGUS production now refuses to start with such credentials, or when
tenant tables do not have RLS enabled. A runtime account must not inherit an
owner role. The API, background workers and webhooks must use only that account.

Run migrations using a dedicated privileged migration/schema-owner connection:

    ALEMBIC_DATABASE_URL="postgresql+psycopg://MIGRATION_OWNER:...@HOST/argus" python scripts/migrate.py

As a PostgreSQL administrator, provision the restricted account (use a secret
manager; these are example SQL statements, not production credentials):

    CREATE ROLE argus_runtime LOGIN NOINHERIT PASSWORD 'REPLACE_WITH_RANDOM_SECRET';
    GRANT CONNECT ON DATABASE argus TO argus_runtime;
    GRANT USAGE ON SCHEMA public TO argus_runtime;
    GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO argus_runtime;
    GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO argus_runtime;

Grant future tables/sequences from the schema owner with ALTER DEFAULT
PRIVILEGES FOR ROLE MIGRATION_OWNER IN SCHEMA public GRANT ...; use only the
minimum privileges the application requires. Verify the account does not own
tables and cannot SET ROLE to an owner/BYPASSRLS role.

Provide ARGUS_DATABASE_URL pointing to argus_runtime for the production Compose
overlay (and DATABASE_URL on Kubernetes and other deployments); set
RUN_MIGRATIONS=false and DB_AUTO_CREATE=false for both API and workers.
The previous owner-role DATABASE_URL is NOT acceptable in production.

## Important

- SET LOCAL app.tenant_id is intentionally scoped to each transaction.
  Authenticated requests bind their tenant after auth; worker sessions inherit
  their queue job's tenant. Every subsequent transaction reapplies the context.
- Missing or empty context results in zero tenant rows and denied tenant writes.
  PostgreSQL's normal owner/superuser exceptions still apply to maintenance.
- Cross-tenant schedulers must first enumerate IDs from tenants, then open a
  tenant-bound session for each tenant. They must never query tenant tables
  without a context.
- BACKUP_ENABLED defaults to false in the production Compose overlay because
  full-instance backups require a separate privileged maintenance connection.
  Run pg_dump with an independently secured backup account and drill restores.
- This is defense in depth against unscoped application queries, not a guarantee
  against arbitrary SQL execution. A compromised app credential capable of
  issuing SQL can manipulate custom PostgreSQL session settings. Prevent SQL
  injection, restrict DB privileges, and isolate privileged maintenance access.
- SQLite development/tests do not enforce PostgreSQL RLS. Validate the
  non-owner PostgreSQL test and conduct a staging migration/rollback drill.
- This migration intentionally refuses downgrade to the unsafe fail-open policy.

Public canary, OOB, verified webhooks and Slack callbacks first resolve a high-entropy token to a tenant
through three read-only migration-owned SECURITY DEFINER functions. The functions
return only a tenant ID, never protected records. The application then sets the
transaction's tenant and performs all further work under RLS. Restrict database
access to these functions and review them before changing callback formats.

The in-app production PostgreSQL backup path intentionally refuses to create a
snapshot with a restricted runtime account: RLS would silently omit rows for
other tenants. Use a separate privileged pg_dump/restore workflow instead.
