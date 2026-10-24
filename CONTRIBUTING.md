# Contributing

Thanks for contributing to Argus. The codebase is a set of packages, each with a small,
documented interface; the contract between them is `docs/ARCHITECTURE.md`. This file
summarizes what a change must satisfy to be merged.

## Setup

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
cp .env.example .env && python scripts/generate_secrets.py --write
python -m pytest -q
```

Set `ARGUS_LAZY_APP=1` when importing `app.main` outside tests (the conftest does it).
Tests run against a fresh SQLite database per test with the in-memory queue and must never
touch the network (`respx` for httpx, `monkeypatch` for SDKs).

## Package layout

Where things live. Each package keeps its models, router and tests in the files listed
here, so a change to one feature normally touches one row of this table.

| Package | Files |
|---|---|
| core | `app/core/`, `app/main.py`, `app/worker.py`, `app/models/{base,identity,inventory,findings,audit,agents}.py`, `app/api/{deps,auth,ops}.py`, `app/agents/{runtime,providers}.py`, `app/agents/tools/registry.py` |
| graph | `app/graph/`, `app/models/graph.py`, `app/api/graph.py` |
| detections | `app/detections/`, `app/models/detections.py`, `app/api/{detections,canaries}.py` |
| collectors | `app/collectors/`, `app/models/collectors.py`, `app/api/collectors.py` |
| testing | `app/testing/`, `app/models/testing.py`, `app/api/{tests,scans}.py` |
| agents | `app/agents/{tools,specialists,evals}/`, `app/api/{agents,evals}.py` |
| actions | `app/actions/`, `app/models/actions.py`, `app/api/actions.py` |
| integrations | `app/integrations/`, `app/models/integrations.py`, `app/api/{integrations,ingest}.py` |
| core-api | `app/api/{admin,assets,findings,events,investigations,approvals,audit,reports}.py` |
| frontend | `app/static/` |
| infra | `Dockerfile*`, `compose*.yaml`, `docker/`, `infra/`, `.github/`, `scripts/`, `docs/` (except `ARCHITECTURE.md`), `README.md` |

Keep a change inside the package it belongs to. If you need something from another package
that does not exist, add a small helper inside your package and say so in the pull request
description. Do not reformat or "tidy" unrelated files in the same change.

## Code conventions (enforced in review)

- Python 3.11+, `from __future__ import annotations`, type hints, no `print` (use `logging.getLogger('argus.<pkg>')`).
- Packages expose `setup(app)` in `__init__.py` for queue handlers, tools, subscribers and startup hooks. Routers are `APIRouter(prefix='/api/v1/<name>', tags=['<name>'])` exporting `router`; discovery is automatic.
- Every endpoint depends on `Principal` via `require('<perm>')` with a permission string from `app/core/rbac.py`. Lists use `Page` and return `{items, next_cursor}`.
- Every domain table uses `TenantMixin`; every query uses `scoped()` / `get_scoped()`; objects are fetched by `(id, tenant_id)`.
- Every state change calls `record_audit(db, principal, '<pkg>.<verb>', subject_id, {...})`.
- Background work is a queue handler `(job, ctx)`: idempotent, uses `ctx.db_factory` with `session_scope`, calls `await ctx.heartbeat()` in loops, and re-checks authorization itself.
- Findings and events are created only via `core.findings.upsert_finding` / `upsert_event`.
- Secrets: never logged, never in evidence or model context; resolve with `resolve_secret(ref, settings)`; pass free text through `redact()`.
- External processes: fixed argv through `testing.harness.run_tool` or `asyncio.create_subprocess_exec`, never a shell; always a timeout.
- Heavy SDKs are imported lazily inside functions and listed in `requirements-optional.txt`.
- JSON columns are `Text` written with `models.base.dumps` and read with `loads`.

## Tests

- One file per package: `tests/test_<pkg>*.py`, using the fixtures in `tests/conftest.py` (`owner`, `second_tenant`, `api_key`, `ingest_key`, `db`, `make_user`, `wait_job`, `wait_for`).
- Every list and get endpoint has a cross-tenant test using `second_tenant` expecting 404 or an empty list.
- Permission tests: at least one request from a role that lacks the permission expects 403.
- Fixtures for external tools and collectors live under `tests/fixtures/` as recorded output; adapters are tested by parsing fixtures, not by running tools.
- Run your package tests plus `tests/test_core_*.py` before opening a pull request.

## Infrastructure and docs changes

- Validate YAML with `python -c "import yaml,sys; yaml.safe_load(open(sys.argv[1]))" <file>`; Terraform with `terraform fmt -check -recursive`; Helm with `helm lint` and `helm template` when available.
- Keep `.env.example` in sync with `app/core/config.py`: every setting, grouped, commented, safe default.
- Keep `docs/API.md` in sync with routers and `docs/ROADMAP.md` with what is actually implemented.
- Documentation states what the code does, with file references. No marketing language, no claims of certification.
- Never commit `.env`, databases, keys or real telemetry. Example payloads must be synthetic and say so.

## Pull requests

- Branch from `main`; keep each pull request to one change.
- Tests pass locally (`python -m pytest -q`), including the cross-tenant and permission tests for any endpoint you add.
- The description says what is real versus stubbed (for example an adapter tested only against fixtures, or a provider without a live integration test) and lists any endpoints or public interfaces added.
- No secrets, databases, `.env` files or real telemetry in the diff.
- Commit messages: imperative subject, body explaining why.

## Security issues

Do not open public issues for vulnerabilities. See `docs/SECURITY.md`.
