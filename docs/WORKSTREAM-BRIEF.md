# Workstream brief (read before writing code)

You are building one package of Sentinel, an enterprise agentic security operations
platform. The blueprint is `docs/ARCHITECTURE.md`; read it in full first. The foundation
(core, models, auth, queue, agent runtime) is already built and tested. Build on it; do not
rewrite it.

## Environment

- Repo: `C:\Users\thoma\OneDrive\Desktop\sentinel-agentic-security` (Windows, Git Bash and PowerShell both available).
- Python: `D:\venvs\sentinel\Scripts\python.exe` (all requirements installed). Run tests with
  `D:/venvs/sentinel/Scripts/python.exe -m pytest -q tests/test_<yours>*.py`.
- Set `SENTINEL_LAZY_APP=1` in the environment when importing `app.main` outside tests (conftest does it).
- Do not `git commit`. Do not run `pip install` of new packages unless the brief says so; heavy
  SDKs are optional and imported lazily inside functions.
- The old MVP is in `docs/legacy/` and in git history (`git show HEAD~1:app/main.py`). Reuse logic from it where useful.

## Files you must read before coding

- `docs/ARCHITECTURE.md`
- `app/core/config.py`, `app/core/db.py`, `app/core/rbac.py`, `app/core/errors.py`, `app/core/audit.py`
- `app/core/queue.py` (handlers, enqueue, heartbeat), `app/core/events.py`, `app/core/findings.py`
- `app/api/deps.py` (require, get_db, Page), `app/api/auth.py` (router style example), `app/api/ops.py`
- `app/models/__init__.py`, `app/models/base.py`, `app/models/inventory.py`, `app/models/findings.py`
- `app/agents/runtime.py`, `app/agents/tools/registry.py`, `app/agents/providers.py` (if you touch agents or tools)
- `tests/conftest.py` (fixtures: owner, second_tenant, api_key, ingest_key, db, wait_job, wait_for, make_user)
- `tests/test_core_auth.py` (test style)

## Conventions that are enforced

- Your package: `app/<name>/` with `__init__.py` exposing `setup(app)` when you need to register
  queue handlers, tools, event subscribers, startup hooks (`app.state.startup_hooks.append(async fn)`) or background loops
  (`from app.main import spawn`). `setup` is called once by the app factory before routers mount.
- Your models: `app/models/<name>.py`, every table uses `TenantMixin` (except pure lookup tables). Add nothing to other model files.
- Your router: `app/api/<name>.py` exposing `router = APIRouter(prefix='/api/v1/<name>', tags=['<name>'])`.
  It is discovered automatically. Every endpoint has `principal: Principal = Depends(require('<perm>'))`.
  Use the permission strings from `app/core/rbac.py`. Lists use `Page` and return `{items, next_cursor}`.
- Tenant scoping on every query: `from app.core.db import scoped, get_scoped`.
- Audit every state change: `record_audit(db, principal, '<pkg>.<verb>', subject_id, {...})`.
- Queue work: `@app.state.queue.handler('<pkg>.<verb>')` inside `setup`, handler `(job, ctx)`; use
  `ctx.db_factory` with `session_scope`, call `await ctx.heartbeat()` in long loops, and re-check
  authorization inside the handler. Enqueue with `await request.app.state.queue.enqueue(kind, payload, tenant_id=principal.tenant_id)`.
- Findings and events are created only through `app.core.findings.upsert_finding` / `upsert_event`.
- Secrets: never log, never store in evidence, resolve with `app.core.security.resolve_secret(ref, settings)`; pass free text through `redact()`.
- External processes: fixed argv list via `asyncio.create_subprocess_exec`, never a shell string. Timeouts always.
- Network calls in tests are forbidden. Use `respx` for httpx and `monkeypatch` for SDK clients.
- Every list/get endpoint gets a cross-tenant test using the `second_tenant` fixture (expect 404 or an empty list).
- Keep functions typed, no prints, logging via `logging.getLogger('sentinel.<pkg>')`.
- Serialize datetimes as-is (FastAPI handles them); JSON columns via `models.base.dumps/loads`.

## Report

When done, run your tests plus `tests/test_core_*.py` and report: files created, public interfaces
(function signatures) other packages can call, endpoints added, what is real vs. stubbed (be exact),
any helper you had to add outside your package (should be none), and test results verbatim.
