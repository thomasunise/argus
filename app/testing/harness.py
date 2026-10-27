"""Test harness: adapter base class, normalized finding shape, bounded subprocess runner,
and the queue-handler body that executes one TestRun safely.

Safety is the product. Scope is checked at request time by the router and AGAIN here at
execution time; a queued run is not a grant. External tools run through run_tool() with a
fixed argv list, never a shell, with a timeout and bounded output, and all output is passed
through redact() before it is ever persisted or logged.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

from ..core.config import Settings
from ..core.errors import ScopeDenied, Unavailable
from ..core.security import redact
from . import scope as scope_module
from .ratelimit import RateLimiter, limiter_for

log = logging.getLogger('argus.testing')

MAX_OUTPUT_BYTES = 2 * 1024 * 1024  # 2 MB per stream

# A run that finds its scope at max_concurrency waits and tries again instead of starting.
CONCURRENCY_RETRY_SECONDS = 15
MAX_CONCURRENCY_DEFERRALS = 240  # about an hour of waiting before the run is failed


@dataclass
class NormalizedFinding:
    rule: str
    title: str
    description: str
    severity: str
    remediation: str = ''
    evidence: dict = field(default_factory=dict)
    cve_ids: list[str] = field(default_factory=list)
    cvss: float | None = None
    verified: bool = False


@dataclass
class HarnessContext:
    settings: Settings
    tenant_id: str
    run_id: str
    heartbeat: Callable[[], Awaitable[None]]
    rate_limiter: RateLimiter
    logger: logging.Logger
    scan_root: Any  # pathlib.Path
    tier: str = 'passive'
    target: str = ''  # normalized target produced by scope.check (web origin / repo relative path)
    auth_headers: dict = field(default_factory=dict)  # decrypted per-asset credentials, this run only
    role_headers: dict = field(default_factory=dict)  # role -> decrypted headers map for multi-role / IDOR probes
    db_factory: Any = None  # only adapters that persist their own state (out-of-band probes)


class TestAdapter:
    """Base class. Subclasses are instantiated once and registered in ADAPTERS."""

    name: str = ''
    tier: str = 'passive'  # nominal tier; the run tier is authoritative and passed on ctx
    target_kinds: tuple[str, ...] = ()
    description: str = ''

    def available(self, settings: Settings) -> bool:  # pragma: no cover - overridden
        return True

    async def run(self, plan_params: dict, asset, scope, ctx: HarnessContext) -> list[NormalizedFinding]:
        raise NotImplementedError


# -- adapter registry -------------------------------------------------------

ADAPTERS: dict[str, TestAdapter] = {}


def register(adapter: TestAdapter) -> TestAdapter:
    ADAPTERS[adapter.name] = adapter
    return adapter


def get_adapter(name: str) -> TestAdapter | None:
    return ADAPTERS.get(name)


# -- bounded, shell-free subprocess runner ----------------------------------


async def run_tool(argv: list[str], timeout: int, cwd: str | None = None, env: dict | None = None,
                   stdin: bytes | None = None) -> tuple[int, str, str]:
    """Run an external tool with a fixed argv (never a shell). Output is bounded to 2 MB per
    stream, the process is killed on timeout, and stdout/stderr are redacted before return."""
    if not argv or not isinstance(argv, list):
        raise ValueError('run_tool requires a non-empty argv list')
    run_env = env if env is not None else _base_env()
    try:
        process = await asyncio.create_subprocess_exec(
            *argv, cwd=cwd, env=run_env,
            stdin=asyncio.subprocess.PIPE if stdin is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
    except (FileNotFoundError, NotADirectoryError) as exc:
        raise Unavailable(f'tool not available: {argv[0]}') from exc
    try:
        out, err = await asyncio.wait_for(process.communicate(input=stdin), timeout=timeout)
    except asyncio.TimeoutError:
        process.kill()
        try:
            await process.communicate()
        except Exception:  # noqa: BLE001 - process already gone
            pass
        raise Unavailable(f'tool {argv[0]} exceeded {timeout}s timeout')
    stdout = redact(_decode(out))
    stderr = redact(_decode(err))
    return process.returncode or 0, stdout, stderr


def _base_env() -> dict:
    """A minimal environment that keeps PATH (and, on Windows, SystemRoot) but drops the rest,
    so a tool cannot inherit secrets from the API process environment."""
    env = {'PATH': os.environ.get('PATH', ''), 'HOME': os.environ.get('HOME', os.environ.get('USERPROFILE', '')),
           'LANG': os.environ.get('LANG', 'C.UTF-8')}
    for key in ('SystemRoot', 'SYSTEMROOT', 'TEMP', 'TMP', 'USERPROFILE', 'ComSpec'):
        if key in os.environ:
            env[key] = os.environ[key]
    return env


def _decode(raw: bytes | None) -> str:
    if not raw:
        return ''
    if len(raw) > MAX_OUTPUT_BYTES:
        raw = raw[:MAX_OUTPUT_BYTES]
    return raw.decode('utf-8', errors='replace')


# -- execution (queue handler body) -----------------------------------------


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


async def execute_run(run_id: str, db_factory, settings: Settings, app, heartbeat=None, job_tenant_id: str = '',
                      deferrals: int = 0) -> dict:
    """Load a TestRun, re-check scope at execution time, rate limit, run the adapter under a
    timeout, upsert findings and write TestResult rows. Returns a small status dict.

    All DB access uses short session_scope blocks so the long adapter call holds no session.
    `heartbeat` is the queue job's ctx.heartbeat (extends the lease / observes cancellation).
    When the scope already has `max_concurrency` runs in progress the run stays queued and is
    re-enqueued after CONCURRENCY_RETRY_SECONDS; `deferrals` counts how often that happened.
    """
    from ..core.audit import record_audit
    from ..core.db import session_scope
    from ..core.findings import upsert_finding
    from ..core.rbac import system_principal
    from ..models import Asset, AssetAuthorization, utcnow
    from .auth import load_auth_headers, load_role_headers
    from ..models.testing import TestResult, TestRun, TestScope
    from sqlalchemy import select

    # 1) load run + asset + scope + authorization
    with session_scope(db_factory) as db:
        run = db.get(TestRun, run_id)
        if run is None:
            return {'run_id': run_id, 'status': 'missing'}
        tenant_id = run.tenant_id
        if job_tenant_id and job_tenant_id != tenant_id:
            raise PermissionError('queued job tenant does not match the test run')
        adapter = get_adapter(run.adapter)
        # Rows referenced by id are re-checked against the run's tenant: a queued row is not a grant.
        asset = db.get(Asset, run.asset_id)
        if asset is not None and asset.tenant_id != tenant_id:
            asset = None
        scope = db.get(TestScope, run.scope_id) if run.scope_id else None
        if scope is not None and scope.tenant_id != tenant_id:
            scope = None
        if scope is not None and run.status == 'queued' and _scope_at_capacity(db, scope, run_id, settings):
            busy = True
        else:
            busy = False
        authorization = None
        if asset is not None and not busy:
            authorization = db.execute(
                select(AssetAuthorization)
                .where(AssetAuthorization.tenant_id == tenant_id, AssetAuthorization.asset_id == asset.id,
                       AssetAuthorization.revoked_at.is_(None))
                .order_by(AssetAuthorization.created_at.desc())
            ).scalars().first()
        if not busy:
            run.status, run.started_at = 'running', utcnow()
        run_tier = run.tier
        # Detach the values we need before the session closes.
        asset_snapshot = _AssetSnapshot.of(asset) if asset else None
        scope_snapshot = _ScopeSnapshot.of(scope) if scope else None
        auth_snapshot = _AuthSnapshot.of(authorization) if authorization else None
        auth_headers = load_auth_headers(db, tenant_id, run.asset_id)
        role_headers = load_role_headers(db, tenant_id, run.asset_id)

    principal = system_principal(tenant_id)

    if busy:
        return await _defer_for_concurrency(app, db_factory, settings, principal, run_id, tenant_id, scope_snapshot,
                                            deferrals)

    # 2) re-check scope at execution time
    now = datetime.now(timezone.utc)
    try:
        if adapter is None:
            raise ScopeDenied(f'unknown adapter {run.adapter!r}')
        if asset_snapshot is None:
            raise ScopeDenied('asset no longer exists')
        normalized_target = scope_module.check(adapter, asset_snapshot, scope_snapshot, auth_snapshot, now,
                                               settings, tier=run_tier)
    except ScopeDenied as exc:
        with session_scope(db_factory) as db:
            run = db.get(TestRun, run_id)
            run.status, run.error, run.finished_at = 'denied', str(exc), utcnow()
            record_audit(db, principal, 'testing.run.denied', run_id,
                         {'adapter': run.adapter, 'asset_id': run.asset_id, 'reason': str(exc)})
        log.warning('run %s denied: %s', run_id, exc)
        return {'run_id': run_id, 'status': 'denied', 'reason': str(exc)}

    # 3) rate limit (token bucket per tenant+asset honoring scope.max_rps)
    max_rps = scope_snapshot.max_rps if scope_snapshot else settings.test_rate_limit_rps
    limiter = limiter_for(tenant_id, asset_snapshot.id, max_rps)

    async def _heartbeat() -> None:
        if heartbeat is not None:
            await heartbeat()

    ctx = HarnessContext(settings=settings, tenant_id=tenant_id, run_id=run_id, heartbeat=_heartbeat,
                         rate_limiter=limiter, logger=log, scan_root=settings.scan_root, tier=run_tier,
                         target=normalized_target, auth_headers=auth_headers, role_headers=role_headers, db_factory=db_factory)

    # 4) run adapter under a timeout; build plain NormalizedFindings (no DB held)
    try:
        await limiter.acquire()
        findings = await asyncio.wait_for(
            adapter.run(_plan_params_for(db_factory, run_id), asset_snapshot, scope_snapshot, ctx),
            timeout=settings.test_tool_timeout_seconds,
        )
    except ScopeDenied as exc:
        with session_scope(db_factory) as db:
            run = db.get(TestRun, run_id)
            run.status, run.error, run.finished_at = 'denied', str(exc), utcnow()
            record_audit(db, principal, 'testing.run.denied', run_id, {'reason': str(exc)})
        return {'run_id': run_id, 'status': 'denied', 'reason': str(exc)}
    except (asyncio.TimeoutError, Unavailable, Exception) as exc:  # noqa: BLE001
        reason = exc.message if isinstance(exc, Unavailable) else f'{type(exc).__name__}'
        with session_scope(db_factory) as db:
            run = db.get(TestRun, run_id)
            run.status, run.finished_at = 'failed', utcnow()
            run.error = redact(str(reason))[:1000]
            record_audit(db, principal, 'testing.run.failed', run_id,
                         {'adapter': run.adapter, 'error': type(exc).__name__})
        log.exception('run %s (%s) failed', run_id, run.adapter)
        return {'run_id': run_id, 'status': 'failed', 'error': type(exc).__name__}

    # 5) persist findings + TestResult rows, update asset, audit
    with session_scope(db_factory) as db:
        run = db.get(TestRun, run_id)
        asset = db.get(Asset, run.asset_id)
        written = 0
        by_severity: dict[str, int] = {}
        for nf in findings:
            finding, _created = upsert_finding(
                db, tenant_id, source=adapter.name, rule=nf.rule, title=nf.title, description=nf.description,
                severity_name=nf.severity, asset_id=run.asset_id, remediation=nf.remediation,
                evidence=dict(nf.evidence or {}), cve_ids=list(nf.cve_ids or []), cvss=nf.cvss,
                validation_status='verified' if (getattr(nf, 'verified', False) or bool((nf.evidence or {}).get('verified'))) else None,
            )
            evidence_text = _json_dumps(nf.evidence or {})
            db.add(TestResult(tenant_id=tenant_id, run_id=run_id, finding_id=finding.id, rule=nf.rule[:160],
                              title=redact(nf.title)[:240], severity=finding.severity, evidence_json=evidence_text,
                              raw_hash=hashlib.sha256(f'{nf.rule}|{evidence_text}'.encode()).hexdigest()))
            written += 1
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
        run.status, run.finished_at, run.result_count = 'completed', utcnow(), written
        run.stats_json = _json_dumps({'by_severity': by_severity})
        if asset is not None:
            asset.last_scan_at = utcnow()
        record_audit(db, principal, 'testing.run.completed', run_id,
                     {'adapter': adapter.name, 'asset_id': run.asset_id, 'tier': run.tier, 'findings': written})
    log.info('run %s (%s) completed: %d findings', run_id, adapter.name, written)
    return {'run_id': run_id, 'status': 'completed', 'result_count': written}


def _scope_at_capacity(db, scope, run_id: str, settings: Settings) -> bool:
    """True when the scope already has max_concurrency runs in progress. Runs started longer ago than the tool
    timeout plus a margin are treated as dead (a crashed worker) so they cannot hold a slot forever. On PostgreSQL a
    transaction-scoped lock per scope makes the count and the switch to 'running' atomic across workers and
    replicas; SQLite (development only) serializes writers anyway."""
    from datetime import timedelta

    from sqlalchemy import func, select, text

    from ..models import utcnow
    from ..models.testing import TestRun

    bind = db.get_bind()
    if bind is not None and bind.dialect.name == 'postgresql':
        db.execute(text('SELECT pg_advisory_xact_lock(hashtext(:key))'), {'key': f'testing.scope:{scope.id}'})
    alive_since = utcnow() - timedelta(seconds=settings.test_tool_timeout_seconds + 120)
    running = db.execute(
        select(func.count()).select_from(TestRun)
        .where(TestRun.tenant_id == scope.tenant_id, TestRun.scope_id == scope.id, TestRun.status == 'running',
               TestRun.id != run_id, TestRun.started_at >= alive_since)
    ).scalar_one()
    return running >= max(1, int(scope.max_concurrency or 1))


async def _defer_for_concurrency(app, db_factory, settings: Settings, principal, run_id: str, tenant_id: str,
                                 scope_snapshot, deferrals: int) -> dict:
    from ..core.audit import record_audit
    from ..core.db import session_scope
    from ..models import utcnow
    from ..models.testing import TestRun

    limit = scope_snapshot.max_concurrency if scope_snapshot else 1
    if deferrals >= MAX_CONCURRENCY_DEFERRALS:
        reason = f'scope stayed at max_concurrency ({limit}) for {deferrals} retries'
        with session_scope(db_factory) as db:
            run = db.get(TestRun, run_id)
            run.status, run.error, run.finished_at = 'failed', reason, utcnow()
            record_audit(db, principal, 'testing.run.failed', run_id, {'adapter': run.adapter, 'error': 'concurrency_wait'})
        log.warning('run %s failed: %s', run_id, reason)
        return {'run_id': run_id, 'status': 'failed', 'error': 'concurrency_wait'}
    from .service import _lease_seconds

    job = await app.state.queue.enqueue('testing.run', {'run_id': run_id, 'deferrals': deferrals + 1},
                                        tenant_id=tenant_id, lease_seconds=_lease_seconds(settings),
                                        delay_seconds=CONCURRENCY_RETRY_SECONDS)
    with session_scope(db_factory) as db:
        run = db.get(TestRun, run_id)
        if run is not None:
            run.job_id = job.id
    log.info('run %s deferred: scope at max_concurrency %s (retry %d)', run_id, limit, deferrals + 1)
    return {'run_id': run_id, 'status': 'deferred', 'job_id': job.id}


def precheck(db, adapter: TestAdapter, asset, scope, settings: Settings, *, tier: str | None = None) -> str:
    """Request-time scope check. Loads the asset's current authorization and evaluates
    scope.check against read-only snapshots. Raises ScopeDenied or returns the normalized target.
    """
    from ..models import AssetAuthorization
    from sqlalchemy import select

    authorization = db.execute(
        select(AssetAuthorization)
        .where(AssetAuthorization.tenant_id == asset.tenant_id, AssetAuthorization.asset_id == asset.id,
               AssetAuthorization.revoked_at.is_(None))
        .order_by(AssetAuthorization.created_at.desc())
    ).scalars().first()
    return scope_module.check(
        adapter,
        _AssetSnapshot.of(asset),
        _ScopeSnapshot.of(scope) if scope is not None else None,
        _AuthSnapshot.of(authorization) if authorization is not None else None,
        datetime.now(timezone.utc),
        settings,
        tier=tier,
    )


def _plan_params_for(db_factory, run_id: str) -> dict:
    from ..core.db import session_scope
    from ..models import loads
    from ..models.testing import TestPlan, TestRun

    with session_scope(db_factory) as db:
        run = db.get(TestRun, run_id)
        if run is None:
            return {}
        own = loads(run.params_json, {})
        if isinstance(own, dict) and own:
            return own
        if not run.plan_id:
            return {}
        plan = db.get(TestPlan, run.plan_id)
        if plan is None or plan.tenant_id != run.tenant_id:
            return {}
        params = loads(plan.params_json, {})
        return params if isinstance(params, dict) else {}


def _json_dumps(value: dict) -> str:
    from ..models import dumps

    # Redact string values defensively; never store secrets in evidence.
    return dumps({k: (redact(v) if isinstance(v, str) else v) for k, v in (value or {}).items()}, limit=6000)


# -- lightweight read-only snapshots passed to adapters/scope ----------------


@dataclass
class _AssetSnapshot:
    id: str
    name: str
    kind: str
    target: str
    environment: str
    criticality: str

    @classmethod
    def of(cls, asset) -> '_AssetSnapshot':
        return cls(id=asset.id, name=asset.name, kind=asset.kind, target=asset.target,
                   environment=asset.environment, criticality=asset.criticality)


@dataclass
class _ScopeSnapshot:
    id: str
    name: str
    asset_ids: list[str]
    allowed_tiers: list[str]
    environments: list[str]
    window_start: str
    window_end: str
    max_rps: float
    max_concurrency: int
    expires_at: datetime | None
    revoked_at: datetime | None

    @classmethod
    def of(cls, scope) -> '_ScopeSnapshot':
        from ..models import loads

        return cls(id=scope.id, name=scope.name, asset_ids=loads(scope.asset_ids_json, []),
                   allowed_tiers=loads(scope.allowed_tiers_json, []), environments=loads(scope.environments_json, []),
                   window_start=scope.window_start, window_end=scope.window_end, max_rps=scope.max_rps,
                   max_concurrency=scope.max_concurrency, expires_at=_aware(scope.expires_at),
                   revoked_at=_aware(scope.revoked_at))


@dataclass
class _AuthSnapshot:
    id: str
    allow_active: bool
    allow_intrusive: bool
    expires_at: datetime | None
    revoked_at: datetime | None

    @classmethod
    def of(cls, auth) -> '_AuthSnapshot':
        return cls(id=auth.id, allow_active=bool(auth.allow_active), allow_intrusive=bool(auth.allow_intrusive),
                   expires_at=_aware(auth.expires_at), revoked_at=_aware(auth.revoked_at))
