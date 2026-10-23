"""Harness unit tests: scope enforcement, the bounded subprocess runner, the rate limiter,
and execute_run end to end (scope re-check, findings, denial, failure)."""
from __future__ import annotations

import sys
import types
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.core.errors import ScopeDenied, Unavailable
from app.testing import harness, scope as scope_mod
from app.testing.ratelimit import RateLimiter
from app.models import Asset, AssetAuthorization, Finding, utcnow
from app.models.testing import TestResult, TestRun, TestScope

NOW = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)


class _DummyAdapter(harness.TestAdapter):
    name = 'dummy'
    tier = 'passive'
    target_kinds = ('cloud_account',)


def _asset(kind='cloud_account', env='production', target='acct-123'):
    return types.SimpleNamespace(id='asset-1', name='a', kind=kind, target=target, environment=env,
                                 criticality='medium', tenant_id='t1')


def _scope(asset_ids=('asset-1',), tiers=('passive',), envs=(), ws='', we='', max_rps=5.0):
    return types.SimpleNamespace(id='scope-1', name='s', asset_ids=list(asset_ids), allowed_tiers=list(tiers),
                                 environments=list(envs), window_start=ws, window_end=we, max_rps=max_rps,
                                 max_concurrency=1, expires_at=None, revoked_at=None)


def _auth(active=False, intrusive=False, expires=None, revoked=None):
    return types.SimpleNamespace(id='auth-1', allow_active=active, allow_intrusive=intrusive,
                                 expires_at=expires, revoked_at=revoked)


def test_scope_happy_path(settings):
    out = scope_mod.check(_DummyAdapter(), _asset(), _scope(), _auth(), NOW, settings)
    assert out == 'acct-123'


def test_scope_denies_when_asset_not_in_scope(settings):
    with pytest.raises(ScopeDenied):
        scope_mod.check(_DummyAdapter(), _asset(), _scope(asset_ids=('other',)), _auth(), NOW, settings)


def test_scope_requires_authorization(settings):
    with pytest.raises(ScopeDenied):
        scope_mod.check(_DummyAdapter(), _asset(), _scope(), None, NOW, settings)


def test_scope_rejects_expired_authorization(settings):
    expired = _auth(expires=NOW - timedelta(days=1))
    with pytest.raises(ScopeDenied):
        scope_mod.check(_DummyAdapter(), _asset(), _scope(), expired, NOW, settings)


def test_scope_tier_must_be_allowed_by_scope_and_auth(settings):
    adapter = _DummyAdapter()
    # Scope does not allow active.
    with pytest.raises(ScopeDenied):
        scope_mod.check(adapter, _asset(), _scope(tiers=('passive',)), _auth(active=True), NOW, settings, tier='active')
    # Scope allows active but authorization does not.
    with pytest.raises(ScopeDenied):
        scope_mod.check(adapter, _asset(), _scope(tiers=('passive', 'active')), _auth(active=False), NOW, settings, tier='active')


def test_scope_intrusive_only_in_staging_or_lab(settings):
    adapter = _DummyAdapter()
    scope = _scope(tiers=('passive', 'active', 'intrusive'))
    auth = _auth(active=True, intrusive=True)
    with pytest.raises(ScopeDenied):
        scope_mod.check(adapter, _asset(env='production'), scope, auth, NOW, settings, tier='intrusive')
    assert scope_mod.check(adapter, _asset(env='lab'), scope, auth, NOW, settings, tier='intrusive') == 'acct-123'


def test_scope_time_window(settings):
    scope = _scope(ws='13:00', we='14:00')  # NOW is 12:00 UTC -> outside
    with pytest.raises(ScopeDenied):
        scope_mod.check(_DummyAdapter(), _asset(), scope, _auth(), NOW, settings)
    inside = _scope(ws='11:00', we='13:00')
    assert scope_mod.check(_DummyAdapter(), _asset(), inside, _auth(), NOW, settings) == 'acct-123'


def test_scope_rejects_revoked_or_expired_scope(settings):
    revoked = _scope()
    revoked.revoked_at = NOW - timedelta(hours=1)
    with pytest.raises(ScopeDenied):
        scope_mod.check(_DummyAdapter(), _asset(), revoked, _auth(), NOW, settings)


@pytest.mark.asyncio
async def test_run_tool_captures_output_and_redacts():
    code, out, err = await harness.run_tool([sys.executable, '-c', "print('AKIAIOSFODNN7EXAMPLE ok')"], timeout=10)
    assert code == 0
    assert 'ok' in out and 'AKIAIOSFODNN7EXAMPLE' not in out


@pytest.mark.asyncio
async def test_run_tool_times_out():
    with pytest.raises(Unavailable):
        await harness.run_tool([sys.executable, '-c', 'import time; time.sleep(5)'], timeout=1)


@pytest.mark.asyncio
async def test_run_tool_missing_binary():
    with pytest.raises(Unavailable):
        await harness.run_tool(['this-binary-does-not-exist-xyz'], timeout=5)


@pytest.mark.asyncio
async def test_rate_limiter_blocks_then_refills():
    import time

    limiter = RateLimiter(10)  # 10 tokens/sec, capacity ~10
    start = time.monotonic()
    for _ in range(11):
        await limiter.acquire()
    assert time.monotonic() - start >= 0.05  # the 11th token had to wait for a refill


# --------- execute_run integration (no HTTP, direct call) ---------


class _FakeRepoAdapter(harness.TestAdapter):
    name = 'fake_repo'
    tier = 'passive'
    target_kinds = ('repo',)

    async def run(self, plan_params, asset, scope, ctx):
        await ctx.rate_limiter.acquire()
        await ctx.heartbeat()
        return [harness.NormalizedFinding(rule='fake:rule', title='Fake finding', description='d',
                                          severity='high', remediation='fix it', evidence={'token': 'password=hunter2hunter2'},
                                          cve_ids=['CVE-2024-0001'], cvss=8.1)]


def _seed(db, tenant_id, *, kind='repo', target='repo', env='production', tiers=('passive',),
          allow_active=False, allow_intrusive=False, scan_root=None):
    if scan_root is not None and kind == 'repo':
        (scan_root / target).mkdir(parents=True, exist_ok=True)
    asset = Asset(tenant_id=tenant_id, name='app', kind=kind, target=target, environment=env, approved=True)
    db.add(asset)
    db.flush()
    db.add(AssetAuthorization(tenant_id=tenant_id, asset_id=asset.id, authorized_by='u', attestation='ok',
                              allow_active=allow_active, allow_intrusive=allow_intrusive))
    scope = TestScope(tenant_id=tenant_id, name='s', asset_ids_json=f'["{asset.id}"]',
                      allowed_tiers_json='["' + '","'.join(tiers) + '"]', environments_json='[]', max_rps=20.0)
    db.add(scope)
    db.flush()
    return asset.id, scope.id


@pytest.mark.asyncio
async def test_execute_run_completes_and_writes_findings(app, settings, default_tenant_id, monkeypatch):
    harness.register(_FakeRepoAdapter())
    factory = app.state.db_factory
    with factory() as db:
        asset_id, scope_id = _seed(db, default_tenant_id, scan_root=settings.scan_root)
        run = TestRun(tenant_id=default_tenant_id, scope_id=scope_id, adapter='fake_repo', asset_id=asset_id,
                      tier='passive', status='queued')
        db.add(run)
        db.commit()
        run_id = run.id

    result = await harness.execute_run(run_id, factory, settings, app)
    assert result['status'] == 'completed' and result['result_count'] == 1

    with factory() as db:
        run = db.get(TestRun, run_id)
        assert run.status == 'completed' and run.finished_at is not None
        results = db.execute(select(TestResult).where(TestResult.run_id == run_id)).scalars().all()
        assert len(results) == 1 and results[0].finding_id
        # Secret value never persisted in TestResult evidence.
        assert 'hunter2hunter2' not in results[0].evidence_json
        finding = db.get(Finding, results[0].finding_id)
        assert finding.severity == 'high' and 'CVE-2024-0001' in finding.cve_ids
        assert 'hunter2hunter2' not in finding.evidence
        asset = db.get(Asset, asset_id)
        assert asset.last_scan_at is not None


@pytest.mark.asyncio
async def test_execute_run_denied_when_authorization_missing(app, settings, default_tenant_id):
    harness.register(_FakeRepoAdapter())
    factory = app.state.db_factory
    with factory() as db:
        (settings.scan_root / 'repo2').mkdir(parents=True, exist_ok=True)
        asset = Asset(tenant_id=default_tenant_id, name='app', kind='repo', target='repo2', environment='production')
        db.add(asset)
        db.flush()
        scope = TestScope(tenant_id=default_tenant_id, name='s', asset_ids_json=f'["{asset.id}"]',
                          allowed_tiers_json='["passive"]', environments_json='[]', max_rps=20.0)
        db.add(scope)
        db.flush()
        run = TestRun(tenant_id=default_tenant_id, scope_id=scope.id, adapter='fake_repo', asset_id=asset.id,
                      tier='passive', status='queued')
        db.add(run)
        db.commit()
        run_id = run.id

    result = await harness.execute_run(run_id, factory, settings, app)
    assert result['status'] == 'denied'
    with factory() as db:
        assert db.get(TestRun, run_id).status == 'denied'


@pytest.mark.asyncio
async def test_execute_run_marks_failed_on_adapter_error(app, settings, default_tenant_id):
    class _Boom(harness.TestAdapter):
        name = 'boom_repo'
        tier = 'passive'
        target_kinds = ('repo',)

        async def run(self, plan_params, asset, scope, ctx):
            raise RuntimeError('kaboom secret=AKIAIOSFODNN7EXAMPLE')

    harness.register(_Boom())
    factory = app.state.db_factory
    with factory() as db:
        asset_id, scope_id = _seed(db, default_tenant_id, target='repo3', scan_root=settings.scan_root)
        run = TestRun(tenant_id=default_tenant_id, scope_id=scope_id, adapter='boom_repo', asset_id=asset_id,
                      tier='passive', status='queued')
        db.add(run)
        db.commit()
        run_id = run.id

    result = await harness.execute_run(run_id, factory, settings, app)
    assert result['status'] == 'failed'
    with factory() as db:
        run = db.get(TestRun, run_id)
        assert run.status == 'failed' and 'AKIAIOSFODNN7EXAMPLE' not in run.error


def test_adapter_cannot_run_below_its_nominal_tier(settings):
    """Adapters run at their own tier whatever the request says; a lower label must not pass a lower scope."""
    class _Intrusive(_DummyAdapter):
        name = 'intrusive-dummy'
        tier = 'intrusive'

    permissive = _scope(tiers=('passive', 'active', 'intrusive'), envs=('staging',))
    with pytest.raises(ScopeDenied, match='runs at tier intrusive'):
        scope_mod.check(_Intrusive(), _asset(env='staging'), permissive, _auth(active=True, intrusive=True), NOW, settings, tier='passive')
    with pytest.raises(ScopeDenied):
        scope_mod.check(_Intrusive(), _asset(), _scope(tiers=('passive',)), _auth(), NOW, settings, tier='passive')
    # Requesting the adapter's own tier (or higher) is still subject to the normal checks.
    out = scope_mod.check(_Intrusive(), _asset(env='staging'), permissive, _auth(active=True, intrusive=True), NOW, settings, tier='intrusive')
    assert out == 'acct-123'
