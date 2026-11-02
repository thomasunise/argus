"""P0 trust-boundary regression tests. All negative cases must fail closed.

PostgreSQL test checks RLS as a non-owner role instead of as the migration
owner (the owner bypasses RLS by default). The remaining tests need no network.
"""
from __future__ import annotations

import copy
import hashlib
import time
import uuid
from types import SimpleNamespace

import pytest

from app.actions import policy as action_policy
from app.core.config import assert_safe_config
from app.core.errors import ScopeDenied
from app.core.queue import _RedisBackend
from app.exploit import engine, sandbox
from app.exploit.executor.cluster import EnvelopeError, validate_envelope
from app.exploit.executor.engine_validation import EngineError, validate_engine
from app.testing import scope as test_scope
from app.testing.authorization import sign_roe, verify_roe

KEY = 'independent-approver-signing-key-1234567890abcdef'
IMAGE = 'ghcr.io/example/argus-poc@sha256:' + 'a' * 64
ENGINE_IMAGE = 'ghcr.io/example/argus-engine@sha256:' + 'b' * 64


def _asset():
    return SimpleNamespace(id='asset-123', tenant_id='tenant-123',
                           kind='web', target='https://example.test', environment='production')


def _token(asset=None, **kwargs):
    asset = asset or _asset()
    fields = dict(key=KEY, tenant_id=asset.tenant_id, asset_id=asset.id, target=asset.target,
                  document_sha256=hashlib.sha256(b'approved signed ROE').hexdigest(),
                  expires_epoch=int(time.time()) + 3600)
    fields.update(kwargs)
    return sign_roe(**fields)


def test_production_signature_is_bound_to_asset_tenant_target_and_expiry(settings):
    asset = _asset()
    settings.exploit_roe_signing_key = KEY
    token = _token(asset)
    assert verify_roe(token, asset, settings)
    assert not verify_roe('ROE-2026-01', asset, settings)
    assert not verify_roe(token + '0', asset, settings)
    assert not verify_roe(token, SimpleNamespace(**{**vars(asset), 'tenant_id': 'other-tenant'}), settings)
    assert not verify_roe(token, SimpleNamespace(**{**vars(asset), 'target': 'https://different.test'}), settings)
    assert not verify_roe(token, SimpleNamespace(**{**vars(asset), 'id': 'another-asset'}), settings)
    assert not verify_roe(token, asset, settings, now=time.time() + 86400)
    settings.exploit_roe_signing_key = 'wrong-key-wrong-key-wrong-key-wrong-key'
    assert not verify_roe(token, asset, settings)


def test_production_exploit_requires_matching_scope_document(settings):
    asset = _asset()
    settings.exploit_roe_signing_key = KEY
    token = _token(asset)
    auth = SimpleNamespace(allow_exploit=True, scope_document_ref=token)
    scope = SimpleNamespace(signed_document_ref='')
    with pytest.raises(ScopeDenied, match='scope must explicitly bind'):
        test_scope.assert_exploit_authorized(asset, auth, settings, scope=scope)
    scope.signed_document_ref = token
    test_scope.assert_exploit_authorized(asset, auth, settings, scope=scope)
    auth.scope_document_ref = 'ROE-2026-01'
    with pytest.raises(ScopeDenied, match='valid, signed'):
        test_scope.assert_exploit_authorized(asset, auth, settings, scope=scope)
    # Even a permissive environment override must not grant production
    # exploit capability without a signed token.
    settings.exploit_environments = 'staging,lab,production'
    with pytest.raises(ScopeDenied, match='valid, signed'):
        test_scope.assert_exploit_authorized(asset, auth, settings, scope=scope)


def _poc():
    j = sandbox.SandboxJob(request_id='bcd123ef-0000-4000-8000-000000000001',
                           tenant_id='tenant-123', language='python', code='print(1)',
                           image=IMAGE, target_host='example.test', target_ip='203.0.113.10')
    return sandbox.render_manifest(j), sandbox.render_network_policy(j), j.code


@pytest.mark.parametrize('change', [
    lambda j, p: j['spec']['template']['spec']['securityContext'].update(runAsNonRoot=False),
    lambda j, p: j['spec']['template']['spec']['containers'][0]['securityContext'].update(runAsUser=0),
    lambda j, p: j['spec']['template']['spec']['containers'][0].pop('resources'),
    lambda j, p: j['spec']['template']['spec']['volumes'].append(
        {'name': 'stolen', 'secret': {'secretName': 'api-token'}}),
    lambda j, p: j['spec']['template']['metadata'].update(
        annotations={'sidecar.istio.io/inject': 'true'}),
    lambda j, p: j['spec']['template']['spec']['containers'][0].update(
        command=['/bin/sh', '-c', 'echo test']),
    lambda j, p: p['spec']['egress'][0]['to'][0]['ipBlock'].update(cidr='999.999.999.999/32'),
])
def test_poc_executor_denies_uncontained_pods(change):
    j, p, code = _poc()
    change(j, p)
    with pytest.raises(EnvelopeError):
        validate_envelope(j, p, code, namespace='argus-sandbox')


def test_poc_executor_accepts_expected_envelope():
    j, p, code = _poc()
    validate_envelope(j, p, code, namespace='argus-sandbox')


def _engine():
    j = engine.EngineJob(run_id='bcd123ef-0000-4000-8000-000000000001',
                         tenant_id='tenant-123', image=ENGINE_IMAGE,
                         argv=['--target', 'https://example.test'], env={'STRIX_LLM': 'model'},
                         target_host='example.test', egress=[('203.0.113.10', 443)])
    return engine.render_manifest(j), engine.render_network_policy(j)


@pytest.mark.parametrize('change', [
    lambda j, p: j['spec']['template']['spec']['securityContext'].update(runAsUser=0),
    lambda j, p: j['spec']['template']['spec']['containers'][0]['securityContext'].update(runAsNonRoot=False),
    lambda j, p: j['spec']['template']['spec']['volumes'].append(
        {'name': 'token', 'projected': {'sources': [{'serviceAccountToken': {'path': 'token'}}]}}),
    lambda j, p: j['spec']['template']['spec']['containers'][0].update(command=[]),
    lambda j, p: p['spec']['egress'][0]['to'][0]['ipBlock'].update(cidr='300.1.1.1/32'),
])
def test_engine_executor_denies_uncontained_pods(change):
    j, p = _engine()
    change(j, p)
    with pytest.raises(EngineError):
        validate_engine(j, p, namespace='argus-sandbox', allowed_images={ENGINE_IMAGE})


def test_engine_allowlist_stays_mandatory():
    j, p = _engine()
    with pytest.raises(EngineError, match='allowlisted'):
        validate_engine(j, p, namespace='argus-sandbox', allowed_images=set())


def test_scan_jobs_route_only_to_scanner_queue():
    scan = SimpleNamespace(kind='testing.run', priority=3)
    response = SimpleNamespace(kind='actions.execute', priority=3)
    assert _RedisBackend._list(scan) == 'argus:scan:q:3'
    assert _RedisBackend._list(response) == 'argus:q:3'
    with pytest.raises(ValueError):
        _RedisBackend('redis://localhost', worker_role='anything')


def test_production_requires_out_of_process_scanner(settings):
    insecure = settings.model_copy(update={'app_env': 'production', 'workers_inprocess': True})
    with pytest.raises(RuntimeError, match='WORKERS_INPROCESS'):
        assert_safe_config(insecure)


def test_postgres_rls_is_deny_by_default_for_nonowner(app):
    """Direct SQL without tenant context must see no assets and cannot insert.

    This test is skipped for SQLite because SQLite has no PostgreSQL RLS.
    It uses a temporary non-owner role; the service's migration user is not
    an appropriate account to use when evaluating RLS effectiveness.
    """
    engine_db = app.state.engine
    if engine_db.dialect.name != 'postgresql':
        pytest.skip('requires PostgreSQL RLS')
    from sqlalchemy import text
    role = 'argus_p0_' + uuid.uuid4().hex[:12]
    with engine_db.begin() as c:
        c.execute(text(f'CREATE ROLE "{role}" NOLOGIN'))
        c.execute(text(f'GRANT USAGE ON SCHEMA public TO "{role}"'))
        c.execute(text(f'GRANT SELECT, INSERT ON public.assets TO "{role}"'))
    try:
        with engine_db.begin() as c:
            c.execute(text(f'SET LOCAL ROLE "{role}"'))
            assert c.execute(text('SELECT COUNT(*) FROM public.assets')).scalar_one() == 0
            from sqlalchemy.exc import DBAPIError
            with c.begin_nested():
                with pytest.raises(DBAPIError):
                    c.execute(text("INSERT INTO public.assets (id, tenant_id, name, kind, target) "
                                   "VALUES ('p0-blocked', 'unknown', 'blocked', 'web', 'https://example.test')"))
            # An explicit tenant context is the only way to see tenant rows.
            c.execute(text("SELECT set_config('app.tenant_id', :tid, true)"), {'tid': app.state.default_tenant_id})
            assert c.execute(text('SELECT COUNT(*) FROM public.assets')).scalar_one() >= 0
    finally:
        with engine_db.begin() as c:
            c.execute(text(f'REVOKE ALL ON public.assets FROM "{role}"'))
            c.execute(text(f'REVOKE ALL ON SCHEMA public FROM "{role}"'))
            c.execute(text(f'DROP ROLE "{role}"'))
