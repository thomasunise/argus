"""Discovery loop: bounded recon -> stored facts -> scoped follow-up tests.

Recon runs in the sandbox executor with egress pinned to the asset origin. Its output is facts
(endpoints, technologies), not findings. Follow-up tests go through
`testing.service.launch_scan`, which re-checks the scope at request time, so the loop can never
widen its own authority: discovery proposes, the existing gate disposes.

Every phase is capped (`discovery_max_endpoints`, `discovery_follow_up_limit`), and every
transition is audited.
"""
from __future__ import annotations

import json
import logging
import socket

import httpx
from typing import Any, Callable

from sqlalchemy import select

from ..core.audit import record_audit
from ..core.db import get_scoped, session_scope
from ..core.errors import NotFound, PolicyDenied, ScopeDenied, Unavailable
from ..core.rbac import Principal, system_principal
from ..exploit import engine
from ..models import Asset, AssetAuthorization, Tenant, dumps, loads, utcnow
from ..models.discovery import DISCOVERY_KINDS, Discovery, DiscoveryRun, RequestCapture
from ..models.testing import TestScope
from ..testing import scope as scope_module
from ..testing import service as testing_service

log = logging.getLogger('argus.discovery')

DISCOVERY_MARKER = 'ARGUS_DISCOVERY '
TRAILER = 'ARGUS_ENGINE '
REQUEST_MARKER = 'ARGUS_REQUEST '


class ReconAdapter:
    """Pseudo-adapter so the existing scope gate can validate a discovery run."""

    name = 'recon'
    tier = 'active'
    target_kinds = ('web',)
    description = 'Bounded web discovery (crawl, probes, header technology hints).'


def parse_discoveries(text: str) -> list[dict[str, str]]:
    facts: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for line in (text or '').splitlines():
        stripped = line.strip()
        if not stripped.startswith(DISCOVERY_MARKER):
            continue
        try:
            item = json.loads(stripped[len(DISCOVERY_MARKER):])
        except ValueError:
            continue
        if not isinstance(item, dict):
            continue
        kind = str(item.get('kind') or 'endpoint').lower()
        value = str(item.get('value') or '').strip()
        if not value or len(value) > 500:
            continue
        if kind not in DISCOVERY_KINDS:
            kind = 'endpoint'
        if (kind, value) in seen:
            continue
        seen.add((kind, value))
        facts.append({'kind': kind, 'value': value, 'source': str(item.get('source') or 'recon')[:64],
                      'confidence': str(item.get('confidence') or 'medium')[:8]})
    return facts


def tenant_opt_in(tenant: Tenant | None) -> bool:
    if tenant is None:
        return False
    data = loads(tenant.settings_json, {})
    block = data.get('discovery') if isinstance(data, dict) else None
    return bool(isinstance(block, dict) and block.get('enabled'))


def assert_enabled(settings, tenant: Tenant | None) -> None:
    if not settings.discovery_enabled:
        raise PolicyDenied('discovery is disabled (DISCOVERY_ENABLED=false)')
    if settings.discovery_kill_switch:
        raise PolicyDenied('the discovery kill switch is engaged')
    if not tenant_opt_in(tenant):
        raise PolicyDenied("this tenant has not opted in (settings.discovery.enabled)")


def _target_ip(target: str) -> tuple[str, int]:
    port = 8443 if target.endswith(':8443') else 443
    host = target.split('://', 1)[-1].split('/', 1)[0].split(':')[0]
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    ips = sorted({info[4][0] for info in infos if ':' not in info[4][0]})
    if not ips:
        raise ScopeDenied('the target resolved to no permitted IPv4 address')
    return ips[0], port


def _upsert_fact(db, tenant_id: str, asset_id: str, run_id: str, fact: dict[str, str]) -> tuple[Discovery, bool]:
    row = db.execute(select(Discovery).where(Discovery.tenant_id == tenant_id, Discovery.asset_id == asset_id,
                                             Discovery.kind == fact['kind'], Discovery.value == fact['value'])).scalar_one_or_none()
    if row is None:
        row = Discovery(tenant_id=tenant_id, asset_id=asset_id, run_id=run_id, kind=fact['kind'], value=fact['value'],
                        source=fact['source'], confidence=fact['confidence'], status='new')
        db.add(row)
        db.flush()
        return row, True
    row.run_id = run_id
    row.last_seen = utcnow()
    return row, False


async def execute_run(app, run_id: str, *, client=None, launcher: Callable[..., Any] | None = None) -> dict[str, Any]:
    """Run one discovery pass. `client` and `launcher` are injectable for tests."""
    settings = app.state.settings
    launcher = launcher or testing_service.launch_scan

    with session_scope(app.state.db_factory) as db:
        run = db.get(DiscoveryRun, run_id)
        if run is None:
            return {'run_id': run_id, 'status': 'missing'}
        tenant_id = run.tenant_id
        principal = system_principal(tenant_id)
        tenant = db.get(Tenant, tenant_id)
        try:
            assert_enabled(settings, tenant)
        except PolicyDenied as exc:
            run.status, run.error, run.finished_at = 'denied', str(exc), utcnow()
            record_audit(db, principal, 'discovery.run.denied', run.id, {'reason': str(exc)})
            return {'run_id': run.id, 'status': 'denied', 'reason': str(exc)}

        asset = db.get(Asset, run.asset_id)
        scope = db.get(TestScope, run.scope_id)
        authorization = db.execute(
            select(AssetAuthorization).where(AssetAuthorization.tenant_id == tenant_id,
                                             AssetAuthorization.asset_id == run.asset_id,
                                             AssetAuthorization.revoked_at.is_(None))
            .order_by(AssetAuthorization.created_at.desc())).scalars().first()
        try:
            if asset is None or asset.tenant_id != tenant_id:
                raise ScopeDenied('asset no longer exists')
            target = scope_module.check(ReconAdapter(), asset, scope, authorization, utcnow(), settings, tier='active')
        except ScopeDenied as exc:
            run.status, run.error, run.finished_at = 'denied', str(exc), utcnow()
            record_audit(db, principal, 'discovery.run.denied', run.id, {'reason': str(exc)})
            return {'run_id': run.id, 'status': 'denied', 'reason': str(exc)}

        run.status, run.started_at = 'running', utcnow()
        record_audit(db, principal, 'discovery.run.started', run.id,
                     {'asset_id': run.asset_id, 'scope_id': run.scope_id, 'target': target})
        max_endpoints = max(1, int(settings.discovery_max_endpoints))
        follow_up_limit = max(0, int(settings.discovery_follow_up_limit))

    try:
        ip, port = _target_ip(target)
    except (ScopeDenied, OSError) as exc:
        with session_scope(app.state.db_factory) as db:
            run = db.get(DiscoveryRun, run_id)
            run.status, run.error, run.finished_at = 'failed', str(exc)[:500], utcnow()
            record_audit(db, system_principal(tenant_id), 'discovery.run.failed', run_id, {'error': 'resolution'})
        return {'run_id': run_id, 'status': 'failed', 'error': 'resolution'}

    host = target.split('://', 1)[-1].split('/', 1)[0].split(':')[0]
    limits = engine.EngineLimits(wall_seconds=int(settings.discovery_max_wall_seconds), cpu=1.0,
                                 memory_mb=512, pids=128)
    phases: list[engine.EngineJob] = []
    browser_image = str(getattr(settings, 'discovery_browser_image', '') or '')
    if browser_image:
        pages = max(1, min(10, max_endpoints))
        phases.append(engine.EngineJob(
            run_id=run_id, suffix='b', tenant_id=tenant_id, image=browser_image,
            argv=['--target', target, '--max-pages', str(pages)],
            env={'ARGUS_TARGET': target, 'ARGUS_MAX_PAGES': str(pages), 'ARGUS_RUN_ID': run_id},
            target_host=host, egress=[(ip, port)], limits=limits))
    phases.append(engine.EngineJob(
        run_id=run_id, suffix='r' if browser_image else '', tenant_id=tenant_id, image=str(settings.discovery_image),
        argv=['--target', target, '--max-endpoints', str(max_endpoints)],
        env={'ARGUS_TARGET': target, 'ARGUS_MAX_ENDPOINTS': str(max_endpoints), 'ARGUS_RUN_ID': run_id},
        target_host=host, egress=[(ip, port)], limits=limits))

    client = client or engine.client_for(settings)
    if client is None:
        with session_scope(app.state.db_factory) as db:
            run = db.get(DiscoveryRun, run_id)
            run.status, run.error, run.finished_at = 'failed', 'no executor is configured (EXPLOIT_EXECUTOR_URL)', utcnow()
            record_audit(db, system_principal(tenant_id), 'discovery.run.failed', run_id, {'error': 'no_executor'})
        return {'run_id': run_id, 'status': 'failed', 'error': 'no_executor'}

    facts: list[dict[str, str]] = []
    captured: list[dict[str, Any]] = []
    for phase in phases:
        try:
            result = await client.run(phase)
        except Unavailable as exc:
            with session_scope(app.state.db_factory) as db:
                run = db.get(DiscoveryRun, run_id)
                run.status, run.error, run.finished_at = 'failed', str(exc)[:500], utcnow()
                record_audit(db, system_principal(tenant_id), 'discovery.run.failed', run_id, {'error': 'executor'})
            return {'run_id': run_id, 'status': 'failed', 'error': 'executor'}
        facts.extend(parse_discoveries(result.stdout))
        captured.extend(parse_requests(result.stdout))

    deduped: list[dict[str, str]] = []
    seen_facts: set[tuple[str, str]] = set()
    for fact in facts:
        key = (fact['kind'], fact['value'])
        if key in seen_facts:
            continue
        seen_facts.add(key)
        deduped.append(fact)
    facts = deduped
    created: list[Discovery] = []
    with session_scope(app.state.db_factory) as db:
        run = db.get(DiscoveryRun, run_id)
        principal = system_principal(tenant_id)
        for fact in facts:
            row, is_new = _upsert_fact(db, tenant_id, run.asset_id, run.id, fact)
            if is_new:
                created.append(row)
        stored_captures = 0
        for item in captured[: max(1, int(settings.discovery_max_requests))]:
            if _upsert_request(db, tenant_id, run.asset_id, run.id, run.scope_id, item):
                stored_captures += 1
        run.discovery_count = len(facts)
        run.status, run.finished_at = 'completed', utcnow()
        record_audit(db, principal, 'discovery.run.completed', run.id,
                     {'asset_id': run.asset_id, 'facts': len(facts), 'new': len(created), 'captures': stored_captures})
        new_facts = [(row.id, row.value) for row in created if row.kind == 'endpoint'][:follow_up_limit]
        asset_id, scope_id = run.asset_id, run.scope_id

    follow_ups = 0
    for discovery_id, endpoint in new_facts:
        try:
            launched = await launcher(app, system_principal(tenant_id), asset_id=asset_id, scope_id=scope_id,
                                      adapter_name='nuclei', triggered_by='discovery')
        except Exception as exc:  # noqa: BLE001 - a follow-up failure must not fail the pass
            log.warning('discovery follow-up for %s failed: %s', endpoint, exc)
            continue
        follow_ups += 1
        with session_scope(app.state.db_factory) as db:
            row = db.get(Discovery, discovery_id)
            if row is not None:
                row.status = 'queued_for_test'
                row.test_run_id = str(launched.get('id') or '')
            record_audit(db, system_principal(tenant_id), 'discovery.followup.queued', discovery_id,
                         {'endpoint': endpoint, 'test_run_id': str(launched.get('id') or '')})

    with session_scope(app.state.db_factory) as db:
        run = db.get(DiscoveryRun, run_id)
        run.follow_up_count = follow_ups
    return {'run_id': run_id, 'status': 'completed', 'discoveries': len(facts), 'follow_ups': follow_ups}


def run_to_dict(run: DiscoveryRun) -> dict[str, Any]:
    return {'id': run.id, 'asset_id': run.asset_id, 'scope_id': run.scope_id, 'status': run.status,
            'discovery_count': run.discovery_count, 'follow_up_count': run.follow_up_count,
            'error': run.error, 'job_id': run.job_id, 'created_at': run.created_at,
            'started_at': run.started_at, 'finished_at': run.finished_at}


def fact_to_dict(row: Discovery) -> dict[str, Any]:
    return {'id': row.id, 'asset_id': row.asset_id, 'run_id': row.run_id, 'kind': row.kind, 'value': row.value,
            'source': row.source, 'confidence': row.confidence, 'status': row.status,
            'test_run_id': row.test_run_id, 'first_seen': row.first_seen, 'last_seen': row.last_seen}


def parse_requests(text: str) -> list[dict[str, Any]]:
    """Requests the browser reported, deduped by method+path. Invalid lines are skipped."""
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for line in (text or '').splitlines():
        stripped = line.strip()
        if not stripped.startswith(REQUEST_MARKER):
            continue
        try:
            item = json.loads(stripped[len(REQUEST_MARKER):])
        except ValueError:
            continue
        if not isinstance(item, dict):
            continue
        method = str(item.get('method') or 'GET').upper()[:8]
        path = str(item.get('path') or '')
        if not path.startswith('/') or len(path) > 500 or (method, path) in seen:
            continue
        seen.add((method, path))
        rows.append({'method': method, 'path': path, 'status': int(item.get('status') or 0),
                     'content_type': str(item.get('content_type') or '')[:120],
                     'has_auth': bool(item.get('has_auth'))})
    return rows


def _upsert_request(db, tenant_id: str, asset_id: str, run_id: str, scope_id: str, item: dict[str, Any]) -> bool:
    row = db.execute(select(RequestCapture).where(RequestCapture.tenant_id == tenant_id,
                                                  RequestCapture.asset_id == asset_id,
                                                  RequestCapture.method == item['method'],
                                                  RequestCapture.path == item['path'])).scalar_one_or_none()
    if row is not None:
        row.run_id, row.status, row.last_seen = run_id, item['status'], utcnow()
        return False
    db.add(RequestCapture(tenant_id=tenant_id, asset_id=asset_id, run_id=run_id, scope_id=scope_id,
                          method=item['method'], path=item['path'], status=item['status'],
                          content_type=item['content_type'], has_auth=item['has_auth']))
    db.flush()
    return True


class ReplayAdapter:
    """Pseudo-adapter for the replay scope check (tier active)."""

    name = 'replay'
    tier = 'active'
    target_kinds = ('web',)
    description = 'Replay one captured request against its asset.'


SAFE_METHODS = {'GET', 'HEAD'}


async def replay(app, principal: Principal, capture_id: str) -> dict[str, Any]:
    """Re-issue one captured request. GET/HEAD only, same origin, scope re-checked, body never returned."""
    settings = app.state.settings
    with session_scope(app.state.db_factory) as db:
        capture = db.execute(select(RequestCapture).where(RequestCapture.id == capture_id,
                                                          RequestCapture.tenant_id == principal.tenant_id)).scalar_one_or_none()
        if capture is None:
            raise NotFound('captured request not found')
        asset = db.get(Asset, capture.asset_id)
        scope = db.get(TestScope, capture.scope_id)
        authorization = db.execute(
            select(AssetAuthorization).where(AssetAuthorization.tenant_id == principal.tenant_id,
                                             AssetAuthorization.asset_id == capture.asset_id,
                                             AssetAuthorization.revoked_at.is_(None))
            .order_by(AssetAuthorization.created_at.desc())).scalars().first()
        target = scope_module.check(ReplayAdapter(), asset, scope, authorization, utcnow(), settings, tier='active')
        method = capture.method if capture.method in SAFE_METHODS else 'GET'
        path = capture.path if capture.path.startswith('/') and '..' not in capture.path else '/'
        record_audit(db, principal, 'discovery.request.replayed', capture.id,
                     {'asset_id': capture.asset_id, 'method': method, 'path': path})

    async with httpx.AsyncClient(base_url=target, timeout=httpx.Timeout(15.0), follow_redirects=False,
                                 trust_env=False, verify=True) as client:
        response = await client.request(method, path)
    return {'id': capture_id, 'method': method, 'path': path, 'status': response.status_code,
            'bytes': len(response.content), 'content_type': response.headers.get('content-type', '')[:120]}


def capture_to_dict(row: RequestCapture) -> dict[str, Any]:
    return {'id': row.id, 'asset_id': row.asset_id, 'run_id': row.run_id, 'method': row.method,
            'path': row.path, 'status': row.status, 'content_type': row.content_type,
            'has_auth': bool(row.has_auth), 'first_seen': row.first_seen, 'last_seen': row.last_seen}
