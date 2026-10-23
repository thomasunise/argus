"""Legacy Wazuh indexer pull as a queue job (`integrations.wazuh_sync`). Pulls alerts newer than
the last sync (or `lookback_minutes`) over HTTPS with an optional CA bundle and feeds them through
the normal ingest pipeline. Configuration comes from an IntegrationConfig of kind `wazuh`, or from
the legacy WAZUH_* settings when no integration id is given."""
from __future__ import annotations

import asyncio
import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
from sqlalchemy import select

from ..core.config import Settings
from ..core.db import session_scope
from ..core.errors import SentinelError
from ..core.rbac import system_principal
from ..models import Tenant, dumps, loads, utcnow
from ..models.integrations import IntegrationConfig
from .delivery import resolve_secrets
from .ingest import ingest, publish_deferred

log = logging.getLogger('sentinel.integrations.wazuh')

DEFAULT_INDEX = 'wazuh-alerts-*'
DEFAULT_LOOKBACK_MINUTES = 30
DEFAULT_PAGE_SIZE = 200
MAX_PAGES = 10
SCHEDULER_INTERVAL_SECONDS = 60


class WazuhSyncError(SentinelError):
    status = 502
    code = 'wazuh_sync_failed'


def build_query(since: datetime, size: int) -> dict[str, Any]:
    return {'size': size, 'sort': [{'timestamp': {'order': 'asc'}}],
            'query': {'range': {'timestamp': {'gt': since.astimezone(timezone.utc).isoformat()}}},
            '_source': ['id', 'rule', 'agent', 'timestamp', 'data', 'syscheck', 'location', 'decoder', 'GeoLocation', 'full_log']}


async def fetch_alerts(url: str, index: str, auth: tuple[str, str] | None, ca_bundle: str, since: datetime, size: int,
                       settings: Settings | None = None) -> list[dict]:
    if not url.startswith('https://'):
        raise WazuhSyncError('Wazuh indexer URL must use https://')
    if settings is not None:
        from .egress import egress_ok

        denied = egress_ok(url, settings)
        if denied:
            raise WazuhSyncError(f'Wazuh indexer URL refused: {denied}')
    if not re.fullmatch(r'[A-Za-z0-9*_.,-]{1,128}', index):
        raise WazuhSyncError('Wazuh index pattern contains unsupported characters')
    alerts: list[dict] = []
    cursor = since
    async with httpx.AsyncClient(timeout=20, verify=ca_bundle or True, trust_env=False, follow_redirects=False) as client:
        for _ in range(MAX_PAGES):
            try:
                response = await client.post(f'{url.rstrip("/")}/{index}/_search', auth=auth, json=build_query(cursor, size))
                response.raise_for_status()
                hits = response.json().get('hits', {}).get('hits', [])
            except (httpx.HTTPError, ValueError) as exc:
                raise WazuhSyncError(f'Wazuh indexer sync failed: {type(exc).__name__}; verify URL, trust chain and read-only permissions') from exc
            page = [dict(h.get('_source') or {}, id=(h.get('_source') or {}).get('id') or h.get('_id')) for h in hits if isinstance(h, dict)]
            alerts.extend(page)
            if len(page) < size:
                break
            last_ts = page[-1].get('timestamp')
            from .inbound import parse_time

            parsed = parse_time(last_ts)
            if parsed is None or parsed <= cursor:
                break
            cursor = parsed
    return alerts


def _settings_source(settings: Settings) -> dict[str, Any] | None:
    if not settings.wazuh_indexer_url:
        return None
    return {'indexer_url': settings.wazuh_indexer_url, 'index_pattern': DEFAULT_INDEX, 'ca_bundle': settings.wazuh_ca_bundle,
            'lookback_minutes': DEFAULT_LOOKBACK_MINUTES, 'page_size': DEFAULT_PAGE_SIZE,
            '_auth': (settings.wazuh_indexer_user, settings.wazuh_indexer_password) if settings.wazuh_indexer_user else None}


async def run_sync(db_factory, settings: Settings, tenant_id: str, integration_id: str | None, heartbeat=None) -> dict[str, Any]:
    with session_scope(db_factory) as db:
        tenant = db.get(Tenant, tenant_id)
        if not tenant or not tenant.is_active:
            raise PermissionError('tenant is not active')
        integration: IntegrationConfig | None = None
        if integration_id:
            integration = db.get(IntegrationConfig, integration_id)
            if integration is None or integration.tenant_id != tenant_id or integration.kind != 'wazuh':
                raise PermissionError('wazuh integration not found for this tenant')
            if not integration.enabled:
                return {'accepted': 0, 'skipped': 'integration disabled'}
            config = loads(integration.config_json, {})
            secrets = resolve_secrets(loads(integration.secret_refs_json, {}), settings)
            auth = (secrets['username'], secrets.get('password', '')) if secrets.get('username') else None
            state = loads(integration.state_json, {})
        else:
            config = _settings_source(settings)
            if config is None:
                raise WazuhSyncError('No wazuh integration configured (set WAZUH_INDEXER_URL or create an integration of kind wazuh)')
            auth = config.pop('_auth')
            state = {}
        lookback = int(config.get('lookback_minutes') or DEFAULT_LOOKBACK_MINUTES)
        last = state.get('last_sync_at')
        since = datetime.fromisoformat(last) if isinstance(last, str) and last else utcnow() - timedelta(minutes=lookback)
        if since.tzinfo is None:
            since = since.replace(tzinfo=timezone.utc)
        since = max(since, utcnow() - timedelta(days=7))
        url, index, ca_bundle, size = str(config.get('indexer_url') or ''), str(config.get('index_pattern') or DEFAULT_INDEX), str(config.get('ca_bundle') or ''), \
            int(config.get('page_size') or DEFAULT_PAGE_SIZE)
    started = utcnow()
    try:
        alerts = await fetch_alerts(url, index, auth, ca_bundle, since, size, settings)
    except WazuhSyncError as exc:
        with session_scope(db_factory) as db:
            if integration_id:
                row = db.get(IntegrationConfig, integration_id)
                if row:
                    row.last_error = str(exc)[:1000]
        raise
    if heartbeat:
        await heartbeat()

    def _persist():
        """Blocking database work runs in a worker thread so the event loop (shared with request commits) stays free."""
        with session_scope(db_factory) as db:
            result = ingest(db, tenant_id, 'wazuh', alerts, actor=system_principal(tenant_id), api_key_id='', extra={'pull': True}) if alerts else None
            if integration_id:
                row = db.get(IntegrationConfig, integration_id)
                if row:
                    newest = max((a.get('timestamp') for a in alerts if a.get('timestamp')), default=None)
                    from .inbound import parse_time

                    newest_dt = parse_time(newest) if newest else None
                    state = loads(row.state_json, {})
                    state.update({'last_sync_at': (newest_dt or started).isoformat(), 'last_run_at': started.isoformat(), 'last_count': len(alerts)})
                    row.state_json = dumps(state)
                    row.last_error = ''
                    row.last_delivery_at = started
            return result

    result = await asyncio.to_thread(_persist)
    if result is not None:
        await publish_deferred(result)
    stats = result.as_dict() if result else {'source': 'wazuh', 'received': 0, 'accepted': 0, 'duplicates': 0, 'findings': 0, 'errors': []}
    stats['since'] = since.isoformat()
    return stats


def install(app) -> None:
    queue = app.state.queue
    settings: Settings = app.state.settings

    @queue.handler('integrations.wazuh_sync')
    async def wazuh_sync(job, ctx):
        tenant_id = job.payload.get('tenant_id') or job.tenant_id
        if tenant_id != job.tenant_id:
            raise PermissionError('job tenant does not match payload tenant')
        return await run_sync(ctx.db_factory, ctx.settings, tenant_id, job.payload.get('integration_id'), heartbeat=ctx.heartbeat)

    async def _start(app) -> None:
        if settings.app_env == 'test':
            return
        from ..main import spawn

        spawn(app, _scheduler_loop(app))

    app.state.startup_hooks.append(_start)


def due_integrations(db, now: datetime) -> list[tuple[str, str]]:
    """(tenant_id, integration_id) for enabled wazuh integrations whose schedule has elapsed."""
    out: list[tuple[str, str]] = []
    rows = db.execute(select(IntegrationConfig).where(IntegrationConfig.kind == 'wazuh', IntegrationConfig.enabled.is_(True))).scalars().all()
    for row in rows:
        minutes = int((loads(row.config_json, {}) or {}).get('schedule_minutes') or 0)
        if minutes <= 0:
            continue
        last = (loads(row.state_json, {}) or {}).get('last_run_at')
        last_dt = datetime.fromisoformat(last) if isinstance(last, str) and last else None
        if last_dt is not None and last_dt.tzinfo is None:
            last_dt = last_dt.replace(tzinfo=timezone.utc)
        if last_dt is None or now - last_dt >= timedelta(minutes=minutes):
            out.append((row.tenant_id, row.id))
    return out


async def _scheduler_loop(app) -> None:
    queue = app.state.queue
    while True:
        await asyncio.sleep(SCHEDULER_INTERVAL_SECONDS)
        try:
            with session_scope(app.state.db_factory) as db:
                due = due_integrations(db, utcnow())
            for tenant_id, integration_id in due:
                await queue.enqueue('integrations.wazuh_sync', {'integration_id': integration_id}, tenant_id=tenant_id,
                                    idempotency_key=f'wazuh_sync:{integration_id}', priority=7)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception('wazuh scheduler cycle failed')
