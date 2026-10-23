"""Evidence graph package. `setup(app)` registers the `graph.recompute` queue handler and an
event subscriber that schedules a recompute after collectors apply results."""
from __future__ import annotations

import logging

from ..core import events
from .service import (EdgeDraft, NodeDraft, apply, attack_paths, edge_to_dict, exposure_score, link_asset, neighbors, node_to_dict,  # noqa: F401
                      path_to_dict, query, recompute, stats, upsert_edge, upsert_node)

log = logging.getLogger('sentinel.graph')

RECOMPUTE_DELAY_SECONDS = 2.0


def setup(app) -> None:
    from ..core.db import session_scope
    from ..models import Tenant

    queue = app.state.queue

    @queue.handler('graph.recompute')
    async def recompute_job(job, ctx):
        tenant_id = job.payload.get('tenant_id') or job.tenant_id
        if tenant_id != job.tenant_id:
            raise PermissionError('graph.recompute payload tenant does not match job tenant')
        with session_scope(ctx.db_factory) as db:
            tenant = db.get(Tenant, tenant_id)
            if tenant is None or not tenant.is_active:
                return {'skipped': 'tenant inactive'}
            await ctx.heartbeat()
            result = recompute(db, tenant_id, from_kind=job.payload.get('from_kind', 'exposure'), to_kind=job.payload.get('to_kind', 'data_store'),
                               max_hops=int(job.payload.get('max_hops', 6)), limit=int(job.payload.get('limit', 50)))
        return result

    async def on_graph_applied(topic: str, payload: dict) -> None:
        tenant_id = payload.get('tenant_id')
        if not tenant_id or not queue._running:  # a stopped app (tests) must not schedule work
            return
        try:
            await queue.enqueue('graph.recompute', {'tenant_id': tenant_id}, tenant_id=tenant_id,
                                idempotency_key=f'graph.recompute:{tenant_id}', delay_seconds=RECOMPUTE_DELAY_SECONDS)
        except Exception:
            log.exception('could not schedule graph.recompute for tenant %s', tenant_id)

    events.subscribe('graph.applied', on_graph_applied)
