"""Read-only view of the AI-usage inventory (shadow-AI discovery) and AI gateway activity."""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy import func, select

from ...core.db import scoped
from ...models import utcnow
from ...models.ai import AIGatewayRequest, AIService
from ._common import clamp_limit, serialize
from .registry import ToolContext, registry


@registry.tool('ai_inventory', 'AI services seen in this tenant (shadow-AI discovery): service, provider, channel (network, cloud_api, oauth_app, '
               'gateway), actor, review status and counts, plus AI gateway totals for the last 30 days. Optional status/channel filters.',
               {'properties': {'status': {'type': 'string', 'enum': ['unreviewed', 'sanctioned', 'blocked']},
                               'channel': {'type': 'string', 'enum': ['network', 'cloud_api', 'oauth_app', 'gateway']},
                               'limit': {'type': 'integer'}},
                'required': []}, tags=('ai', 'inventory'))
def ai_inventory(args: dict, ctx: ToolContext) -> dict:
    stmt = scoped(AIService, ctx.principal)
    if args.get('status'):
        stmt = stmt.where(AIService.status == args['status'])
    if args.get('channel'):
        stmt = stmt.where(AIService.channel == args['channel'])
    limit = clamp_limit(args.get('limit'), 50, 200)
    rows = ctx.db.execute(stmt.order_by(AIService.last_seen_at.desc()).limit(limit)).scalars().all()
    since = utcnow() - timedelta(days=30)
    base = (AIGatewayRequest.tenant_id == ctx.principal.tenant_id, AIGatewayRequest.created_at >= since)
    by_status = {k: int(n) for k, n in ctx.db.execute(select(AIGatewayRequest.status, func.count()).where(*base).group_by(AIGatewayRequest.status)).all()}
    return {'count': len(rows),
            'items': [serialize({'id': r.id, 'service': r.service, 'provider': r.provider, 'channel': r.channel, 'actor': r.actor, 'status': r.status,
                                 'event_count': r.event_count, 'first_seen_at': r.first_seen_at, 'last_seen_at': r.last_seen_at, 'evidence': r.evidence})
                      for r in rows],
            'gateway_last_30_days': by_status}
