"""Shadow-AI rule: AI services seen in telemetry that nobody has reviewed, or that the tenant has
blocked. Reads the AI-usage inventory maintained by app.ai.discovery (the `ai.discover` job)."""
from __future__ import annotations

from collections import defaultdict

from sqlalchemy import select

from ...models.ai import AIService
from ..engine import DetectionDraft, DetectionRule, RuleContext, registry
from ..util import aware, iso, sample, window_bucket


class UnsanctionedAIService(DetectionRule):
    id = 'agentic.unsanctioned_ai_service'
    name = 'Unsanctioned AI service in use'
    severity = 'medium'
    category = 'agentic'
    description = ('An AI service that has not been reviewed, or that the tenant has blocked, was used: traffic to a model API or AI '
                   'assistant, a managed model API call in a cloud account, or an OAuth grant to an AI application. Data sent there '
                   'leaves the organization outside any agreed controls.')
    remediation = ('Review the service in the AI inventory (PATCH /api/v1/ai/services/{id}): sanction it, or block it and move users to '
                   'the Argus AI gateway; revoke OAuth grants to blocked AI apps.')
    default_params = {'bucket_minutes': 1440, 'include_unreviewed': True, 'ignore_services': [], 'min_events': 1}

    def evaluate(self, ctx: RuleContext) -> list[DetectionDraft]:
        statuses = ['blocked'] + (['unreviewed'] if ctx.param('include_unreviewed', True) else [])
        ignore = set(ctx.param('ignore_services', []))
        min_events = int(ctx.param('min_events', 1))
        rows = ctx.db.execute(select(AIService).where(AIService.tenant_id == ctx.tenant_id, AIService.status.in_(statuses),
                                                      AIService.channel != 'gateway', AIService.last_seen_at >= ctx.since,
                                                      AIService.last_seen_at <= ctx.horizon)
                              .order_by(AIService.last_seen_at.asc()).limit(ctx.max_events)).scalars().all()
        groups: dict[tuple[str, str, str], list[AIService]] = defaultdict(list)
        for row in rows:
            if row.service_key in ignore or (row.event_count or 0) < min_events:
                continue
            groups[(row.service_key, row.channel, row.status)].append(row)
        drafts: list[DetectionDraft] = []
        for (key, channel, status), items in groups.items():
            first = min(aware(r.first_seen_at) for r in items)
            last = max(aware(r.last_seen_at) for r in items)
            name = items[0].service
            if status == 'blocked':
                severity, confidence = 'high', 0.9
            elif channel == 'oauth_app':
                severity, confidence = 'medium', 0.8
            elif channel == 'cloud_api':
                severity, confidence = 'medium', 0.85
            else:
                severity, confidence = 'low', 0.7
            actors = sample(r.actor for r in items if r.actor)
            how = {'network': 'network traffic to', 'cloud_api': 'cloud API calls to', 'oauth_app': 'an OAuth grant to'}.get(channel, 'use of')
            drafts.append(DetectionDraft(
                rule_id=self.id, severity=severity, confidence=confidence,
                title=f'{"Blocked" if status == "blocked" else "Unreviewed"} AI service in use: {name} ({channel})',
                description=(f'{len(items)} actor(s) showed {how} {name} ({items[0].provider}) between {iso(first)} and {iso(last)}. '
                             f'The service is {status} in the AI inventory.'),
                entity=name, entity_kind='service', fingerprint_parts=[key, channel, status],
                window_bucket=window_bucket(last, int(ctx.param('bucket_minutes', 1440))),  # type: ignore[arg-type]
                first_seen_at=first, last_seen_at=last, asset_id=next((r.asset_id for r in items if r.asset_id), None),
                tags=['shadow_ai', channel, status],
                evidence={'service_key': key, 'service': name, 'provider': items[0].provider, 'channel': channel, 'status': status,
                          'actors': actors, 'actor_count': len(items), 'events': sum(r.event_count or 0 for r in items),
                          'evidence': sample(r.evidence for r in items if r.evidence), 'inventory_ids': [r.id for r in items[:25]]}))
        return drafts


registry.register(UnsanctionedAIService())
