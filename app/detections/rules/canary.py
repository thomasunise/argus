"""Canary tripwire: any hit on a planted token is a critical detection. There is no legitimate
reason for a canary to be used."""
from __future__ import annotations

from collections import defaultdict

from sqlalchemy import select

from ...models.detections import Canary, CanaryHit
from ..engine import DetectionDraft, DetectionRule, RuleContext, registry
from ..util import aware, iso, sample, window_bucket


class CanaryTripwire(DetectionRule):
    id = 'canary.tripwire'
    name = 'Canary tripwire'
    severity = 'critical'
    category = 'canary'
    description = ('A planted canary token, URL, credential, file or hostname was used. Canaries have no legitimate consumer, so a hit '
                   'means the place it was planted has been read by someone who should not be there.')
    remediation = 'Treat the placement as compromised: identify how the canary was reached, contain that system, and rotate real secrets stored near it.'
    default_params = {'bucket_minutes': 60, 'include_expired': True}

    def evaluate(self, ctx: RuleContext) -> list[DetectionDraft]:
        bucket_minutes = int(ctx.param('bucket_minutes', 60))
        include_expired = bool(ctx.param('include_expired', True))
        rows = ctx.db.execute(select(CanaryHit, Canary).join(Canary, Canary.id == CanaryHit.canary_id)
                              .where(CanaryHit.tenant_id == ctx.tenant_id, Canary.tenant_id == ctx.tenant_id,
                                     CanaryHit.received_at >= ctx.since, CanaryHit.received_at <= ctx.horizon)
                              .order_by(CanaryHit.received_at.asc()).limit(ctx.max_events)).all()
        grouped: dict[str, list[tuple[CanaryHit, Canary]]] = defaultdict(list)
        for hit, canary in rows:
            if not include_expired and canary.expires_at and aware(canary.expires_at) < aware(hit.received_at):  # type: ignore[operator]
                continue
            grouped[canary.id].append((hit, canary))
        drafts: list[DetectionDraft] = []
        for canary_id, items in grouped.items():
            canary = items[0][1]
            hits = [h for h, _ in items]
            first, last = aware(hits[0].received_at), aware(hits[-1].received_at)
            ips = sample(h.source_ip for h in hits)
            drafts.append(DetectionDraft(
                rule_id=self.id, severity=self.severity, confidence=0.95,
                title=f'Canary "{canary.label}" ({canary.kind}) triggered from {ips[0] if ips else "unknown"}',
                description=(f'The {canary.kind} canary "{canary.label}" planted at "{canary.placement or "unspecified"}" received {len(hits)} '
                             f'hit(s) between {iso(first)} and {iso(last)} from {", ".join(ips) or "unknown sources"}.'),
                entity=canary.label, entity_kind='canary', fingerprint_parts=[canary.id], window_bucket=window_bucket(first, bucket_minutes),  # type: ignore[arg-type]
                first_seen_at=first, last_seen_at=last, tags=['canary', canary.kind],
                evidence={'canary_id': canary.id, 'kind': canary.kind, 'label': canary.label, 'placement': canary.placement, 'hits': len(hits),
                          'source_ips': ips, 'user_agents': sample(h.user_agent for h in hits), 'first_hit_at': iso(first), 'last_hit_at': iso(last),
                          'hit_ids': [h.id for h in hits[:25]]}))
        return drafts


registry.register(CanaryTripwire())
