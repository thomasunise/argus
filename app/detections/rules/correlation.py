"""Evidence-linked cross-source attack chains, not just per-event rate anomalies."""
from __future__ import annotations

from collections import defaultdict

from ..engine import DetectionDraft, DetectionRule, RuleContext, registry
from ..util import event_ids, event_time, iso, window_bucket


def _stage(event) -> str:
    action = str(event.action or '').lower().replace('_', '.')
    category = str(event.category or '').lower()
    if any(s in action for s in ('grant.permission', 'attach.role', 'add.role', 'assume.role', 'privilege.escalat',
                                 'create.access.key', 'put.user.policy', 'add.member', 'grant.admin')):
        return 'privilege'
    if any(s in action for s in ('export', 'get.object', 'read.secret', 'download', 'dump.database',
                                 'read.database', 'query.data', 'get.secret.value', 'list.secret')):
        return 'data'
    if category == 'network' and any(s in action for s in ('egress', 'upload', 'external', 'transfer', 'exfil')):
        return 'egress'
    if category in {'auth', 'identity'} and any(s in action for s in ('login', 'sign.in', 'authenticate', 'session.create')):
        return 'auth'
    return ''


class CrossSourceAttackChain(DetectionRule):
    id = 'agentic.cross_source_attack_chain'
    name = 'Cross-source credential, privilege and data access chain'
    severity = 'high'
    category = 'agentic'
    description = 'Correlates ordered authentication, privilege, data and egress activity from multiple sources for one identity.'
    remediation = 'Review the correlated evidence, verify the identity and use approved containment if unauthorized.'
    default_params = {'window_minutes': 30, 'min_sources': 2, 'min_stages': 3}

    def evaluate(self, ctx: RuleContext) -> list[DetectionDraft]:
        window = max(1, int(ctx.param('window_minutes', 30)))
        min_sources = max(2, int(ctx.param('min_sources', 2)))
        min_stages = max(3, int(ctx.param('min_stages', 3)))
        by_actor = defaultdict(list)
        for ev in ctx.events():
            if ev.actor and _stage(ev):
                by_actor[ev.actor].append(ev)
        drafts = []
        for actor, events in by_actor.items():
            for index, start in enumerate(events):
                if _stage(start) != 'auth':
                    continue
                horizon = event_time(start).timestamp() + window * 60
                seen = set()
                chain = []
                for ev in events[index:]:
                    if event_time(ev).timestamp() > horizon:
                        break
                    stage = _stage(ev)
                    if stage in seen:
                        continue
                    if not chain and stage != 'auth':
                        continue
                    if stage == 'privilege' and 'auth' not in seen:
                        continue
                    if stage in {'data', 'egress'} and 'privilege' not in seen:
                        continue
                    if stage == 'auth' and seen:
                        continue
                    seen.add(stage)
                    chain.append(ev)
                sources = {e.source for e in chain}
                if len(seen) < min_stages or 'privilege' not in seen or not ({'data', 'egress'} & seen) or len(sources) < min_sources:
                    continue
                stages = [_stage(e) for e in chain]
                drafts.append(DetectionDraft(
                    rule_id=self.id, title=f'{actor} crossed {len(stages)} attack stages across {len(sources)} sources',
                    description=f'Ordered activity for {actor} included {", ".join(stages)} across {", ".join(sorted(sources))}.',
                    severity='critical' if 'egress' in seen else self.severity,
                    confidence=round(min(.96, .7 + .06 * (len(stages) - 3) + .03 * (len(sources) - 2)), 2),
                    entity=actor, entity_kind='identity', fingerprint_parts=[actor],
                    window_bucket=window_bucket(event_time(start), window),
                    first_seen_at=event_time(chain[0]), last_seen_at=event_time(chain[-1]),
                    evidence={'actor': actor, 'sources': sorted(sources), 'stages': stages,
                              'actions': [e.action for e in chain], 'event_ids': event_ids(chain),
                              'window_minutes': window, 'correlation_type': 'ordered_multi_source',
                              'observation_only': True}))
                break
        return drafts


registry.register(CrossSourceAttackChain())
