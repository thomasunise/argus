"""Swarm rules: coordinated behaviour across many identities, or one identity moving faster and
wider than a human operator can."""
from __future__ import annotations

from bisect import bisect_right
from collections import defaultdict

from sqlalchemy import select

from ...models import Asset, SecurityEvent
from ..engine import DetectionDraft, DetectionRule, RuleContext, registry
from ..util import (entity_class, epoch, event_ids, event_time, gaps_ms, iso, median, sample, scale_confidence, span, window_bucket)


def _by_actor(events: list[SecurityEvent]) -> dict[str, list[SecurityEvent]]:
    grouped: dict[str, list[SecurityEvent]] = defaultdict(list)
    for event in events:
        if event.actor:
            grouped[event.actor].append(event)
    return grouped


def _baseline_says_normal(ctx: RuleContext, dimension: str, key: str, value: float) -> tuple[bool, dict]:
    """True when a mature baseline covers `value` within `baseline_sigma` standard deviations."""
    baseline = ctx.baseline(dimension, key)
    if baseline is None:
        return False, {}
    detail = {'baseline_mean': round(baseline.mean, 3), 'baseline_stddev': round(baseline.variance ** 0.5, 3), 'baseline_samples': baseline.samples}
    if baseline.samples < int(ctx.param('baseline_min_samples', 10)):
        return False, detail
    normal = value <= baseline.mean + float(ctx.param('baseline_sigma', 3.0)) * (baseline.variance ** 0.5)
    return normal, detail


class CoordinatedIdentityFanout(DetectionRule):
    id = 'swarm.coordinated_identity_fanout'
    name = 'Coordinated identity fan-out'
    severity = 'high'
    category = 'swarm'
    description = ('Many distinct identities performed the same action against the same class of entity inside a short window, '
                   'and the action volume is above its baseline. This is the signature of a swarm sharing a playbook.')
    remediation = 'Confirm whether the identities belong to one automation. If not, suspend the sessions and rotate shared credentials.'
    default_params = {'window_minutes': 5, 'min_actors': 10, 'baseline_min_samples': 10, 'baseline_sigma': 3.0, 'ignore_actions': []}

    def evaluate(self, ctx: RuleContext) -> list[DetectionDraft]:
        window = int(ctx.param('window_minutes', 5))
        min_actors = int(ctx.param('min_actors', 10))
        ignored = set(ctx.param('ignore_actions', []) or [])
        groups: dict[tuple[str, str], list[SecurityEvent]] = defaultdict(list)
        for event in ctx.events():
            if event.actor and event.action and event.action not in ignored:
                groups[(event.action, entity_class(event))].append(event)
        drafts: list[DetectionDraft] = []
        for (action, eclass), items in groups.items():
            times = [epoch(event_time(e)) for e in items]
            i = 0
            while i < len(items):
                end = bisect_right(times, times[i] + window * 60)
                chunk = items[i:end]
                actors = {e.actor for e in chunk}
                if len(actors) < min_actors:
                    i += 1
                    continue
                normal, detail = _baseline_says_normal(ctx, 'action_rate', action, float(len(chunk)))
                if normal:
                    i = end
                    continue
                first, last = span(chunk)
                drafts.append(DetectionDraft(
                    rule_id=self.id, title=f'{len(actors)} identities performed {action} on {eclass} within {window} min',
                    description=(f'{len(actors)} distinct actors executed `{action}` against {eclass} entities between {iso(first)} and '
                                 f'{iso(last)} ({len(chunk)} events). Coordinated fan-out across identities is how swarms parallelize access.'),
                    severity='critical' if len(actors) >= 3 * min_actors else self.severity,
                    confidence=scale_confidence(len(actors), min_actors, base=0.65), entity=f'{action} on {eclass}', entity_kind='action',
                    fingerprint_parts=[action, eclass], window_bucket=window_bucket(first, window), first_seen_at=first, last_seen_at=last,
                    evidence={'action': action, 'entity_class': eclass, 'distinct_actors': len(actors), 'events': len(chunk),
                              'window_minutes': window, 'window_start': iso(first), 'window_end': iso(last),
                              'actors_sample': sample(sorted(actors)), 'entities_sample': sample(e.entity for e in chunk),
                              'event_ids': event_ids(chunk), **detail}))
                i = end
        return drafts


class NovelActionBurst(DetectionRule):
    id = 'swarm.novel_action_burst'
    name = 'Novel action burst'
    severity = 'high'
    category = 'swarm'
    description = ('An identity performed several actions it had never performed before, all inside a short window. Humans learn a '
                   'system gradually; an agent enumerating capabilities does not.')
    remediation = 'Review the new actions against the identity\'s role. Revoke the session and tighten the permission set if unexplained.'
    default_params = {'window_minutes': 10, 'min_novel_actions': 5, 'history_days': 30, 'baseline_min_samples': 10, 'baseline_sigma': 3.0}

    def evaluate(self, ctx: RuleContext) -> list[DetectionDraft]:
        window = int(ctx.param('window_minutes', 10))
        min_novel = int(ctx.param('min_novel_actions', 5))
        events = [e for e in ctx.events() if e.actor and e.action]
        if not events:
            return []
        seen = ctx.seen_pairs(SecurityEvent.actor, SecurityEvent.action, before=ctx.since, lookback_days=int(ctx.param('history_days', 30)))
        drafts: list[DetectionDraft] = []
        for actor, items in _by_actor(events).items():
            novel: list[SecurityEvent] = []
            for event in items:
                if (actor, event.action) not in seen:
                    seen.add((actor, event.action))
                    novel.append(event)
            if len(novel) < min_novel:
                continue
            times = [epoch(event_time(e)) for e in novel]
            i = 0
            while i < len(novel):
                end = bisect_right(times, times[i] + window * 60)
                count = end - i
                if count < min_novel:
                    i += 1
                    continue
                normal, detail = _baseline_says_normal(ctx, 'actor_novel_actions', actor, float(count))
                if normal:
                    i = end
                    continue
                chunk = novel[i:end]
                first, last = span(chunk)
                drafts.append(DetectionDraft(
                    rule_id=self.id, title=f'{actor} performed {count} never-before-seen actions in {window} min',
                    description=(f'`{actor}` executed {count} actions with no prior history for this identity in the last '
                                 f'{ctx.param("history_days", 30)} days, between {iso(first)} and {iso(last)}.'),
                    severity='critical' if count >= 3 * min_novel else self.severity, confidence=scale_confidence(count, min_novel, base=0.6),
                    entity=actor, entity_kind='identity', fingerprint_parts=[actor], window_bucket=window_bucket(first, window),
                    first_seen_at=first, last_seen_at=last,
                    evidence={'actor': actor, 'novel_actions': count, 'actions_sample': sample(e.action for e in chunk), 'window_minutes': window,
                              'window_start': iso(first), 'window_end': iso(last), 'event_ids': event_ids(chunk), **detail}))
                i = end
        return drafts


class SynchronizedMultiAssetAccess(DetectionRule):
    id = 'swarm.synchronized_multi_asset_access'
    name = 'Synchronized multi-asset access'
    severity = 'high'
    category = 'swarm'
    description = ('One identity touched many assets of different kinds within seconds of each other, with sub-second gaps between '
                   'events. Lateral movement at that pace is scripted, not interactive.')
    remediation = 'Verify the identity is an approved automation. Otherwise disable it and review every asset it touched.'
    default_params = {'window_seconds': 60, 'min_assets': 5, 'min_kinds': 2, 'max_median_gap_ms': 1000}

    def evaluate(self, ctx: RuleContext) -> list[DetectionDraft]:
        window_s = float(ctx.param('window_seconds', 60))
        min_assets = int(ctx.param('min_assets', 5))
        min_kinds = int(ctx.param('min_kinds', 2))
        max_gap = float(ctx.param('max_median_gap_ms', 1000))
        events = [e for e in ctx.events() if e.actor and (e.asset_id or e.entity)]
        if not events:
            return []
        asset_ids = sorted({e.asset_id for e in events if e.asset_id})
        kinds: dict[str, str] = {}
        for start in range(0, len(asset_ids), 500):
            chunk = asset_ids[start:start + 500]
            for asset_id, kind in ctx.db.execute(select(Asset.id, Asset.kind).where(Asset.tenant_id == ctx.tenant_id, Asset.id.in_(chunk))).all():
                kinds[asset_id] = kind

        def key_and_kind(event: SecurityEvent) -> tuple[str, str]:
            if event.asset_id and event.asset_id in kinds:
                return event.asset_id, kinds[event.asset_id]
            return event.entity or event.asset_id or '', entity_class(event)

        drafts: list[DetectionDraft] = []
        for actor, items in _by_actor(events).items():
            times = [epoch(event_time(e)) for e in items]
            i = 0
            while i < len(items):
                end = bisect_right(times, times[i] + window_s)
                chunk = items[i:end]
                if len(chunk) < min_assets:
                    i += 1
                    continue
                keyed = [key_and_kind(e) for e in chunk]
                assets = {k for k, _ in keyed}
                asset_kinds = {kind for _, kind in keyed}
                med = median(gaps_ms(times[i:end]))
                if len(assets) < min_assets or len(asset_kinds) < min_kinds or med >= max_gap:
                    i += 1
                    continue
                first, last = span(chunk)
                drafts.append(DetectionDraft(
                    rule_id=self.id, title=f'{actor} accessed {len(assets)} assets across {len(asset_kinds)} kinds in {int(window_s)}s',
                    description=(f'`{actor}` touched {len(assets)} distinct assets spanning {", ".join(sorted(asset_kinds))} with a median gap of '
                                 f'{med:.0f} ms between events ({iso(first)} to {iso(last)}).'),
                    severity='critical' if len(assets) >= 3 * min_assets else self.severity,
                    confidence=scale_confidence(len(assets), min_assets, base=0.65), entity=actor, entity_kind='identity',
                    fingerprint_parts=[actor], window_bucket=window_bucket(first, max(1, int(window_s // 60) or 1)), first_seen_at=first,
                    last_seen_at=last,
                    evidence={'actor': actor, 'distinct_assets': len(assets), 'asset_kinds': sorted(asset_kinds), 'median_gap_ms': round(med, 1),
                              'events': len(chunk), 'window_seconds': window_s, 'window_start': iso(first), 'window_end': iso(last),
                              'assets_sample': sample(k for k, _ in keyed), 'event_ids': event_ids(chunk)}))
                i = end
        return drafts


class MachineSpeedSequence(DetectionRule):
    id = 'swarm.machine_speed_sequence'
    name = 'Machine-speed action sequence'
    severity = 'high'
    category = 'swarm'
    description = ('A single identity emitted a long run of events with a median inter-arrival time under half a second. '
                   'No interactive user sustains that cadence.')
    remediation = 'Confirm the identity is a registered service account with an expected request rate; otherwise block it and investigate.'
    default_params = {'min_events': 20, 'max_median_gap_ms': 500, 'ignore_actor_prefixes': []}

    def evaluate(self, ctx: RuleContext) -> list[DetectionDraft]:
        min_events = max(3, int(ctx.param('min_events', 20)))
        max_gap = float(ctx.param('max_median_gap_ms', 500))
        prefixes = tuple(ctx.param('ignore_actor_prefixes', []) or [])
        events = [e for e in ctx.events() if e.actor and not (prefixes and e.actor.startswith(prefixes))]
        drafts: list[DetectionDraft] = []
        for actor, items in _by_actor(events).items():
            if len(items) < min_events:
                continue
            times = [epoch(event_time(e)) for e in items]
            gaps = gaps_ms(times)
            i = 0
            while i + min_events <= len(items):
                seed = gaps[i:i + min_events - 1]
                med = median(seed)
                if med >= max_gap:
                    i += 1
                    continue
                j = i + min_events
                while j < len(items) and gaps[j - 1] <= 2 * max_gap:
                    j += 1
                chunk = items[i:j]
                run_gaps = gaps[i:j - 1]
                med = median(run_gaps)
                first, last = span(chunk)
                drafts.append(DetectionDraft(
                    rule_id=self.id, title=f'{actor} issued {len(chunk)} events at a median gap of {med:.0f} ms',
                    description=(f'`{actor}` produced {len(chunk)} events between {iso(first)} and {iso(last)} with median inter-arrival '
                                 f'{med:.0f} ms (minimum {min(run_gaps):.0f} ms).'),
                    severity='critical' if len(chunk) >= 5 * min_events else self.severity,
                    confidence=scale_confidence(max_gap, max(med, 1.0), base=0.65), entity=actor, entity_kind='identity',
                    fingerprint_parts=[actor], window_bucket=window_bucket(first, 10), first_seen_at=first, last_seen_at=last,
                    evidence={'actor': actor, 'events': len(chunk), 'median_gap_ms': round(med, 1), 'min_gap_ms': round(min(run_gaps), 1),
                              'span_seconds': round(times[j - 1] - times[i], 3), 'actions_sample': sample(e.action for e in chunk),
                              'window_start': iso(first), 'window_end': iso(last), 'event_ids': event_ids(chunk)}))
                i = j
        return drafts


registry.register(CoordinatedIdentityFanout())
registry.register(NovelActionBurst())
registry.register(SynchronizedMultiAssetAccess())
registry.register(MachineSpeedSequence())
