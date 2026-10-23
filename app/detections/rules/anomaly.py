"""Statistical anomalies against rolling baselines."""
from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from ...models import SecurityEvent
from ..engine import DetectionDraft, DetectionRule, RuleContext, baseline_stddev, registry
from ..util import event_ids, iso, sample, window_bucket

_ENTITY_KIND = {'actor_rate': 'identity', 'source_rate': 'source', 'entity_rate': 'asset', 'action_rate': 'action'}


class RateSpike(DetectionRule):
    id = 'anomaly.rate_spike'
    name = 'Event rate spike'
    severity = 'medium'
    category = 'anomaly'
    description = ('An identity or event source produced far more events in the current window than its own history predicts '
                   '(beyond mean + sigma standard deviations over a mature baseline).')
    remediation = 'Check what the identity or sensor was doing during the spike; throttle or disable it if the burst is not expected.'
    default_params = {'window_minutes': 5, 'sigma': 4.0, 'min_samples': 30, 'min_events': 10, 'dimensions': ['actor_rate', 'source_rate']}

    def evaluate(self, ctx: RuleContext) -> list[DetectionDraft]:
        window = int(ctx.param('window_minutes', 5))
        sigma = float(ctx.param('sigma', 4.0))
        min_samples = int(ctx.param('min_samples', 30))
        min_events = int(ctx.param('min_events', 10))
        dimensions = [d for d in ctx.param('dimensions', []) if d in _ENTITY_KIND]
        window_start = ctx.now - timedelta(minutes=window)
        events = ctx.events(since=max(window_start, ctx.since))
        buckets: dict[str, dict[str, list[SecurityEvent]]] = {d: defaultdict(list) for d in dimensions}
        for event in events:
            for dimension in dimensions:
                key = {'actor_rate': event.actor, 'source_rate': event.source, 'entity_rate': event.entity, 'action_rate': event.action}[dimension]
                if key:
                    buckets[dimension][key].append(event)
        drafts: list[DetectionDraft] = []
        for dimension in dimensions:
            baselines = ctx.baselines(dimension, window)
            for key, items in buckets[dimension].items():
                baseline = baselines.get(key)
                count = len(items)
                if baseline is None or baseline.samples < min_samples or count < min_events:
                    continue
                std = baseline_stddev(baseline)
                threshold = baseline.mean + sigma * std
                if count <= threshold:
                    continue
                z = (count - baseline.mean) / std if std > 0 else float('inf')
                label = 'identity' if dimension == 'actor_rate' else dimension.replace('_rate', '')
                drafts.append(DetectionDraft(
                    rule_id=self.id, title=f'{label} {key} produced {count} events in {window} min (baseline {baseline.mean:.1f} ± {std:.1f})',
                    description=(f'`{key}` emitted {count} events in the last {window} minutes against a baseline mean of {baseline.mean:.2f} '
                                 f'and standard deviation {std:.2f} over {baseline.samples} windows (z = {"inf" if z == float("inf") else f"{z:.1f}"}).'),
                    severity='high' if z >= 2 * sigma else self.severity, confidence=round(min(0.95, 0.6 + 0.035 * min(z, 10.0)), 3),
                    entity=key, entity_kind=_ENTITY_KIND[dimension], fingerprint_parts=[dimension, key],
                    window_bucket=window_bucket(window_start, window), first_seen_at=window_start, last_seen_at=ctx.now,
                    evidence={'dimension': dimension, 'key': key, 'count': count, 'baseline_mean': round(baseline.mean, 3),
                              'baseline_stddev': round(std, 3), 'baseline_samples': baseline.samples, 'threshold': round(threshold, 2),
                              'z_score': None if z == float('inf') else round(z, 2), 'window_minutes': window, 'window_start': iso(window_start),
                              'window_end': iso(ctx.now), 'actions_sample': sample(e.action for e in items), 'event_ids': event_ids(items)}))
        return drafts


registry.register(RateSpike())
