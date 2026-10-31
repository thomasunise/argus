"""Detection engine: rule registry, evaluation context, fingerprint dedupe, Detection/Finding
upserts and rolling baselines.

A run evaluates every enabled rule for one tenant over the events in `[since, now]`, where
`since` defaults to a fixed lookback. Rules return DetectionDrafts; the engine fingerprints each
draft as sha256(tenant|rule|entity|bucket) so re-evaluating the same window is idempotent.
"""
from __future__ import annotations

import hashlib
import importlib
import logging
import math
import pkgutil
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..core.audit import record_audit
from ..core.events import publish_soon
from ..core.findings import SEVERITIES, severity as normalize_severity, upsert_finding
from ..core.security import redact
from ..core.telemetry import DETECTIONS
from ..models import SecurityEvent, dumps, loads, utcnow
from ..models.detections import Baseline, Detection, DetectionRuleState, DetectionRun
from .util import aware, bucket_start, event_time, window_bucket

log = logging.getLogger('argus.detections')

CATEGORIES = ('swarm', 'identity', 'canary', 'anomaly', 'cloud', 'k8s', 'code', 'agentic', 'industrial')
DEFAULT_LOOKBACK_MINUTES = 60
DEFAULT_MAX_EVENTS = 20_000
MAX_DRAFTS_PER_RULE = 200
EVIDENCE_LIMIT = 6000
BASELINE_WINDOW_MINUTES = 5
BASELINE_MAX_KEYS = 5000
BASELINE_HISTORY_DAYS = 30
CLOCK_SKEW_SECONDS = 300


# ---------------------------------------------------------------- drafts and context


@dataclass
class DetectionDraft:
    rule_id: str
    title: str
    description: str
    severity: str
    confidence: float
    entity: str
    entity_kind: str
    evidence: dict = field(default_factory=dict)
    fingerprint_parts: list[str] = field(default_factory=list)
    window_bucket: str = ''
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None
    asset_id: str | None = None
    tags: list[str] = field(default_factory=list)

    def fingerprint(self, tenant_id: str) -> str:
        entity = '|'.join(self.fingerprint_parts) if self.fingerprint_parts else self.entity
        return hashlib.sha256(f'{tenant_id}|{self.rule_id}|{entity}|{self.window_bucket}'.encode()).hexdigest()


class RuleContext:
    """Everything a rule may touch. Rules read events through `events()` so windows stay bounded."""

    def __init__(self, db: Session, tenant_id: str, since: datetime, now: datetime, params: dict, settings: Any,
                 rule: 'DetectionRule | None' = None, max_events: int = DEFAULT_MAX_EVENTS):
        self.db = db
        self.tenant_id = tenant_id
        self.since = aware(since)  # type: ignore[assignment]
        self.now = aware(now)  # type: ignore[assignment]
        # Query upper bound: a little past `now` so sensor clock skew does not hide the newest events until the next run.
        self.horizon = self.now + timedelta(seconds=CLOCK_SKEW_SECONDS)
        self.params = params
        self.settings = settings
        self.rule = rule
        self.max_events = max_events
        self.events_scanned = 0
        self._baseline_cache: dict[tuple[str, int], dict[str, Baseline]] = {}

    def param(self, name: str, default: Any = None) -> Any:
        return self.params.get(name, default)

    def events(self, since: datetime | None = None, until: datetime | None = None, *, category: str | None = None,
               action: str | None = None, actions: list[str] | set[str] | None = None, actor: str | None = None,
               source: str | None = None, limit: int | None = None) -> list[SecurityEvent]:
        """Events for this tenant whose event time (occurred_at, else received_at) is within [since, until]. Ascending."""
        since = aware(since) or self.since
        until = aware(until) or self.horizon
        when = func.coalesce(SecurityEvent.occurred_at, SecurityEvent.received_at)
        stmt = select(SecurityEvent).where(SecurityEvent.tenant_id == self.tenant_id, when >= since, when <= until)
        if category:
            stmt = stmt.where(SecurityEvent.category == category)
        if action:
            stmt = stmt.where(SecurityEvent.action == action)
        if actions:
            stmt = stmt.where(SecurityEvent.action.in_(list(actions)))
        if actor:
            stmt = stmt.where(SecurityEvent.actor == actor)
        if source:
            stmt = stmt.where(SecurityEvent.source == source)
        cap = max(1, min(limit or self.max_events, self.max_events))
        rows = list(db_scalars(self.db, stmt.order_by(when.asc(), SecurityEvent.received_at.asc()).limit(cap + 1)))
        if len(rows) > cap:
            log.warning('rule %s hit the event cap of %d for tenant %s; results truncated', self.rule.id if self.rule else '?', cap, self.tenant_id)
            rows = rows[:cap]
        self.events_scanned += len(rows)
        return rows

    def seen_pairs(self, column_a, column_b, before: datetime, lookback_days: int) -> set[tuple[str, str]]:
        """Distinct (a, b) pairs for events before `before` inside the lookback. Used for novelty baselines."""
        when = func.coalesce(SecurityEvent.occurred_at, SecurityEvent.received_at)
        start = aware(before) - timedelta(days=max(1, lookback_days))  # type: ignore[operator]
        stmt = (select(column_a, column_b).where(SecurityEvent.tenant_id == self.tenant_id, when >= start, when < aware(before))
                .distinct().limit(200_000))
        return {(a or '', b or '') for a, b in self.db.execute(stmt).all()}

    def baselines(self, dimension: str, window_minutes: int = BASELINE_WINDOW_MINUTES) -> dict[str, Baseline]:
        cache_key = (dimension, window_minutes)
        if cache_key not in self._baseline_cache:
            rows = db_scalars(self.db, select(Baseline).where(Baseline.tenant_id == self.tenant_id, Baseline.dimension == dimension,
                                                               Baseline.window_minutes == window_minutes))
            self._baseline_cache[cache_key] = {b.key: b for b in rows}
        return self._baseline_cache[cache_key]

    def baseline(self, dimension: str, key: str, window_minutes: int = BASELINE_WINDOW_MINUTES) -> Baseline | None:
        return self.baselines(dimension, window_minutes).get(key)

    def graph(self):
        """The graph service module when the graph package is present, else None."""
        try:
            return importlib.import_module('app.graph.service')
        except ImportError:
            return None


def db_scalars(db: Session, stmt):
    return db.execute(stmt).scalars().all()


# ---------------------------------------------------------------- rules and registry


class DetectionRule:
    id: str = ''
    name: str = ''
    severity: str = 'medium'
    description: str = ''
    category: str = 'anomaly'
    default_params: dict = {}
    tags: list[str] = []

    def evaluate(self, ctx: RuleContext) -> list[DetectionDraft]:  # pragma: no cover - interface
        raise NotImplementedError

    def to_dict(self) -> dict:
        return {'id': self.id, 'name': self.name, 'severity': self.severity, 'description': self.description, 'category': self.category,
                'default_params': dict(self.default_params), 'tags': list(self.tags)}


class RuleRegistry:
    def __init__(self):
        self._rules: dict[str, DetectionRule] = {}
        self._loaded = False
        self._lock = threading.Lock()

    def register(self, rule: DetectionRule) -> DetectionRule:
        if not rule.id or '.' not in rule.id:
            raise ValueError(f'rule id must look like <category>.<name>: {rule.id!r}')
        if rule.category not in CATEGORIES:
            raise ValueError(f'unknown rule category {rule.category!r} for {rule.id}')
        self._rules[rule.id] = rule
        return rule

    def ensure_loaded(self) -> None:
        if self._loaded:
            return
        with self._lock:
            if self._loaded:
                return
            from . import rules as rules_pkg

            for module in pkgutil.iter_modules(rules_pkg.__path__):
                if not module.name.startswith('_'):
                    importlib.import_module(f'{rules_pkg.__name__}.{module.name}')
            self._loaded = True

    def get(self, rule_id: str) -> DetectionRule | None:
        self.ensure_loaded()
        return self._rules.get(rule_id)

    def all(self) -> list[DetectionRule]:
        self.ensure_loaded()
        return [self._rules[k] for k in sorted(self._rules)]

    def ids(self) -> list[str]:
        return [r.id for r in self.all()]


registry = RuleRegistry()


# ---------------------------------------------------------------- tenant rule state


def rule_states(db: Session, tenant_id: str) -> dict[str, DetectionRuleState]:
    rows = db_scalars(db, select(DetectionRuleState).where(DetectionRuleState.tenant_id == tenant_id))
    return {r.rule_id: r for r in rows}


def effective_params(rule: DetectionRule, state: DetectionRuleState | None) -> dict:
    params = dict(rule.default_params)
    if state:
        overrides = loads(state.params_json)
        if isinstance(overrides, dict):
            params.update({k: v for k, v in overrides.items() if k in rule.default_params})
    return params


def validate_params(rule: DetectionRule, params: dict) -> dict:
    """Only known keys, with values of the same JSON type as the default. Raises ValueError."""
    cleaned: dict = {}
    for key, value in params.items():
        if key not in rule.default_params:
            raise ValueError(f'unknown parameter {key!r} for rule {rule.id}')
        default = rule.default_params[key]
        if isinstance(default, bool):
            if not isinstance(value, bool):
                raise ValueError(f'parameter {key!r} must be a boolean')
        elif isinstance(default, (int, float)):
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)) or value < 0:
                raise ValueError(f'parameter {key!r} must be a non-negative number')
            value = type(default)(value)
        elif isinstance(default, list):
            if not isinstance(value, list) or len(value) > 200 or not all(isinstance(v, str) and len(v) <= 200 for v in value):
                raise ValueError(f'parameter {key!r} must be a list of short strings')
        elif isinstance(default, str):
            if not isinstance(value, str) or len(value) > 500:
                raise ValueError(f'parameter {key!r} must be a string')
        else:
            raise ValueError(f'parameter {key!r} is not overridable')
        cleaned[key] = value
    return cleaned


# ---------------------------------------------------------------- run


def _bounded_evidence(evidence: dict) -> str:
    def clean(value: Any, depth: int = 0) -> Any:
        if depth > 4:
            return '...'
        if isinstance(value, str):
            return redact(value)[:300]
        if isinstance(value, dict):
            return {str(k)[:60]: clean(v, depth + 1) for k, v in list(value.items())[:40]}
        if isinstance(value, (list, tuple)):
            return [clean(v, depth + 1) for v in list(value)[:50]]
        if isinstance(value, datetime):
            return aware(value).isoformat()  # type: ignore[union-attr]
        return value

    return dumps(clean(evidence), limit=EVIDENCE_LIMIT)


def _severity_rank(value: str) -> int:
    return SEVERITIES.index(normalize_severity(value))


def upsert_detection(db: Session, tenant_id: str, rule: DetectionRule, draft: DetectionDraft) -> tuple[Detection, str]:
    """Returns (detection, outcome) where outcome is created | updated | unchanged | suppressed."""
    fp = draft.fingerprint(tenant_id)
    now = utcnow()
    first_seen = aware(draft.first_seen_at) or now
    last_seen = aware(draft.last_seen_at) or first_seen
    evidence_text = _bounded_evidence(draft.evidence)
    severity_name = normalize_severity(draft.severity or rule.severity)
    confidence = max(0.0, min(1.0, float(draft.confidence)))
    tags = sorted(set(['detection', rule.category, *rule.tags, *draft.tags]))
    existing = db.execute(select(Detection).where(Detection.tenant_id == tenant_id, Detection.fingerprint == fp)).scalar_one_or_none()
    if existing:
        if existing.status == 'false_positive':
            return existing, 'suppressed'
        if existing.evidence_json == evidence_text and existing.severity == severity_name:
            return existing, 'unchanged'
        existing.evidence_json = evidence_text
        existing.occurrences += 1
        existing.last_seen_at = max(aware(existing.last_seen_at) or last_seen, last_seen)  # type: ignore[type-var]
        existing.confidence = max(existing.confidence, confidence)
        if _severity_rank(severity_name) < _severity_rank(existing.severity):
            existing.severity = severity_name
        if existing.status == 'resolved':
            existing.status = 'open'
        existing.updated_at = now
        _link_finding(db, tenant_id, rule, draft, existing, severity_name)
        return existing, 'updated'
    detection = Detection(tenant_id=tenant_id, rule_id=rule.id, fingerprint=fp, title=redact(draft.title)[:240],
                          description=redact(draft.description)[:4000], severity=severity_name, status='open', confidence=confidence,
                          entity=redact(draft.entity)[:200], entity_kind=draft.entity_kind[:32], evidence_json=evidence_text,
                          first_seen_at=first_seen, last_seen_at=last_seen, occurrences=1, tags_json=dumps(tags))
    db.add(detection)
    db.flush()
    _link_finding(db, tenant_id, rule, draft, detection, severity_name)
    DETECTIONS.labels(rule.id, severity_name).inc()
    _graph_link(db, tenant_id, detection)
    publish_soon('detection.created', {'tenant_id': tenant_id, 'detection_id': detection.id, 'rule_id': rule.id, 'severity': severity_name,
                                       'title': detection.title, 'entity': detection.entity, 'entity_kind': detection.entity_kind,
                                       'confidence': confidence, 'finding_id': detection.finding_id})
    return detection, 'created'


def _link_finding(db: Session, tenant_id: str, rule: DetectionRule, draft: DetectionDraft, detection: Detection, severity_name: str) -> None:
    evidence = {'detection_id': detection.id, 'entity': detection.entity, 'entity_kind': detection.entity_kind,
                'confidence': detection.confidence, 'occurrences': detection.occurrences, 'last_seen_at': aware(detection.last_seen_at),
                'summary': {k: v for k, v in draft.evidence.items() if not isinstance(v, (list, dict))}}
    finding, _ = upsert_finding(db, tenant_id, source='detection', rule=rule.id, title=f'{rule.name}: {detection.entity}'[:240],
                                description=rule.description, severity_name=severity_name, asset_id=draft.asset_id,
                                remediation=_remediation(rule), evidence={k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in evidence.items()},
                                detection_id=detection.id, tags=['detection', rule.category])
    detection.finding_id = finding.id


def _remediation(rule: DetectionRule) -> str:
    return getattr(rule, 'remediation', '') or 'Investigate the linked detection evidence, confirm whether the activity is authorized, and contain the entity if not.'


def _graph_link(db: Session, tenant_id: str, detection: Detection) -> None:
    """Best effort: mirror the detection into the evidence graph when that package exists."""
    try:
        from app.graph import service as graph  # type: ignore
    except ImportError:
        return
    try:
        node = graph.upsert_node(db, tenant_id, 'finding', f'detection:{detection.id}',
                                 {'rule_id': detection.rule_id, 'severity': detection.severity, 'title': detection.title}, 'detections')
        kind = {'identity': 'identity', 'asset': 'asset', 'host': 'asset', 'canary': 'canary'}.get(detection.entity_kind)
        if kind and detection.entity:
            subject = graph.upsert_node(db, tenant_id, kind, detection.entity, {}, 'detections')
            graph.upsert_edge(db, tenant_id, subject.id, node.id, 'triggered', {'rule_id': detection.rule_id}, 'detections')
    except Exception:  # the graph is an enrichment, never a dependency
        log.exception('graph link failed for detection %s', detection.id)


def run(db: Session, tenant_id: str, since: datetime | None = None, rule_ids: list[str] | None = None, *, now: datetime | None = None,
        settings: Any = None, trigger: str = 'job') -> dict:
    """Evaluate enabled rules for one tenant. Returns counts; never raises for a single rule failure."""
    registry.ensure_loaded()
    now = aware(now) or utcnow()
    lookback = int(getattr(settings, 'detections_lookback_minutes', DEFAULT_LOOKBACK_MINUTES) or DEFAULT_LOOKBACK_MINUTES)
    since = aware(since) or (now - timedelta(minutes=lookback))
    max_events = int(getattr(settings, 'detections_max_events', DEFAULT_MAX_EVENTS) or DEFAULT_MAX_EVENTS)
    states = rule_states(db, tenant_id)
    wanted = set(rule_ids or [])
    run_row = DetectionRun(tenant_id=tenant_id, trigger=trigger[:24], since=since, started_at=now)
    db.add(run_row)
    db.flush()
    created = updated = unchanged = suppressed = rules_run = scanned = 0
    errors: list[dict] = []
    created_ids: list[str] = []
    started = time.perf_counter()
    for rule in registry.all():
        if wanted and rule.id not in wanted:
            continue
        state = states.get(rule.id)
        if state is not None and not state.enabled:
            continue
        ctx = RuleContext(db, tenant_id, since, now, effective_params(rule, state), settings, rule=rule, max_events=max_events)
        rules_run += 1
        try:
            drafts = list(rule.evaluate(ctx))[:MAX_DRAFTS_PER_RULE]
        except Exception as exc:
            log.exception('rule %s failed for tenant %s', rule.id, tenant_id)
            errors.append({'rule_id': rule.id, 'error': f'{type(exc).__name__}: {exc}'[:300]})
            continue
        scanned += ctx.events_scanned
        seen_fps: set[str] = set()
        for draft in drafts:
            draft.rule_id = rule.id
            fp = draft.fingerprint(tenant_id)
            if fp in seen_fps:
                continue
            seen_fps.add(fp)
            try:
                detection, outcome = upsert_detection(db, tenant_id, rule, draft)
            except Exception as exc:
                log.exception('upsert failed for rule %s', rule.id)
                errors.append({'rule_id': rule.id, 'error': f'{type(exc).__name__}: {exc}'[:300]})
                continue
            if outcome == 'created':
                created += 1
                created_ids.append(detection.id)
            elif outcome == 'updated':
                updated += 1
            elif outcome == 'suppressed':
                suppressed += 1
            else:
                unchanged += 1
    run_row.finished_at = utcnow()
    run_row.rules_run, run_row.detections_created, run_row.detections_updated = rules_run, created, updated
    run_row.events_scanned = scanned
    run_row.errors_json = dumps(errors[:50])
    if created or updated:
        record_audit(db, 'system', 'detections.run', run_row.id, {'created': created, 'updated': updated, 'rules_run': rules_run,
                                                                   'trigger': trigger, 'since': since.isoformat()}, tenant_id=tenant_id)
    db.flush()
    log.info('detections run tenant=%s rules=%d created=%d updated=%d unchanged=%d errors=%d in %.0fms', tenant_id, rules_run, created,
             updated, unchanged, len(errors), (time.perf_counter() - started) * 1000)
    return {'run_id': run_row.id, 'detections_created': created, 'detections_updated': updated, 'detections_unchanged': unchanged,
            'detections_suppressed': suppressed, 'rules_run': rules_run, 'events_scanned': scanned, 'errors': errors,
            'created_ids': created_ids[:100], 'since': since.isoformat(), 'now': now.isoformat()}


# ---------------------------------------------------------------- baselines


def welford_update(mean: float, variance: float, samples: int, value: float) -> tuple[float, float, int]:
    """One step of Welford's online algorithm using population variance (M2 / n)."""
    m2 = variance * samples
    samples += 1
    delta = value - mean
    mean += delta / samples
    m2 += delta * (value - mean)
    return mean, (m2 / samples if samples else 0.0), samples


def baseline_stddev(baseline: Baseline) -> float:
    return math.sqrt(max(0.0, baseline.variance))


def update_baselines(db: Session, tenant_id: str, now: datetime | None = None, *, window_minutes: int = BASELINE_WINDOW_MINUTES,
                     history_days: int = BASELINE_HISTORY_DAYS) -> dict:
    """Fold the most recent complete window into every dimension's rolling stats.

    Keys that already have a baseline but no events in the window record a 0 sample, so idle
    periods count. Idempotent per window: a key already updated for this bucket is skipped.
    """
    now = aware(now) or utcnow()
    window_end = bucket_start(now, window_minutes)
    window_start = window_end - timedelta(minutes=window_minutes)
    when = func.coalesce(SecurityEvent.occurred_at, SecurityEvent.received_at)
    rows = db_scalars(db, select(SecurityEvent).where(SecurityEvent.tenant_id == tenant_id, when >= window_start, when < window_end)
                      .limit(DEFAULT_MAX_EVENTS))
    counts: dict[str, dict[str, float]] = {d: {} for d in ('actor_rate', 'entity_rate', 'action_rate', 'source_rate', 'actor_novel_actions')}
    actor_actions: dict[str, set[str]] = {}
    for event in rows:
        if event.actor:
            counts['actor_rate'][event.actor] = counts['actor_rate'].get(event.actor, 0) + 1
            actor_actions.setdefault(event.actor, set()).add(event.action or '')
        if event.entity:
            counts['entity_rate'][event.entity] = counts['entity_rate'].get(event.entity, 0) + 1
        if event.action:
            counts['action_rate'][event.action] = counts['action_rate'].get(event.action, 0) + 1
        counts['source_rate'][event.source] = counts['source_rate'].get(event.source, 0) + 1
    if actor_actions:
        start = window_start - timedelta(days=history_days)
        seen_stmt = (select(SecurityEvent.actor, SecurityEvent.action).where(SecurityEvent.tenant_id == tenant_id, when >= start,
                                                                             when < window_start, SecurityEvent.actor.in_(list(actor_actions)[:900]))
                     .distinct().limit(200_000))
        seen = {(a, b or '') for a, b in db.execute(seen_stmt).all()}
        for actor, actions in actor_actions.items():
            counts['actor_novel_actions'][actor] = float(len([a for a in actions if (actor, a) not in seen]))
    existing = {(b.dimension, b.key): b for b in db_scalars(db, select(Baseline).where(Baseline.tenant_id == tenant_id,
                                                                                         Baseline.window_minutes == window_minutes))}
    touched = skipped = created = 0
    for dimension, keyed in counts.items():
        keys = set(keyed) | {k for (d, k) in existing if d == dimension}
        for key in sorted(keys)[:BASELINE_MAX_KEYS]:
            value = float(keyed.get(key, 0))
            baseline = existing.get((dimension, key))
            if baseline is None:
                baseline = Baseline(tenant_id=tenant_id, dimension=dimension, key=key[:200], window_minutes=window_minutes, mean=0.0, variance=0.0,
                                    samples=0, last_value=0.0)
                db.add(baseline)
                existing[(dimension, key)] = baseline
                created += 1
            elif baseline.last_bucket_at is not None and aware(baseline.last_bucket_at) >= window_start:  # type: ignore[operator]
                skipped += 1
                continue
            baseline.mean, baseline.variance, baseline.samples = welford_update(baseline.mean, baseline.variance, baseline.samples, value)
            baseline.last_value = value
            baseline.last_bucket_at = window_start
            baseline.updated_at = utcnow()
            touched += 1
    db.flush()
    return {'window_start': window_start.isoformat(), 'window_end': window_end.isoformat(), 'events': len(rows), 'updated': touched,
            'created': created, 'skipped': skipped}


# ---------------------------------------------------------------- serialization


def detection_to_dict(d: Detection) -> dict:
    return {'id': d.id, 'rule_id': d.rule_id, 'fingerprint': d.fingerprint, 'title': d.title, 'description': d.description,
            'severity': d.severity, 'status': d.status, 'confidence': d.confidence, 'entity': d.entity, 'entity_kind': d.entity_kind,
            'evidence': loads(d.evidence_json), 'first_seen_at': d.first_seen_at, 'last_seen_at': d.last_seen_at,
            'occurrences': d.occurrences, 'finding_id': d.finding_id, 'tags': loads(d.tags_json, []), 'created_at': d.created_at,
            'updated_at': d.updated_at}


def baseline_to_dict(b: Baseline) -> dict:
    return {'id': b.id, 'dimension': b.dimension, 'key': b.key, 'window_minutes': b.window_minutes, 'mean': b.mean, 'variance': b.variance,
            'stddev': baseline_stddev(b), 'samples': b.samples, 'last_value': b.last_value, 'last_bucket_at': b.last_bucket_at,
            'updated_at': b.updated_at}


__all__ = ['DetectionRule', 'DetectionDraft', 'RuleContext', 'registry', 'run', 'update_baselines', 'welford_update', 'rule_states',
           'effective_params', 'validate_params', 'detection_to_dict', 'baseline_to_dict', 'upsert_detection', 'baseline_stddev',
           'window_bucket', 'event_time', 'BASELINE_WINDOW_MINUTES']
