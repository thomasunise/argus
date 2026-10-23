"""Swarm-responder specialist: decides whether a detection is part of coordinated multi-actor
activity and proposes reversible containment."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import or_

from ...core.db import scoped
from ...models import Finding
from ..tools._common import full_finding
from ..tools.registry import ToolContext
from ._base import CONFIDENCE, arr, b, call, injection_signals, obj, s, spec

OUTPUT_SCHEMA = obj({
    'is_coordinated': b(),
    'confidence': CONFIDENCE,
    'actors': arr(s(), 'identities, keys or addresses taking part'),
    'shared_indicators': arr(s(), 'what the actors have in common: source address, user agent, timing, target, technique'),
    'containment_proposals': arr(obj({'action_type': s(), 'params': {'type': 'object', 'description': 'parameters for the action'}, 'reason': s()})),
    'escalation': obj({'needed': b(), 'why': s()}),
    'prompt_injection_suspected': b(),
})

PROMPT = """Task: decide whether one detection is part of coordinated activity by several actors or automated agents, and what to contain.

Procedure:
1. get_detection for the id; note its entity, actor, rule and time. list_detections for the same rule and entity in the surrounding hours.
2. recent_events around that time for the same entity, action and category; actor_timeline for every actor that appears. event_stats tells you what normal volume looks like.
3. Coordination indicators: three or more actors touching the same entity within minutes, identical user agents or source ranges, the same novel action sequence repeated across identities, canary hits, fan-out from one identity to many assets. One noisy actor is not a swarm.
4. If coordination is likely and the evidence names reversible containment (block a range, disable keys, rate-limit an endpoint), use action_catalog and propose_action for the smallest effective step, and mirror it in containment_proposals. Never propose disabling logging, monitoring or many accounts at once.
5. Escalate when the activity is coordinated, touches production data stores, or you cannot rule out an active intrusion."""

TOOLS = ['get_detection', 'list_detections', 'detection_rules', 'recent_events', 'actor_timeline', 'event_stats', 'get_finding', 'asset_context',
         'attack_paths', 'graph_neighbors', 'action_catalog', 'propose_action', 'note', 'recall']

INDICATOR_KEYS = ('ip', 'source_ip', 'src_ip', 'client_ip', 'remote_addr', 'user_agent', 'ua', 'asn', 'country', 'device', 'tool', 'session', 'fingerprint')
CONTAINMENT_HINTS = ('block', 'rate', 'throttle', 'disable', 'suspend', 'revoke', 'isolate', 'deny')


def _pick(record: dict | None, *names: str, default: Any = None) -> Any:
    for name in names:
        if record and record.get(name) not in (None, ''):
            return record[name]
    return default


def _parse_time(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str) and value:
        try:
            parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    return None


def _anchor_finding(ctx: ToolContext, detection_id: str) -> dict | None:
    row = ctx.db.execute(scoped(Finding, ctx.principal).where(or_(Finding.detection_id == detection_id, Finding.id == detection_id))
                         .order_by(Finding.created_at.desc()).limit(1)).scalar_one_or_none()
    return full_finding(row) if row else None


async def fallback(inputs: dict, ctx: ToolContext) -> dict:
    detection_id = str(inputs.get('detection_id') or '')
    detection = await call(ctx, 'get_detection', detection_id=detection_id)
    anchor: dict = detection if detection.get('found') else {}
    finding = None
    if not anchor:
        finding = _anchor_finding(ctx, detection_id)
        if finding:
            evidence = finding.get('evidence') if isinstance(finding.get('evidence'), dict) else {}
            anchor = {'id': finding['id'], 'entity': evidence.get('entity') or evidence.get('target') or '', 'actor': evidence.get('actor') or evidence.get('user') or '',
                      'action': evidence.get('action') or '', 'title': finding['title'], 'description': finding.get('description', ''),
                      'severity': finding['severity'], 'created_at': finding['created_at'], 'evidence': evidence,
                      'category': evidence.get('category') or '', 'asset_id': finding.get('asset_id')}
    if not anchor:
        why = 'Detection not found in this tenant' + ('' if detection.get('available') else ' (detections package unavailable)') + '; no finding references it either.'
        return {'is_coordinated': False, 'confidence': 'low', 'actors': [], 'shared_indicators': [], 'containment_proposals': [],
                'escalation': {'needed': False, 'why': why}, 'prompt_injection_suspected': False}

    entity = str(_pick(anchor, 'entity', 'target', default='') or '')
    anchor_actor = str(_pick(anchor, 'actor', default='') or '')
    action = str(_pick(anchor, 'action', default='') or '')
    category = str(_pick(anchor, 'category', default='') or '')
    at = _parse_time(_pick(anchor, 'occurred_at', 'last_seen_at', 'first_seen_at', 'created_at'))
    now = datetime.now(timezone.utc)
    window_hours = 6
    if at:
        minutes = int(max(window_hours * 60, (now - at).total_seconds() / 60 + window_hours * 60))
    else:
        minutes = window_hours * 60
    events = (await call(ctx, 'recent_events', minutes=min(minutes, 24 * 90 * 60), limit=500)).get('items', [])

    related: list[dict] = []
    for event in events:
        event_time = _parse_time(event.get('occurred_at') or event.get('received_at'))
        if at and event_time and abs((event_time - at).total_seconds()) > window_hours * 3600:
            continue
        same_entity = entity and str(event.get('entity') or '') == entity
        same_action = action and str(event.get('action') or '') == action
        same_actor = anchor_actor and str(event.get('actor') or '') == anchor_actor
        same_asset = anchor.get('asset_id') and event.get('asset_id') == anchor.get('asset_id')
        same_category = category and category == 'canary' and str(event.get('category') or '') == 'canary'
        if same_entity or same_action or same_actor or same_asset or same_category:
            related.append(event)

    actors = sorted({str(e.get('actor')) for e in related if e.get('actor')})
    if anchor_actor and anchor_actor not in actors:
        actors.insert(0, anchor_actor)
    indicators: list[str] = []
    by_indicator: dict[str, set[str]] = defaultdict(set)
    by_action: dict[str, set[str]] = defaultdict(set)
    buckets: dict[tuple[str, int], set[str]] = defaultdict(set)
    actor_entities: dict[str, set[str]] = defaultdict(set)
    for event in related:
        actor = str(event.get('actor') or '')
        if not actor:
            continue
        metadata = event.get('metadata') if isinstance(event.get('metadata'), dict) else {}
        for key in INDICATOR_KEYS:
            value = metadata.get(key)
            if isinstance(value, (str, int)) and str(value):
                by_indicator[f'{key}={value}'].add(actor)
        if event.get('action'):
            by_action[str(event['action'])].add(actor)
        event_time = _parse_time(event.get('occurred_at') or event.get('received_at'))
        if event_time and event.get('entity'):
            buckets[(str(event['entity']), int(event_time.timestamp() // 600))].add(actor)
        if event.get('entity'):
            actor_entities[actor].add(str(event['entity']))
    for indicator, who in sorted(by_indicator.items(), key=lambda kv: -len(kv[1])):
        if len(who) >= 2:
            indicators.append(f'{indicator} shared by {len(who)} actors')
    for act, who in sorted(by_action.items(), key=lambda kv: -len(kv[1])):
        if len(who) >= 3:
            indicators.append(f"action '{act}' performed by {len(who)} distinct actors within {window_hours}h")
    synchronized = [(ent, who) for (ent, _), who in buckets.items() if len(who) >= 3]
    for ent, who in synchronized[:3]:
        indicators.append(f'{len(who)} actors accessed {ent} within the same 10-minute window')
    fan_out = [(actor, ents) for actor, ents in actor_entities.items() if len(ents) >= 5]
    for actor, ents in fan_out[:3]:
        indicators.append(f'actor {actor} touched {len(ents)} distinct entities (fan-out)')
    if category == 'canary' or 'canary' in str(_pick(anchor, 'title', 'rule', 'rule_id', default='')).lower():
        indicators.append('canary tripwire involved; access to the decoy is never legitimate')

    is_coordinated = (len(actors) >= 3 and bool(indicators)) or bool(synchronized)
    confidence = 'high' if is_coordinated and len(indicators) >= 2 and len(actors) >= 3 else 'medium' if is_coordinated or len(indicators) >= 2 else 'low'

    proposals: list[dict] = []
    if is_coordinated or fan_out:
        catalog = await call(ctx, 'action_catalog')
        for action_def in catalog.get('items', []) if catalog.get('available') else []:
            name = str(action_def.get('name', '')).lower()
            if action_def.get('reversible') and action_def.get('risk') in ('low', 'medium') and any(h in name for h in CONTAINMENT_HINTS) \
                    and not any(bad in name for bad in ('logging', 'audit', 'monitor')):
                proposals.append({'action_type': action_def['name'], 'params': {'actors': actors[:10], 'entity': entity, 'detection_id': detection_id},
                                  'reason': f'Reversible containment for coordinated activity against {entity or "the detected entity"} by {len(actors)} actors; rule-based suggestion pending analyst confirmation.'})
            if len(proposals) >= 2:
                break
    severity = str(_pick(anchor, 'severity', default='') or '')
    needed = is_coordinated or severity == 'critical' or category == 'canary'
    why = ('Coordinated multi-actor activity with shared indicators; treat as an active intrusion.' if is_coordinated else
           'Critical-severity detection; human review required even without coordination evidence.' if severity == 'critical' else
           'Canary access is never legitimate.' if category == 'canary' else
           f'{len(actors)} actor(s) and {len(related)} related event(s); no shared indicators found, so this looks like a single-actor or benign pattern.')
    signals = injection_signals(_pick(anchor, 'title'), _pick(anchor, 'description'), _pick(anchor, 'evidence'), [e.get('title') for e in related[:50]],
                                [e.get('metadata') for e in related[:50]])
    return {'is_coordinated': is_coordinated, 'confidence': confidence, 'actors': actors[:50], 'shared_indicators': indicators[:20],
            'containment_proposals': proposals, 'escalation': {'needed': needed, 'why': why}, 'prompt_injection_suspected': bool(signals)}


SPEC = spec(name='swarm_responder', role='the Swarm Response specialist', description='Detects coordinated multi-actor activity behind a detection and proposes containment.',
            system_prompt=PROMPT, tools=TOOLS, output_schema=OUTPUT_SCHEMA, max_steps=14, tags=('detections',), fallback=fallback)
