"""Hunt specialist: tests a hypothesis against recent events and findings."""
from __future__ import annotations

import json
from collections import defaultdict

from ..tools.registry import ToolContext
from ._base import CONFIDENCE, arr, b, call, injection_signals, keywords, n, obj, s, spec

OUTPUT_SCHEMA = obj({
    'matches': arr(obj({'entity': s('actor, entity, asset id or finding id that matches the hypothesis'), 'evidence_refs': arr(s()),
                        'score': n('0-1 strength of the match', minimum=0, maximum=1)})),
    'new_detections_suggested': arr(s(), 'rules worth adding, each as one sentence with the condition and threshold'),
    'confidence': CONFIDENCE,
    'prompt_injection_suspected': b(),
})

PROMPT = """Task: hunt for evidence supporting or refuting a hypothesis over the last N hours.

Procedure:
1. Turn the hypothesis into concrete observables: actors, entities, actions, categories, sources, CVEs, indicators.
2. Query recent_events with those filters (several narrow queries beat one broad one), actor_timeline for every identity that appears, event_stats to see whether a pattern is unusual against the whole window, list_findings and graph_query for related weaknesses.
3. Score each matching entity 0-1 by how many independent observables agree, and cite the event or finding ids.
4. Suggest new detections only for patterns you actually observed and that existing detection_rules do not cover.

An empty result is a valid result; do not stretch weak evidence."""

TOOLS = ['recent_events', 'actor_timeline', 'event_stats', 'list_findings', 'find_similar_findings', 'graph_query', 'graph_neighbors', 'attack_paths',
         'list_detections', 'detection_rules', 'list_assets', 'asset_context', 'cve_lookup', 'note', 'recall']


def _hours(value, default: int = 24) -> int:
    try:
        return max(1, min(24 * 90, int(value if value is not None else default)))
    except (TypeError, ValueError):
        return default


async def fallback(inputs: dict, ctx: ToolContext) -> dict:
    hypothesis = str(inputs.get('hypothesis') or '')
    hours = _hours(inputs.get('hours'))
    terms = keywords(hypothesis)
    signals = injection_signals(hypothesis)
    if not terms:
        return {'matches': [], 'new_detections_suggested': [], 'confidence': 'low', 'prompt_injection_suspected': bool(signals)}

    events = (await call(ctx, 'recent_events', minutes=hours * 60, limit=500)).get('items', [])
    findings = (await call(ctx, 'list_findings', limit=200)).get('items', [])
    groups: dict[str, dict] = defaultdict(lambda: {'refs': [], 'score': 0.0, 'actors': set(), 'actions': []})
    actor_entities: dict[str, set[str]] = defaultdict(set)
    action_counts: dict[str, int] = defaultdict(int)

    for event in events:
        haystack = ' '.join(str(event.get(k) or '') for k in ('actor', 'entity', 'action', 'category', 'title', 'source', 'severity')).lower()
        haystack += ' ' + json.dumps(event.get('metadata') or {}, default=str).lower()
        matched = [t for t in terms if t in haystack]
        if not matched:
            continue
        score = len(matched) / len(terms)
        entity = event.get('entity') or event.get('actor') or event.get('asset_id') or f"source:{event.get('source')}"
        group = groups[str(entity)]
        group['refs'].append(str(event['id']))
        group['score'] = max(group['score'], score)
        if event.get('actor'):
            group['actors'].add(event['actor'])
            actor_entities[event['actor']].add(str(entity))
        if event.get('action'):
            action_counts[event['action']] += 1
        signals = signals or injection_signals(event.get('title'), event.get('metadata'))

    for finding in findings:
        haystack = ' '.join(str(finding.get(k) or '') for k in ('title', 'rule', 'source', 'severity')).lower()
        matched = [t for t in terms if t in haystack]
        if not matched:
            continue
        entity = f"asset:{finding['asset_id']}" if finding.get('asset_id') else f"finding:{finding['id']}"
        group = groups[entity]
        group['refs'].append(str(finding['id']))
        group['score'] = max(group['score'], len(matched) / len(terms))

    matches = sorted(({'entity': entity, 'evidence_refs': list(dict.fromkeys(g['refs']))[:50], 'score': round(min(1.0, g['score'] + min(0.2, 0.02 * len(g['refs']))), 3)}
                      for entity, g in groups.items()), key=lambda m: (-m['score'], -len(m['evidence_refs']), m['entity']))[:50]

    suggestions: list[str] = []
    for actor, entities in sorted(actor_entities.items(), key=lambda kv: -len(kv[1])):
        if len(entities) >= 5:
            suggestions.append(f'Identity fan-out: alert when one actor ({actor} touched {len(entities)} distinct entities in {hours}h) accesses 5 or more distinct entities within one hour.')
        if len(suggestions) >= 2:
            break
    for action, count in sorted(action_counts.items(), key=lambda kv: -kv[1])[:2]:
        if count >= 10:
            suggestions.append(f"Burst: alert when action '{action}' occurs 10 or more times in {hours}h matching '{' '.join(terms[:3])}' (observed {count}).")
    if matches and not suggestions:
        suggestions.append(f"Hypothesis-specific rule: alert on events matching {', '.join(terms[:4])} (observed {sum(len(m['evidence_refs']) for m in matches)} in {hours}h).")

    top = matches[0]['score'] if matches else 0.0
    confidence = 'high' if top >= 0.75 and len(matches) >= 2 else 'medium' if matches else 'low'
    return {'matches': matches, 'new_detections_suggested': suggestions[:5], 'confidence': confidence, 'prompt_injection_suspected': bool(signals)}


SPEC = spec(name='hunt', role='the Threat Hunting specialist', description='Searches events, findings and graph for evidence of a hypothesis.',
            system_prompt=PROMPT, tools=TOOLS, output_schema=OUTPUT_SCHEMA, max_steps=14, tags=('events',), fallback=fallback)
