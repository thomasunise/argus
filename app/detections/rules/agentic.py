"""Agentic rules: automated clients driving APIs far more broadly than any single tool should."""
from __future__ import annotations

from bisect import bisect_right
from collections import defaultdict

from ...models import SecurityEvent
from ..engine import DetectionDraft, DetectionRule, RuleContext, registry
from ..util import epoch, event_ids, event_time, iso, meta, sample, scale_confidence, service_of, span, user_agent, window_bucket


class ToolAbusePattern(DetectionRule):
    id = 'agentic.tool_abuse_pattern'
    name = 'Automated client tool abuse'
    severity = 'high'
    category = 'agentic'
    description = ('An automated client (library user agent or agent headers) exercised dozens of distinct API actions across several '
                   'services in minutes. That breadth is an agent exploring what a credential can do, not an application doing its job.')
    remediation = 'Identify the credential behind the client, confirm it maps to a sanctioned agent with a scoped tool set, and revoke it otherwise.'
    default_params = {'window_minutes': 10, 'min_actions': 50, 'min_services': 3,
                      'automated_markers': ['python-requests', 'python-urllib', 'curl/', 'go-http-client', 'axios', 'aiohttp', 'okhttp', 'httpx',
                                            'node-fetch', 'libwww', 'java/', 'powershell', 'wget', 'botocore', 'aws-sdk', 'azure-sdk', 'google-api'],
                      'agent_header_keys': ['agent', 'x-agent', 'x-agent-id', 'x-agent-name', 'agent_id', 'agent_name', 'automation', 'x-automation']}

    def evaluate(self, ctx: RuleContext) -> list[DetectionDraft]:
        window = int(ctx.param('window_minutes', 10))
        min_actions = int(ctx.param('min_actions', 50))
        min_services = int(ctx.param('min_services', 3))
        markers = [m.lower() for m in ctx.param('automated_markers', [])]
        agent_keys = {k.lower() for k in ctx.param('agent_header_keys', [])}
        by_actor: dict[str, list[SecurityEvent]] = defaultdict(list)
        for event in ctx.events():
            if event.actor and event.action:
                by_actor[event.actor].append(event)
        drafts: list[DetectionDraft] = []
        for actor, items in by_actor.items():
            if len(items) < min_actions:
                continue
            times = [epoch(event_time(e)) for e in items]
            automated = [self._automated(e, markers, agent_keys) for e in items]
            i = 0
            while i < len(items):
                end = bisect_right(times, times[i] + window * 60)
                if end - i < min_actions:
                    i += 1
                    continue
                chunk = items[i:end]
                actions = {e.action for e in chunk}
                services = {service_of(e) for e in chunk}
                auto_count = sum(1 for flag in automated[i:end] if flag)
                if len(actions) < min_actions or len(services) < min_services or auto_count == 0:
                    i += 1
                    continue
                first, last = span(chunk)
                drafts.append(DetectionDraft(
                    rule_id=self.id, title=f'Automated client {actor} used {len(actions)} API actions across {len(services)} services in {window} min',
                    description=(f'`{actor}` was identified as an automated client on {auto_count} of {len(chunk)} events and exercised {len(actions)} '
                                 f'distinct actions across {", ".join(sorted(services))} between {iso(first)} and {iso(last)}.'),
                    severity='critical' if len(actions) >= 2 * min_actions else self.severity,
                    confidence=scale_confidence(len(actions), min_actions, base=0.7), entity=actor, entity_kind='identity', fingerprint_parts=[actor],
                    window_bucket=window_bucket(first, window), first_seen_at=first, last_seen_at=last,
                    evidence={'actor': actor, 'distinct_actions': len(actions), 'services': sorted(services)[:20], 'events': len(chunk),
                              'automated_events': auto_count, 'user_agents': sample(user_agent(e) for e in chunk), 'window_minutes': window,
                              'window_start': iso(first), 'window_end': iso(last), 'actions_sample': sample(sorted(actions)), 'event_ids': event_ids(chunk)}))
                i = end
        return drafts

    @staticmethod
    def _automated(event: SecurityEvent, markers: list[str], agent_keys: set[str]) -> bool:
        ua = user_agent(event).lower()
        if ua and any(m in ua for m in markers):
            return True
        data = meta(event)
        keys = {str(k).lower() for k in data}
        headers = data.get('headers') if isinstance(data.get('headers'), dict) else {}
        keys |= {str(k).lower() for k in headers}
        if keys & agent_keys:
            return True
        return bool(data.get('automated') is True or data.get('is_agent') is True)


registry.register(ToolAbusePattern())
