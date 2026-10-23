"""Identity rules: impossible travel and privilege-escalation chains."""
from __future__ import annotations

from collections import defaultdict

from ...models import SecurityEvent
from ..engine import DetectionDraft, DetectionRule, RuleContext, registry
from ..util import epoch, event_time, geo_of, haversine_km, iso, meta, scale_confidence, source_ip, window_bucket


class ImpossibleVelocity(DetectionRule):
    id = 'identity.impossible_velocity'
    name = 'Impossible travel'
    severity = 'high'
    category = 'identity'
    description = ('The same identity acted from two locations that are farther apart than it could have travelled in the time between '
                   'the events. Either the credential is shared or it has been stolen.')
    remediation = 'Force re-authentication, revoke refresh tokens and sessions for the identity, and confirm with the owner.'
    default_params = {'window_minutes': 60, 'max_speed_kmh': 900.0, 'min_distance_km': 200.0, 'country_change_confidence': 0.6,
                      'max_drafts_per_actor': 3}

    def evaluate(self, ctx: RuleContext) -> list[DetectionDraft]:
        window_s = float(ctx.param('window_minutes', 60)) * 60
        max_speed = float(ctx.param('max_speed_kmh', 900.0))
        min_distance = float(ctx.param('min_distance_km', 200.0))
        country_conf = float(ctx.param('country_change_confidence', 0.6))
        per_actor_cap = int(ctx.param('max_drafts_per_actor', 3))
        located: dict[str, list[tuple[SecurityEvent, float | None, float | None, str]]] = defaultdict(list)
        for event in ctx.events():
            if not event.actor:
                continue
            lat, lon, country = geo_of(event)
            if (lat is not None and lon is not None) or country:
                located[event.actor].append((event, lat, lon, country))
        drafts: list[DetectionDraft] = []
        for actor, items in located.items():
            emitted = 0
            prev = None
            for current in items:
                if prev is None:
                    prev = current
                    continue
                a, b = prev, current
                dt = epoch(event_time(b[0])) - epoch(event_time(a[0]))
                if dt > window_s:
                    prev = current
                    continue
                draft = self._compare(ctx, actor, a, b, dt, max_speed, min_distance, country_conf)
                if draft is None:
                    # Same location (or not comparable): keep the earlier anchor so a slow drift still gets compared to the origin.
                    if self._same_place(a, b):
                        continue
                    prev = current
                    continue
                drafts.append(draft)
                emitted += 1
                prev = current
                if emitted >= per_actor_cap:
                    break
        return drafts

    @staticmethod
    def _same_place(a, b) -> bool:
        if a[1] is not None and b[1] is not None:
            return abs(a[1] - b[1]) < 0.01 and abs(a[2] - b[2]) < 0.01
        return bool(a[3]) and a[3] == b[3]

    def _compare(self, ctx: RuleContext, actor: str, a, b, dt: float, max_speed: float, min_distance: float, country_conf: float):
        ev_a, lat_a, lon_a, country_a = a
        ev_b, lat_b, lon_b, country_b = b
        hours = max(dt, 1.0) / 3600.0
        if lat_a is not None and lon_a is not None and lat_b is not None and lon_b is not None:
            distance = haversine_km(lat_a, lon_a, lat_b, lon_b)
            speed = distance / hours
            if distance < min_distance or speed <= max_speed:
                return None
            confidence = scale_confidence(speed, max_speed, base=0.7)
            how = f'{distance:.0f} km in {dt / 60:.1f} min ({speed:.0f} km/h)'
        elif country_a and country_b and country_a != country_b:
            distance, speed, confidence = None, None, country_conf
            how = f'{country_a} to {country_b} in {dt / 60:.1f} min'
        else:
            return None
        first, last = event_time(ev_a), event_time(ev_b)
        return DetectionDraft(
            rule_id=self.id, title=f'{actor} moved {how}', severity=self.severity, confidence=confidence, entity=actor, entity_kind='identity',
            description=f'`{actor}` acted from two locations faster than travel allows: {how}. Events {ev_a.id} and {ev_b.id}.',
            fingerprint_parts=[actor], window_bucket=window_bucket(first, int(ctx.param('window_minutes', 60))), first_seen_at=first,
            last_seen_at=last,
            evidence={'actor': actor, 'from': {'country': country_a, 'ip': source_ip(ev_a), 'lat': _r(lat_a), 'lon': _r(lon_a), 'at': iso(first)},
                      'to': {'country': country_b, 'ip': source_ip(ev_b), 'lat': _r(lat_b), 'lon': _r(lon_b), 'at': iso(last)},
                      'distance_km': None if distance is None else round(distance, 1), 'minutes_apart': round(dt / 60, 2),
                      'speed_kmh': None if speed is None else round(speed, 1), 'event_ids': [ev_a.id, ev_b.id]})


def _r(value: float | None) -> float | None:
    return None if value is None else round(value, 2)


class PrivilegeEscalationChain(DetectionRule):
    id = 'identity.privilege_escalation_chain'
    name = 'Privilege escalation chain'
    severity = 'critical'
    category = 'identity'
    description = ('One identity assumed a role, then granted itself or that role new permissions, then accessed data, all within one '
                   'window. That ordered chain is the core of most cloud intrusions.')
    remediation = 'Revoke the assumed session, remove the added permission, and audit everything the identity read afterwards.'
    default_params = {
        'window_minutes': 30,
        'assume_actions': ['role_assumed', 'sts.assume_role', 'sts.assume_role_with_web_identity', 'iam.assume_role', 'assumerole',
                           'az.role.activate', 'gcp.iam.impersonate'],
        'grant_actions': ['permission_added', 'iam.attach_user_policy', 'iam.attach_role_policy', 'iam.put_user_policy', 'iam.put_role_policy',
                          'iam.add_user_to_group', 'iam.create_access_key', 'iam.create_policy_version', 'az.role_assignment.write',
                          'gcp.set_iam_policy', 'storage.set_iam_policy', 'k8s.rolebinding.create', 'k8s.clusterrolebinding.create'],
        'access_actions': ['data_access', 's3.get_object', 's3.list_bucket', 's3.list_objects', 'dynamodb.scan', 'dynamodb.query',
                           'secretsmanager.get_secret_value', 'ssm.get_parameter', 'ssm.get_parameters', 'kms.decrypt', 'rds.describe_db_snapshots',
                           'storage.objects.get', 'bigquery.query', 'az.storage.blob.read', 'az.keyvault.secret.get', 'k8s.secrets.get'],
        'access_categories': ['data_access', 'data'],
    }

    def evaluate(self, ctx: RuleContext) -> list[DetectionDraft]:
        window_s = float(ctx.param('window_minutes', 30)) * 60
        assume = {a.lower() for a in ctx.param('assume_actions', [])}
        grant = {a.lower() for a in ctx.param('grant_actions', [])}
        access = {a.lower() for a in ctx.param('access_actions', [])}
        access_categories = {c.lower() for c in ctx.param('access_categories', [])}
        by_actor: dict[str, list[SecurityEvent]] = defaultdict(list)
        for event in ctx.events():
            if event.actor:
                by_actor[event.actor].append(event)
        drafts: list[DetectionDraft] = []
        for actor, items in by_actor.items():
            assumed: list[SecurityEvent] = []
            granted: list[tuple[SecurityEvent, SecurityEvent]] = []
            for event in items:
                action = (event.action or '').lower()
                t = epoch(event_time(event))
                if action in assume:
                    assumed.append(event)
                elif action in grant:
                    candidates = [a for a in assumed if t - epoch(event_time(a)) <= window_s]
                    if candidates:
                        granted.append((candidates[-1], event))
                elif action in access or (event.category or '').lower() in access_categories:
                    chain = next(((a, g) for a, g in reversed(granted) if t - epoch(event_time(a)) <= window_s), None)
                    if chain is None:
                        continue
                    a, g = chain
                    first, last = event_time(a), event_time(event)
                    elapsed = (last - first).total_seconds()
                    drafts.append(DetectionDraft(
                        rule_id=self.id, severity=self.severity, confidence=round(min(0.97, 0.75 + 0.2 * (1 - elapsed / max(window_s, 1))), 3),
                        title=f'{actor}: role assumed, permission added, data accessed within {elapsed / 60:.1f} min',
                        description=(f'`{actor}` assumed a role (`{a.action}` on {a.entity}), then added a permission (`{g.action}` on {g.entity}), '
                                     f'then accessed data (`{event.action}` on {event.entity}) between {iso(first)} and {iso(last)}.'),
                        entity=actor, entity_kind='identity', fingerprint_parts=[actor],
                        window_bucket=window_bucket(first, int(ctx.param('window_minutes', 30))), first_seen_at=first, last_seen_at=last,
                        evidence={'actor': actor, 'chain': [{'stage': 'assume', 'action': a.action, 'entity': a.entity, 'at': iso(event_time(a))},
                                                            {'stage': 'grant', 'action': g.action, 'entity': g.entity, 'at': iso(event_time(g))},
                                                            {'stage': 'access', 'action': event.action, 'entity': event.entity, 'at': iso(last)}],
                                  'elapsed_seconds': round(elapsed, 1), 'source_ip': source_ip(event) or source_ip(a),
                                  'role': meta(a).get('role') or a.entity, 'event_ids': [a.id, g.id, event.id]}))
                    assumed, granted = [], []
        return drafts


registry.register(ImpossibleVelocity())
registry.register(PrivilegeEscalationChain())
