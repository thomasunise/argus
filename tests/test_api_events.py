from __future__ import annotations

from datetime import timedelta

from app.core.findings import EventDraft, upsert_event
from app.models import utcnow


def make_event(db, tenant_id, external_id, *, source='wazuh', title='Alert', severity='low', category='auth', actor='', entity='', action='',
               received_at=None):
    event, _ = upsert_event(db, tenant_id, EventDraft(source=source, external_id=external_id, title=title, severity=severity, category=category,
                                                      actor=actor, entity=entity, action=action))
    if received_at is not None:
        event.received_at = received_at
    db.commit()
    return event


def test_list_filters_and_detail(owner, db, default_tenant_id):
    client, _ = owner
    old = utcnow() - timedelta(days=3)
    make_event(db, default_tenant_id, 'e1', title='Failed login', severity='medium', actor='alice', entity='vpn', action='login')
    make_event(db, default_tenant_id, 'e2', title='Privilege change', severity='high', category='identity', actor='alice', entity='iam', action='attach_policy')
    make_event(db, default_tenant_id, 'e3', source='falco', title='Shell in container', severity='critical', category='process', actor='bob',
               entity='pod/api', received_at=old)
    items = client.get('/api/v1/events').json()['items']
    assert [e['external_id'] for e in items] == ['e2', 'e1', 'e3']
    assert [e['external_id'] for e in client.get('/api/v1/events?source=falco').json()['items']] == ['e3']
    assert [e['external_id'] for e in client.get('/api/v1/events?severity=high,critical').json()['items']] == ['e2', 'e3']
    assert len(client.get('/api/v1/events?actor=alice').json()['items']) == 2
    assert [e['external_id'] for e in client.get('/api/v1/events?category=process').json()['items']] == ['e3']
    assert [e['external_id'] for e in client.get('/api/v1/events?search=privilege').json()['items']] == ['e2']
    assert len(client.get('/api/v1/events?since=24h').json()['items']) == 2
    assert len(client.get(f'/api/v1/events?since={(utcnow() - timedelta(days=7)).isoformat()}').json()['items']) == 3
    assert client.get('/api/v1/events?since=yesterday').status_code == 400
    page = client.get('/api/v1/events?limit=2').json()
    assert len(page['items']) == 2 and page['next_cursor'] == '2'
    detail = client.get(f"/api/v1/events/{items[0]['id']}").json()
    assert detail['title'] == 'Privilege change' and detail['metadata'] == {}
    assert [e['id'] for e in detail['related_by_actor']] == [items[1]['id']]
    assert client.get('/api/v1/events/missing').status_code == 404


def test_stats(owner, db, default_tenant_id):
    client, _ = owner
    old = utcnow() - timedelta(days=3)
    for i in range(3):
        make_event(db, default_tenant_id, f'a{i}', severity='medium', actor='alice', entity='vpn', action='login')
    make_event(db, default_tenant_id, 'b1', source='falco', severity='critical', category='process', actor='bob', entity='pod/api', received_at=old)
    stats = client.get('/api/v1/events/stats').json()
    assert stats['total'] == 4 and stats['24h']['total'] == 3 and stats['7d']['total'] == 4
    assert stats['24h']['by_source'] == {'wazuh': 3} and stats['7d']['by_source'] == {'wazuh': 3, 'falco': 1}
    assert stats['7d']['by_severity']['critical'] == 1 and stats['7d']['by_category']['process'] == 1
    assert stats['top_actors'][0] == {'value': 'alice', 'count': 3} and stats['top_entities'][0]['value'] == 'vpn'
    assert stats['top_actions'] == [{'value': 'login', 'count': 3}]


def test_requires_auth_and_cross_tenant(client, owner, second_tenant, db, default_tenant_id):
    event = make_event(db, default_tenant_id, 'x1', actor='alice')
    other = second_tenant['client']
    assert other.get('/api/v1/events').json()['items'] == []
    assert other.get(f'/api/v1/events/{event.id}').status_code == 404
    assert other.get('/api/v1/events/stats').json()['total'] == 0
    anonymous = other.__class__(client.app)
    assert anonymous.get('/api/v1/events').status_code == 401
