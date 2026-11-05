from app.models import Tenant, dumps, loads
from app.testing.auto_verification import _baseline, enabled


def test_auto_verification_default_off_and_eligibility(db, default_tenant_id):
    tenant = db.get(Tenant, default_tenant_id)
    assert not enabled(tenant)
    assert _baseline(db, default_tenant_id, 'missing') is None
    tenant.settings_json = dumps({**loads(tenant.settings_json, {}), 'auto_verification': {'enabled': True}})
    assert enabled(tenant)
    # Avoid closing the fixture's DB session through session_scope.


def test_auto_verification_endpoint_is_explicit_opt_in(owner):
    client, headers = owner
    r = client.get('/api/v1/verification/auto-settings', headers=headers)
    assert r.status_code == 200 and r.json()['enabled'] is False
    r = client.put('/api/v1/verification/auto-settings', json={'enabled': True}, headers=headers)
    assert r.status_code == 200 and r.json()['enabled'] is True
