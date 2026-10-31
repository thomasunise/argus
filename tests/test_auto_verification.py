from app.testing.auto_verification import enabled, _baseline, report_retest
from app.models import Tenant, dumps, loads
from app.models.actions import ActionRequest, ActionRun
from app.models.testing import TestRun, TestResult, TestScope


def test_auto_verification_default_off_and_eligibility(db, default_tenant_id):
    tenant = db.get(Tenant, default_tenant_id)
    assert not enabled(tenant)
    assert _baseline(db, default_tenant_id, 'missing') is None
    tenant.settings_json = dumps({**loads(tenant.settings_json, {}), 'auto_verification': {'enabled': True}})
    assert enabled(tenant)
    assert report_retest(lambda: db, default_tenant_id, 'missing') is None


def test_auto_verification_endpoint_is_explicit_opt_in(owner):
    client, headers = owner
    r = client.get('/api/v1/verification/auto-settings', headers=headers)
    assert r.status_code == 200 and r.json()['enabled'] is False
    r = client.put('/api/v1/verification/auto-settings', json={'enabled': True}, headers=headers)
    assert r.status_code == 200 and r.json()['enabled'] is True
