"""KEV / EPSS enrichment: feed caching (online, offline, bulk file), finding updates, the API and tenancy."""
from __future__ import annotations

import gzip
import json
import time

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from app.core.findings import upsert_finding
from app.intel import enrich, feeds
from app.models import Finding, loads
from tests.conftest import wait_job, wait_for

KEV = {'catalogVersion': '2026.10.20', 'count': 2, 'vulnerabilities': [
    {'cveID': 'CVE-2024-3094', 'vendorProject': 'XZ', 'product': 'xz-utils', 'dateAdded': '2024-03-29', 'dueDate': '2024-04-19',
     'knownRansomwareCampaignUse': 'Unknown'},
    {'cveID': 'CVE-2023-4966', 'vendorProject': 'Citrix', 'product': 'NetScaler', 'dateAdded': '2023-10-18', 'dueDate': '2023-11-08',
     'knownRansomwareCampaignUse': 'Known'}]}


def _epss_response(request: httpx.Request) -> httpx.Response:
    cves = request.url.params.get('cve', '').split(',')
    scores = {'CVE-2024-3094': 0.86, 'CVE-2023-4966': 0.97, 'CVE-2021-0001': 0.01}
    data = [{'cve': c, 'epss': str(scores[c]), 'percentile': '0.99', 'date': '2026-10-23'} for c in cves if c in scores]
    return httpx.Response(200, json={'status': 'OK', 'data': data})


@pytest.fixture(autouse=True)
def _fresh_memo():
    feeds.clear_memo()
    yield
    feeds.clear_memo()


@pytest.fixture
def intel_settings(settings, tmp_path):
    settings.intel_cache_dir = tmp_path / 'intel-cache'
    return settings


@pytest.mark.asyncio
async def test_kev_is_cached_on_disk_and_not_refetched(intel_settings):
    with respx.mock(assert_all_called=True) as mock:
        route = mock.get(feeds.KEV_URL).mock(return_value=httpx.Response(200, json=KEV))
        first = await feeds.kev_lookup(intel_settings, ['CVE-2024-3094', 'CVE-1999-0001'])
        second = await feeds.kev_lookup(intel_settings, ['CVE-2023-4966'])
    assert set(first) == {'CVE-2024-3094'} and set(second) == {'CVE-2023-4966'}
    assert route.call_count == 1
    assert (intel_settings.intel_cache_dir / 'kev.json').is_file()
    assert feeds.status(intel_settings)['kev']['count'] == 2


@pytest.mark.asyncio
async def test_failed_or_malformed_kev_keeps_previous_cache(intel_settings):
    with respx.mock() as mock:
        mock.get(feeds.KEV_URL).mock(return_value=httpx.Response(200, json=KEV))
        await feeds.refresh_kev(intel_settings, force=True)
        mock.get(feeds.KEV_URL).mock(return_value=httpx.Response(200, json={'vulnerabilities': []}))
        bad = await feeds.refresh_kev(intel_settings, force=True)
        mock.get(feeds.KEV_URL).mock(side_effect=httpx.ConnectError('down'))
        down = await feeds.refresh_kev(intel_settings, force=True)
    assert not bad['refreshed'] and 'malformed' in bad['reason']
    assert not down['refreshed'] and 'ConnectError' in down['reason']
    assert 'CVE-2024-3094' in feeds.kev_index(intel_settings)


@pytest.mark.asyncio
async def test_epss_batches_caches_and_remembers_unscored(intel_settings):
    with respx.mock(assert_all_called=True) as mock:
        route = mock.get(feeds.EPSS_API).mock(side_effect=_epss_response)
        scores = await feeds.epss_lookup(intel_settings, ['CVE-2024-3094', 'CVE-2025-9999'])
        again = await feeds.epss_lookup(intel_settings, ['CVE-2024-3094', 'CVE-2025-9999'])
    assert scores['CVE-2024-3094']['epss'] == pytest.approx(0.86)
    assert 'CVE-2025-9999' not in scores
    assert again['CVE-2024-3094']['source'] == 'api-cache'
    assert route.call_count == 1  # the unscored CVE is cached too


@pytest.mark.asyncio
async def test_offline_mode_uses_files_and_never_touches_network(intel_settings):
    intel_settings.intel_offline = True
    folder = feeds.cache_dir(intel_settings)
    (folder / 'kev.json').write_text(json.dumps(KEV), encoding='utf-8')
    csv_text = '#model_version:v2025.03.14,score_date:2026-10-22T00:00:00+0000\ncve,epss,percentile\nCVE-2024-3094,0.91000,0.99800\n'
    (folder / 'epss_scores-current.csv.gz').write_bytes(gzip.compress(csv_text.encode()))
    with respx.mock(assert_all_called=False) as mock:
        kev_route = mock.get(feeds.KEV_URL).mock(return_value=httpx.Response(500))
        epss_route = mock.get(feeds.EPSS_API).mock(return_value=httpx.Response(500))
        refresh = await feeds.refresh_kev(intel_settings, force=True)
        kev = await feeds.kev_lookup(intel_settings, ['CVE-2024-3094'])
        epss = await feeds.epss_lookup(intel_settings, ['CVE-2024-3094', 'CVE-2023-4966'])
    assert refresh['reason'] == 'offline mode'
    assert 'CVE-2024-3094' in kev
    assert epss == {'CVE-2024-3094': {'epss': 0.91, 'percentile': 0.998, 'date': '2026-10-22', 'source': 'bulk-file'}}
    assert kev_route.call_count == 0 and epss_route.call_count == 0
    assert feeds.status(intel_settings)['epss']['bulk_cves'] == 1


def test_apply_sets_kev_epss_tag_and_raises_severity(settings):
    finding = Finding(tenant_id='t', fingerprint='f', title='xz backdoor', description='', source='trivy', severity='medium',
                      cve_ids='CVE-2024-3094,CVE-2021-0001', evidence='{"pkg": "xz"}', tags_json='["os"]', kev=0)
    kev = {'CVE-2024-3094': KEV['vulnerabilities'][0]}
    epss = {'CVE-2024-3094': {'epss': 0.86, 'percentile': 0.99, 'date': '2026-10-23'}, 'CVE-2021-0001': {'epss': 0.01, 'percentile': 0.2, 'date': ''}}
    changed = enrich.apply(finding, kev, epss, settings)
    assert changed == {'kev': True, 'epss': 0.86, 'severity': 'high'}
    assert finding.kev == 1 and finding.severity == 'high' and loads(finding.tags_json) == ['os', 'kev']
    evidence = loads(finding.evidence)
    assert evidence['pkg'] == 'xz'
    assert evidence['intel']['severity_raised_from'] == 'medium'
    assert evidence['intel']['kev']['CVE-2024-3094']['due_date'] == '2024-04-19'
    # A second pass changes nothing and keeps the original severity on record.
    assert enrich.apply(finding, kev, epss, settings) == {}
    assert loads(finding.evidence)['intel']['severity_raised_from'] == 'medium'


def test_apply_never_lowers_severity_and_respects_disabled_floor(settings):
    settings.intel_kev_min_severity = ''
    finding = Finding(tenant_id='t', fingerprint='f', title='x', description='', source='trivy', severity='critical', cve_ids='CVE-2024-3094',
                      evidence='{}', tags_json='[]', kev=0)
    enrich.apply(finding, {'CVE-2024-3094': KEV['vulnerabilities'][0]}, {}, settings)
    assert finding.severity == 'critical'
    low = Finding(tenant_id='t', fingerprint='g', title='x', description='', source='trivy', severity='low', cve_ids='CVE-2024-3094',
                  evidence='{}', tags_json='[]', kev=0)
    enrich.apply(low, {'CVE-2024-3094': KEV['vulnerabilities'][0]}, {}, settings)
    assert low.severity == 'low' and low.kev == 1


def test_epss_threshold_escalation(settings):
    settings.intel_epss_escalate_threshold = 0.5
    finding = Finding(tenant_id='t', fingerprint='f', title='x', description='', source='trivy', severity='low', cve_ids='CVE-2023-4966',
                      evidence='{}', tags_json='[]', kev=0)
    enrich.apply(finding, {}, {'CVE-2023-4966': {'epss': 0.97, 'percentile': 0.99, 'date': ''}}, settings)
    assert finding.severity == 'high' and finding.kev == 0


def _mock_feeds(mock):
    mock.get(feeds.KEV_URL).mock(return_value=httpx.Response(200, json=KEV))
    mock.get(feeds.EPSS_API).mock(side_effect=_epss_response)


def test_backfill_api_enriches_open_findings_and_audits(owner, db, default_tenant_id, second_tenant):
    client, headers = owner
    mine, _ = upsert_finding(db, default_tenant_id, source='trivy', rule='CVE-2024-3094:xz', title='xz', description='', severity_name='medium',
                             cve_ids=['CVE-2024-3094'])
    plain, _ = upsert_finding(db, default_tenant_id, source='zap', rule='hdr', title='header', description='', severity_name='low')
    theirs, _ = upsert_finding(db, second_tenant['tenant_id'], source='trivy', rule='CVE-2024-3094:xz', title='xz', description='',
                               severity_name='medium', cve_ids=['CVE-2024-3094'])
    db.commit()
    with respx.mock(assert_all_called=False) as mock:
        _mock_feeds(mock)
        response = client.post('/api/v1/intel/enrich', json={}, headers=headers)
        assert response.status_code == 202, response.text
        job = wait_job(client, headers, response.json()['job_id'])
    assert job['status'] == 'completed', job
    assert job['result']['checked'] == 1 and job['result']['changed'] == 1
    db.expire_all()
    assert db.get(Finding, mine.id).kev == 1 and db.get(Finding, mine.id).severity == 'high'
    assert db.get(Finding, mine.id).epss == pytest.approx(0.86)
    assert db.get(Finding, plain.id).kev == 0
    assert db.get(Finding, theirs.id).kev == 0  # other tenant untouched
    audit = client.get('/api/v1/audit', params={'action': 'intel.enriched'}, headers=headers).json()
    assert audit['items'] and audit['items'][0]['action'] == 'intel.enriched'


def test_status_cve_lookup_and_permissions(owner, make_user, app):
    client, headers = owner
    with respx.mock(assert_all_called=False) as mock:
        _mock_feeds(mock)
        status = client.get('/api/v1/intel/status', headers=headers)
        cve = client.get('/api/v1/intel/cve/cve-2023-4966', headers=headers)
        bad = client.get('/api/v1/intel/cve/not-a-cve', headers=headers)
    assert status.status_code == 200 and status.json()['enabled'] is False
    assert cve.status_code == 200 and cve.json()['kev'] is True and cve.json()['epss']['epss'] == pytest.approx(0.97)
    assert bad.status_code == 422
    make_user('viewer@test.local', 'viewer-password-long-123456', 'viewer')
    viewer = TestClient(app)
    from tests.conftest import login

    vh = login(viewer, 'viewer@test.local', 'viewer-password-long-123456')
    assert viewer.post('/api/v1/intel/refresh', headers=vh).status_code == 403
    assert viewer.post('/api/v1/intel/enrich', json={}, headers=vh).status_code == 403
    assert viewer.get('/api/v1/intel/status', headers=vh).status_code == 200


@pytest.fixture
def enabled_app(settings):
    from app.main import create_app

    settings.intel_enrichment_enabled = True
    return create_app(settings)


def test_new_cve_finding_is_enriched_automatically(enabled_app, monkeypatch):
    import app.intel as intel_pkg

    monkeypatch.setattr(intel_pkg, 'DEBOUNCE_SECONDS', 0.2)
    from tests.conftest import ADMIN_EMAIL, ADMIN_PASSWORD, login

    with respx.mock(assert_all_called=False) as mock, TestClient(enabled_app) as client:
        _mock_feeds(mock)
        login(client, ADMIN_EMAIL, ADMIN_PASSWORD)
        tenant_id = enabled_app.state.default_tenant_id
        with enabled_app.state.db_factory() as db:
            finding, created = upsert_finding(db, tenant_id, source='trivy', rule='CVE-2023-4966:netscaler', title='Citrix Bleed', description='',
                                              severity_name='medium', cve_ids=['CVE-2023-4966'])
            db.commit()
            finding_id = finding.id
        assert created

        def enriched():
            with enabled_app.state.db_factory() as db:
                row = db.get(Finding, finding_id)
                return row is not None and row.kev == 1

        # upsert_finding publishes from sync code; the bus only fires when a loop is running, so emit it on the app loop.
        from app.core.events import publish

        client.portal.call(publish, 'finding.created', {'tenant_id': tenant_id, 'finding_id': finding_id, 'has_cves': True})
        wait_for(enriched, timeout=20)
        time.sleep(0.1)
