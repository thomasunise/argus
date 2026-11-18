"""Comprehensive test suite for Argus Enterprise-Readiness Checklist (Phases 1, 2, 3, and 6)."""
from __future__ import annotations

import base64
import hashlib
from datetime import timedelta
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
import respx
from app.actions import broker, catalog, credentials
from app.actions.catalog import ActionType, DryRunResult, ExecResult
from app.agents.providers import AzureOpenAIProvider, BedrockProvider, get_provider
from app.ai import dlp
from app.api import discover_routers
from app.core import audit as audit_mod
from app.core.audit import (
    AuditSink,
    configure,
    flush_outbox_backlog,
    outbox_backlog_count,
    record_audit,
    write_chain_head,
)
from app.core.config import assert_safe_config
from app.core.crypto import bind_aad, decrypt, encrypt
from app.core.queue import JobQueue, verify_job
from app.core.rbac import PERMISSIONS, Principal, Role, has
from app.core.security import (
    OidcDiscovery,
    hash_password,
    password_needs_rehash,
    resolve_secret,
    secret_ref_allowed,
    verify_password,
)
from app.integrations.egress import egress_ok, resolve_pinned_outbound
from app.models import ApiKey, AuditEntry, AuditOutbox, Finding, Membership, Tenant, User, utcnow
from sqlalchemy import select
from tests.conftest import ADMIN_EMAIL, ADMIN_PASSWORD, login

# ==============================================================================
# PHASE 1: Product Boundary & Supply Chain
# ==============================================================================


def test_phase1_core_only_build_excludes_offensive_routers_and_specs():
    core_routers = discover_routers(core_only=True)
    core_prefixes = {r.prefix for r in core_routers}
    for forbidden in ('/api/v1/pentest', '/api/v1/exploit', '/api/v1/discovery', '/api/v1/autopilot'):
        assert forbidden not in core_prefixes

    full_routers = discover_routers(core_only=False)
    assert len(full_routers) == len(core_routers) + 4


def test_phase1_supply_chain_and_governance_files_present():
    root = Path(__file__).resolve().parents[1]
    assert (root / '.github' / 'CODEOWNERS').is_file()
    assert (root / 'CHANGELOG.md').is_file()
    assert (root / '.github' / 'workflows' / 'codeql.yml').is_file()
    sec_doc = (root / 'docs' / 'SECURITY.md').read_text(encoding='utf-8').lower()
    assert 'vulnerability disclosure' in sec_doc and 'safe harbor' in sec_doc
    opt_reqs = (root / 'requirements-optional.txt').read_text(encoding='utf-8')
    for line in opt_reqs.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith('#'):
            assert '==' in stripped, f'Unpinned dependency in requirements-optional.txt: {stripped}'


# ==============================================================================
# PHASE 2: Identity, Sessions, OIDC, WebAuthn, SAML, SCIM
# ==============================================================================


def test_phase2_local_login_disabled_allows_only_break_glass(app, client, make_user):
    make_user('regular@test.local', 'regular-password-123456', 'analyst')
    app.state.settings.local_login_disabled = True
    app.state.settings.break_glass_email = ADMIN_EMAIL
    try:
        denied = client.post('/api/v1/auth/login', json={'email': 'regular@test.local', 'password': 'regular-password-123456'})
        assert denied.status_code == 403
        allowed = client.post('/api/v1/auth/login', json={'email': ADMIN_EMAIL, 'password': ADMIN_PASSWORD})
        assert allowed.status_code == 200
    finally:
        app.state.settings.local_login_disabled = False
        app.state.settings.break_glass_email = ''


def test_phase2_mock_oidc_callback_acr_and_group_mapping(app, client, monkeypatch):
    app.state.settings.oidc_issuer = 'https://idp.example.test'
    app.state.settings.oidc_client_id = 'argus-client'
    app.state.settings.oidc_client_secret = 'argus-secret'
    app.state.settings.oidc_required_acr = 'phr'
    app.state.settings.totp_required = True
    app.state.settings.oidc_group_role_map = 'sec-admins=default:admin'
    try:
        async def _fake_discover(issuer: str) -> OidcDiscovery:
            return OidcDiscovery(
                issuer='https://idp.example.test',
                authorization_endpoint='https://idp.example.test/authorize',
                token_endpoint='https://idp.example.test/token',
                jwks_uri='https://idp.example.test/jwks',
                userinfo_endpoint='https://idp.example.test/userinfo',
            )

        monkeypatch.setattr('app.api.auth.oidc_discover', _fake_discover)
        start = client.get('/api/v1/auth/oidc/start', follow_redirects=False)
        assert start.status_code == 302
        qs = parse_qs(urlparse(start.headers['location']).query)
        state = qs['state'][0]

        # 1. Missing required ACR claim fails when oidc_required_acr and totp_required are set
        async def _fake_exchange_low(doc, settings, code, verifier, nonce):
            return {'sub': 'oidc-sub-1', 'email': 'sso-user@test.local', 'email_verified': True, 'name': 'SSO User', 'acr': 'password', 'groups': ['sec-admins']}

        monkeypatch.setattr('app.api.auth.oidc_exchange_code', _fake_exchange_low)
        failed_acr = client.get(f'/api/v1/auth/oidc/callback?state={state}&code=code1', follow_redirects=False)
        assert failed_acr.status_code == 403

        # 2. Matching ACR claim succeeds and applies group mapping (default:admin)
        start2 = client.get('/api/v1/auth/oidc/start', follow_redirects=False)
        state2 = parse_qs(urlparse(start2.headers['location']).query)['state'][0]

        async def _fake_exchange_high(doc, settings, code, verifier, nonce):
            return {'sub': 'oidc-sub-1', 'email': 'sso-user@test.local', 'email_verified': True, 'name': 'SSO User', 'acr': 'phr', 'groups': ['sec-admins']}

        monkeypatch.setattr('app.api.auth.oidc_exchange_code', _fake_exchange_high)
        ok_cb = client.get(f'/api/v1/auth/oidc/callback?state={state2}&code=code2', follow_redirects=False)
        assert ok_cb.status_code == 302
        sess = client.get('/api/v1/auth/session').json()
        assert sess['authenticated'] is True
        assert sess['user']['email'] == 'sso-user@test.local'
        assert sess['role'] == 'admin'
    finally:
        app.state.settings.oidc_issuer = ''
        app.state.settings.oidc_required_acr = ''
        app.state.settings.totp_required = False
        app.state.settings.oidc_group_role_map = ''


def test_phase2_scim_provisioning_and_deprovisioning_revokes_keys(app, client):
    app.state.settings.scim_bearer_token = 'scim-secret-bearer-token-0123456789abcdef'
    scim_headers = {'Authorization': 'Bearer scim-secret-bearer-token-0123456789abcdef'}
    try:
        created = client.post(
            '/api/v1/scim/v2/Users',
            json={'userName': 'scim.person@test.local', 'displayName': 'SCIM Person', 'roles': [{'value': 'operator'}]},
            headers=scim_headers,
        )
        assert created.status_code == 201, created.text
        uid = created.json()['id']

        # Mint an API key owned by this user
        with app.state.db_factory() as db:
            tid = app.state.default_tenant_id
            key_row = ApiKey(
                tenant_id=tid,
                name='scim-user-key',
                prefix='argus_scim0001',
                key_hash=hashlib.sha256(b'raw').hexdigest(),
                role='operator',
                created_by=uid,
            )
            db.add(key_row)
            db.commit()
            key_id = key_row.id

        # Deprovision via SCIM PATCH active=false -> user disabled AND API key revoked immediately
        patched = client.patch(
            f'/api/v1/scim/v2/Users/{uid}',
            json={'Operations': [{'op': 'Replace', 'path': 'active', 'value': False}]},
            headers=scim_headers,
        )
        assert patched.status_code == 200 and patched.json()['active'] is False
        with app.state.db_factory() as db:
            refreshed_key = db.get(ApiKey, key_id)
            assert refreshed_key is not None and refreshed_key.revoked_at is not None
    finally:
        app.state.settings.scim_bearer_token = ''


def test_phase2_api_key_default_expiry_and_ip_allowlist(owner, client):
    owner_client, headers = owner
    created = owner_client.post(
        '/api/v1/auth/api-keys',
        json={'name': 'ip-restricted-key', 'role': 'viewer', 'allowed_ips': ['10.99.0.0/16']},
        headers=headers,
    )
    assert created.status_code == 201
    data = created.json()
    assert data['expires_at'] is not None  # 90-day default expiry applied
    raw_key = data['key']

    # TestClient peer IP is 'testclient' (not in 10.99.0.0/16) -> 401
    denied = client.get('/api/v1/ops/jobs', headers={'X-API-Key': raw_key})
    assert denied.status_code == 401


def test_phase2_totp_enrollment_code_gate_and_server_session_revocation(app, client, make_user):
    owner_headers = login(client, ADMIN_EMAIL, ADMIN_PASSWORD)
    user_id = make_user('enrollee@test.local', 'temp-password-123456', 'analyst')

    # Admin issues one-time enrollment token while logged in as owner
    tok_resp = client.post(f'/api/v1/admin/users/{user_id}/totp-enrollment-token', headers=owner_headers)
    assert tok_resp.status_code == 200
    token = tok_resp.json()['enrollment_code']

    app.state.settings.totp_require_enrollment_code = True
    try:
        client.cookies.clear()
        user_headers = login(client, 'enrollee@test.local', 'temp-password-123456')
        # Without admin enrollment code -> 403
        denied = client.post('/api/v1/auth/totp/enroll', json={}, headers=user_headers)
        assert denied.status_code == 403

        # Enrollee can now enroll with the one-time token
        enrolled = client.post('/api/v1/auth/totp/enroll', json={'enrollment_code': token}, headers=user_headers)
        assert enrolled.status_code == 200

        # Revoke current session via DELETE /api/v1/auth/sessions/{sid}
        all_sids = list(app.state.session_store._mem.keys())
        assert client.delete(f'/api/v1/auth/sessions/{all_sids[0]}', headers=user_headers).status_code == 403
        rev = client.delete(f'/api/v1/auth/sessions/{all_sids[-1]}', headers=user_headers)
        assert rev.status_code == 200
    finally:
        app.state.settings.totp_require_enrollment_code = False


# ==============================================================================
# PHASE 2: Separation of Duties & Cooling-Off Rule
# ==============================================================================


@pytest.mark.asyncio
async def test_phase2_separation_of_duties_roles_and_cooling_off(app, db, default_tenant_id):
    # 1. Verify user_admin lacks actions:approve and approver lacks admin:users
    assert 'admin:users' in PERMISSIONS[Role.user_admin]
    assert 'actions:approve' not in PERMISSIONS[Role.user_admin]
    assert 'actions:approve' in PERMISSIONS[Role.approver]
    assert 'admin:users' not in PERMISSIONS[Role.approver]

    p_custom = Principal(
        tenant_id=default_tenant_id,
        role=Role.viewer,
        user_id='u-custom',
        custom_permissions=frozenset({'actions:approve'}),
    )
    assert has(p_custom, 'actions:approve')

    # 2. Verify cooling-off rule blocks an account created by the requester or < 24h ago
    class HighRiskTestAction(ActionType):
        name = 'test.sod.high'
        description = 'High risk SOD test'
        risk = 'high'
        reversible = True
        platforms = ['argus']
        params_schema = {'type': 'object', 'properties': {}, 'additionalProperties': False}

        async def dry_run(self, params, ctx):
            return DryRunResult(ok=True, summary='ok', blast_radius={'kind': 'host', 'entities': 1, 'ids': ['h1']})

        async def execute(self, params, ctx):
            return ExecResult(ok=True, summary='done')

    catalog.register(HighRiskTestAction)
    try:
        tenant = db.get(Tenant, default_tenant_id)
        assert tenant is not None
        tenant.actions_enabled = True
        db.commit()

        requester_user = User(email='requester-sod@test.local', display_name='Req', password_hash='x')
        db.add(requester_user)
        db.flush()
        db.add(Membership(user_id=requester_user.id, tenant_id=default_tenant_id, role='admin'))

        # Sockpuppet created by requester_user
        sockpuppet = User(email='sockpuppet@test.local', display_name='Sock', password_hash='x', created_by=requester_user.id)
        db.add(sockpuppet)
        db.flush()
        db.add(Membership(user_id=sockpuppet.id, tenant_id=default_tenant_id, role='owner', created_by=requester_user.id))

        # Fresh account created < 24h ago by someone else
        fresh_user = User(email='fresh-approver@test.local', display_name='Fresh', password_hash='x', created_by='other-admin')
        db.add(fresh_user)
        db.flush()
        db.add(Membership(user_id=fresh_user.id, tenant_id=default_tenant_id, role='owner', created_by='other-admin'))
        db.commit()

        req_principal = Principal(tenant_id=default_tenant_id, role=Role.admin, user_id=requester_user.id, email=requester_user.email)
        sock_principal = Principal(tenant_id=default_tenant_id, role=Role.owner, user_id=sockpuppet.id, email=sockpuppet.email)
        fresh_principal = Principal(tenant_id=default_tenant_id, role=Role.owner, user_id=fresh_user.id, email=fresh_user.email)

        action_req = await broker.request(db, req_principal, 'test.sod.high', {}, 'sod test', settings=app.state.settings)
        db.commit()

        # Sockpuppet created by requester is blocked
        with pytest.raises(Exception) as exc1:
            broker.approve(db, sock_principal, action_req.id, 'approve', 'sockpuppet approve')
        assert 'created by the requester' in str(exc1.value)

        # Account < 24h old is blocked by cooling-off rule
        with pytest.raises(Exception) as exc2:
            broker.approve(db, fresh_principal, action_req.id, 'approve', 'fresh approve')
        assert 'cooling-off' in str(exc2.value)
    finally:
        catalog.unregister('test.sod.high')


# ==============================================================================
# PHASE 2: Durable Audit Outbox, Sensitive Reads, Chain Head, KMS & Queue Signing
# ==============================================================================


def test_phase2_durable_audit_outbox_and_chain_head(db, default_tenant_id, settings):
    attempts = {'count': 0, 'anchors': []}

    class FlakySink(AuditSink):
        name = 'flaky_worm'

        def write(self, record: dict) -> None:
            if record.get('kind') == 'chain_head_anchor':
                attempts['anchors'].append(record)
                return
            attempts['count'] += 1
            if attempts['count'] == 1:
                raise RuntimeError('simulated WORM sink network timeout')

    configure(settings)
    audit_mod._sinks.append(FlakySink())
    try:
        record_audit(db, 'admin@test.local', 'test.durable_outbox', 'subj-1', {'k': 'v'}, tenant_id=default_tenant_id)
        db.commit()
        db.expire_all()

        # First delivery failed -> row stays pending in audit_outbox
        assert outbox_backlog_count(db) >= 1
        row = db.execute(select(AuditOutbox).where(AuditOutbox.sink_name == 'flaky_worm')).scalars().first()
        assert row is not None and row.delivered_at is None and 'RuntimeError' in row.last_error

        # Force next_attempt_at to now and flush backlog -> succeeds on retry
        row.next_attempt_at = utcnow() - timedelta(seconds=1)
        db.commit()
        res = flush_outbox_backlog(db)
        db.commit()
        assert res['delivered'] >= 1 and outbox_backlog_count(db) == 0

        # Chain head anchor writes signed head to sink
        anchor = write_chain_head(db, default_tenant_id)
        assert anchor['kind'] == 'chain_head_anchor' and len(attempts['anchors']) == 1
    finally:
        configure(settings)


def test_phase2_sensitive_read_auditing(owner, app, default_tenant_id):
    client, headers = owner
    with app.state.db_factory() as db:
        f = Finding(
            tenant_id=default_tenant_id,
            source='test',
            rule='r1',
            title='Sensitive Finding',
            description='desc',
            remediation='rem',
            severity=4,
            fingerprint='fp-sens-1',
            evidence='secret-ev',
        )
        db.add(f)
        db.commit()
        fid = f.id

    app.state.settings.audit_reads_enabled = True
    try:
        assert client.get(f'/api/v1/findings/{fid}', headers=headers).status_code == 200
        assert client.get('/api/v1/findings/export.csv', headers=headers).status_code == 200
        assert client.get('/api/v1/audit/export.jsonl', headers=headers).status_code == 200
        assert client.get('/api/v1/audit', headers=headers).status_code == 200

        with app.state.db_factory() as db:
            actions = {r.action for r in db.execute(select(AuditEntry)).scalars().all()}
            assert {'findings.viewed', 'findings.exported', 'audit.exported', 'audit.viewed'} <= actions
    finally:
        app.state.settings.audit_reads_enabled = False


def test_phase2_kms_envelope_context_aad_and_tenant_isolation(settings):
    aad_a = bind_aad(tenant_id='tenant-a', table='findings', column='evidence', row_id='row-1')
    aad_b = bind_aad(tenant_id='tenant-b', table='findings', column='evidence', row_id='row-1')

    ct = encrypt('classified-payload', tenant_id='tenant-a', aad=aad_a)
    assert ct is not None and ct.startswith('enc:v2:')
    assert decrypt(ct, tenant_id='tenant-a', aad=aad_a) == 'classified-payload'

    # Cross-tenant or cross-column ciphertext swap fails authentication
    with pytest.raises(ValueError):
        decrypt(ct, tenant_id='tenant-b', aad=aad_b)

    # Production refuses plaintext values on decrypt
    with pytest.raises(ValueError):
        decrypt('unencrypted-legacy-value', refuse_plaintext=True)


def test_phase2_per_tenant_secret_namespace_and_queue_hmac(settings, monkeypatch):
    monkeypatch.setenv('ARGUS_SECRET_ACME_WEBHOOK_TOKEN', 'tok-acme-123')
    monkeypatch.setenv('ARGUS_SECRET_OTHER_WEBHOOK_TOKEN', 'tok-other-999')

    assert resolve_secret('env:ARGUS_SECRET_ACME_WEBHOOK_TOKEN', settings, tenant_slug='acme', enforce_tenant_prefix=True) == 'tok-acme-123'
    allowed, reason = secret_ref_allowed('env:ARGUS_SECRET_OTHER_WEBHOOK_TOKEN', settings, tenant_slug='acme', enforce_tenant_prefix=True)
    assert allowed is False and 'tenant prefix' in reason
    assert resolve_secret('env:ARGUS_SECRET_OTHER_WEBHOOK_TOKEN', settings, tenant_slug='acme', enforce_tenant_prefix=True) == ''

    # Multi-tenant disables global env action credentials by default
    monkeypatch.setenv('ACTIONS_GITHUB_TOKEN', 'global-gh-token')
    assert credentials.resolve('github', 'token', settings, {}, tenant_count=2) == ''


@pytest.mark.asyncio
async def test_phase2_queue_hmac_rejects_unsigned_or_tampered_job(settings):
    q = JobQueue(settings.model_copy(update={'redis_url': ''}))
    ran = {'called': False}

    @q.handler('test.signed')
    async def _handler(job, ctx):
        ran['called'] = True
        return {'ok': True}

    job = await q.enqueue('test.signed', {'role': 'viewer'}, tenant_id='t1')
    assert verify_job(job, settings) is True

    # Tamper with payload in backend before worker claims it
    q._backend.jobs[job.id].payload['role'] = 'owner'
    assert verify_job(q._backend.jobs[job.id], settings) is False
    await q.start(concurrency=1)
    done = await q.wait(job.id, timeout=5)
    await q.stop()
    assert done.status == 'failed' and 'signature verification failed' in done.error
    assert ran['called'] is False


def test_phase2_operational_endpoints_and_dns_pinning(app, client, monkeypatch):
    # 1. /metrics requires bearer token when configured or in production
    app.state.settings.metrics_enabled = True
    app.state.settings.metrics_bearer_token = 'prom-secret-token'
    try:
        assert client.get('/metrics').status_code == 401
        ok_metrics = client.get('/metrics', headers={'Authorization': 'Bearer prom-secret-token'})
        assert ok_metrics.status_code == 200
    finally:
        app.state.settings.metrics_bearer_token = ''
        app.state.settings.metrics_enabled = False

    # 2. /health in production returns only {'status': 'healthy'}
    app.state.settings.app_env = 'production'
    try:
        assert client.get('/health').json() == {'status': 'healthy'}
    finally:
        app.state.settings.app_env = 'development'

    # 3. Password scrypt N=2^17 cost and FIPS PBKDF2 mode
    pbkdf2_hash = hash_password('fips-compliant-password-123', scheme='pbkdf2')
    assert pbkdf2_hash.startswith('pbkdf2_sha256$')
    assert verify_password('fips-compliant-password-123', pbkdf2_hash)
    assert password_needs_rehash(hash_password('x', scrypt_n=2 ** 14), scheme='scrypt', min_scrypt_n=2 ** 17)

    # 4. Outbound DNS pinning rejects private IPs and pins validated public IP
    assert egress_ok('https://127.0.0.1/hook', app.state.settings.model_copy(update={'allow_private_targets': False})) is not None
    validated_url, pinned_ip = resolve_pinned_outbound('https://93.184.216.34/hook', app.state.settings)
    assert validated_url == 'https://93.184.216.34/hook' and pinned_ip == '93.184.216.34'


# ==============================================================================
# PHASE 3: Abuse Tests, Cross-Tenant API Sweep & Trusted Types CSP
# ==============================================================================


def test_phase3_trusted_types_csp_header_present(client):
    resp = client.get('/health')
    csp = resp.headers.get('content-security-policy', '')
    assert "require-trusted-types-for 'script'" in csp
    assert 'trusted-types argus-html argus-parse default' in csp


def test_phase3_cross_tenant_sweep_blocks_all_object_access(owner, second_tenant, app, default_tenant_id):
    client_a, headers_a = owner
    client_b, headers_b = second_tenant['client'], second_tenant['headers']

    # Seed objects in Tenant A
    asset_a = client_a.post(
        '/api/v1/assets',
        json={'name': 'sweep-asset-a', 'kind': 'host', 'target': '10.1.1.1', 'environment': 'production'},
        headers=headers_a,
    ).json()
    canary_a = client_a.post(
        '/api/v1/canaries',
        json={'kind': 'url', 'label': 'sweep-canary-a', 'placement': ' internal'},
        headers=headers_a,
    ).json()
    with app.state.db_factory() as db:
        finding_a = Finding(
            tenant_id=default_tenant_id,
            source='sweep',
            rule='r1',
            title='Tenant A Finding',
            description='desc',
            remediation='rem',
            severity=4,
            fingerprint='sweep-fp-a',
            evidence='classified-a',
        )
        db.add(finding_a)
        db.commit()
        finding_a_id = finding_a.id

    # Walk Tenant A's object IDs authenticated as Tenant B -> every one must return 404
    sweep_paths = [
        ('GET', f"/api/v1/assets/{asset_a['id']}"),
        ('PATCH', f"/api/v1/assets/{asset_a['id']}"),
        ('DELETE', f"/api/v1/assets/{asset_a['id']}"),
        ('GET', f'/api/v1/findings/{finding_a_id}'),
        ('PATCH', f'/api/v1/findings/{finding_a_id}'),
        ('DELETE', f"/api/v1/canaries/{canary_a['id']}"),
    ]
    for method, path in sweep_paths:
        body = {'status': 'resolved'} if method == 'PATCH' and 'findings' in path else ({'criticality': 'low'} if method == 'PATCH' else None)
        resp = client_b.request(method, path, json=body, headers=headers_b)
        assert resp.status_code == 404, f'Cross-tenant leak on {method} {path}: {resp.status_code} {resp.text}'


# ==============================================================================
# PHASE 6: Sector Controls (Banking, Healthcare, Government)
# ==============================================================================


@pytest.mark.asyncio
async def test_phase6_sector_compliance_frameworks_and_change_record(owner, app, db, default_tenant_id):
    client, headers = owner
    for fw in ('pci-dss', 'glba-ffiec', 'nydfs-500', 'dora', 'hipaa', 'nist-800-53'):
        resp = client.get(f'/api/v1/reports/compliance/{fw}', headers=headers)
        assert resp.status_code == 200, f'Framework {fw} failed: {resp.text}'
        data = resp.json()
        assert data['framework'] == fw and len(data['controls']) >= 2

    all_resp = client.get('/api/v1/reports/compliance?include_sector=true', headers=headers).json()
    assert {'pci-dss', 'hipaa', 'nist-800-53'} <= {f['framework'] for f in all_resp['items']}

    # Change-record export on an action request
    class ChangeRecAction(ActionType):
        name = 'test.change.record'
        description = 'Change record test'
        risk = 'low'
        reversible = True
        platforms = ['argus']
        params_schema = {'type': 'object', 'properties': {'host': {'type': 'string'}}, 'required': ['host'], 'additionalProperties': False}

        async def dry_run(self, params, ctx):
            return DryRunResult(ok=True, summary='dry ok', blast_radius={'kind': 'host', 'entities': 1, 'ids': [params['host']]})

        async def execute(self, params, ctx):
            return ExecResult(ok=True, summary='exec ok', rollback_payload={'host': params['host']})

    catalog.register(ChangeRecAction)
    try:
        tenant = db.get(Tenant, default_tenant_id)
        assert tenant is not None
        tenant.actions_enabled = True
        db.commit()
        req_p = Principal(tenant_id=default_tenant_id, role=Role.operator, user_id='cr-req', email='cr@test.local')
        req = await broker.request(db, req_p, 'test.change.record', {'host': 'srv-01'}, 'patch', settings=app.state.settings)
        db.commit()
        cr = client.get(f'/api/v1/actions/requests/{req.id}/change-record', headers=headers)
        assert cr.status_code == 200
        doc = cr.json()
        assert doc['schema'] == 'argus.change_record.v1'
        assert doc['change_id'] == f'CHG-ARGUS-{req.id[:12].upper()}'
    finally:
        catalog.unregister('test.change.record')


def test_phase6_autonomy_hard_disabled_and_fips_validation(settings):
    # 1. AUTONOMY_HARD_DISABLED blocks startup if autonomous flags are enabled
    bad_autonomy = settings.model_copy(update={'autonomy_hard_disabled': True, 'autoresponse_enabled': True})
    with pytest.raises(RuntimeError, match='AUTONOMY_HARD_DISABLED'):
        assert_safe_config(bad_autonomy)

    # 2. FIPS_MODE=true requires PASSWORD_HASH_SCHEME=pbkdf2
    bad_fips = settings.model_copy(update={'fips_mode': True, 'password_hash_scheme': 'scrypt'})
    with pytest.raises(RuntimeError, match='FIPS_MODE'):
        assert_safe_config(bad_fips)
    ok_fips = settings.model_copy(update={'fips_mode': True, 'password_hash_scheme': 'pbkdf2'})
    assert_safe_config(ok_fips)


@respx.mock
def test_phase6_healthcare_phi_dlp_and_baa_providers(app, client, owner, settings):
    # 1. PHI patterns (MRN, DOB, Patient Name) and data/image_url scanning
    sample = {
        'model': 'gpt-test',
        'messages': [
            {
                'role': 'user',
                'content': 'Patient Name: Jane Doe, DOB: 1984-05-19, MRN: AB-9928374',
                'image_url': 'data:text/plain;chivo,MRN: ZZ-1122334',
            }
        ],
    }
    hits = dlp.scan(dlp.texts(sample))
    assert hits.get('patient_name') == 1
    assert hits.get('date_of_birth') == 1
    assert hits.get('medical_record_number') == 2

    redacted = dlp.redact_value(sample, dlp.PHI_TYPES)
    msg_content = redacted['messages'][0]['content']
    assert 'Jane Doe' not in msg_content and '[REDACTED:patient_name]' in msg_content
    assert '1984-05-19' not in msg_content and '[REDACTED:date_of_birth]' in msg_content
    assert 'AB-9928374' not in msg_content and '[REDACTED:medical_record_number]' in msg_content
    assert 'ZZ-1122334' not in redacted['messages'][0]['image_url']

    # 2. Response DLP scanning/redaction in AI gateway
    owner_client, headers = owner
    app.state.settings.ai_gateway_enabled = True
    app.state.settings.ai_gateway_openai_api_key = 'upstream-key'
    owner_client.put(
        '/api/v1/ai-gateway/policy',
        json={'dlp_mode': 'redact', 'dlp_types': list(dlp.DEFAULT_ENFORCED) + list(dlp.PHI_TYPES)},
        headers=headers,
    )
    gw_key = owner_client.post(
        '/api/v1/auth/api-keys',
        json={'name': 'phi-gw', 'role': 'analyst', 'scopes': ['ai_gateway:use']},
        headers=headers,
    ).json()['key']

    respx.post('https://api.openai.com/v1/chat/completions').mock(
        return_value=httpx.Response(
            200,
            json={
                'id': 'c1',
                'choices': [{'index': 0, 'message': {'role': 'assistant', 'content': 'Record for Patient: John Smith (MRN: 88776655)'}}],
                'usage': {'prompt_tokens': 10, 'completion_tokens': 10},
            },
        )
    )
    resp = client.post(
        '/api/v1/ai-gateway/openai/v1/chat/completions',
        json={'model': 'gpt-test', 'messages': [{'role': 'user', 'content': 'lookup'}]},
        headers={'Authorization': f'Bearer {gw_key}'},
    )
    assert resp.status_code == 200
    reply_text = resp.json()['choices'][0]['message']['content']
    assert 'John Smith' not in reply_text and '[REDACTED:patient_name]' in reply_text
    assert '88776655' not in reply_text and '[REDACTED:medical_record_number]' in reply_text

    # 3. BAA-covered providers (Bedrock & Azure OpenAI) instantiate cleanly
    assert isinstance(get_provider(settings, override='azure_openai'), AzureOpenAIProvider)
    assert isinstance(get_provider(settings, override='bedrock'), BedrockProvider)


# ==============================================================================
# SELF-AUDIT HARDENING REGRESSION TESTS
# ==============================================================================


def test_audit_review_opaque_session_cookie_csrf_and_must_change_password(app, client, make_user):
    import json

    uid = make_user('temp-pw@test.local', 'temporary-pass-123456', 'analyst')
    owner_headers = login(client, ADMIN_EMAIL, ADMIN_PASSWORD)
    # Admin issues temporary password -> must_change_password = True
    reset_resp = client.post(
        f'/api/v1/admin/users/{uid}/reset-password',
        json={},
        headers=owner_headers,
    )
    assert reset_resp.status_code == 200
    temp_pw = reset_resp.json()['temporary_password']

    client.cookies.clear()
    login_resp = client.post('/api/v1/auth/login', json={'email': 'temp-pw@test.local', 'password': temp_pw})
    assert login_resp.status_code == 200 and login_resp.json().get('password_change_required') is True
    user_csrf = login_resp.json()['csrf']

    # 1. Cookie payload contains ONLY opaque 'sid' (no user_id, csrf, or secrets in cookie)
    raw_cookie = client.cookies.get('argus_session') or ''
    cookie_payload_b64 = raw_cookie.split('.')[0]
    cookie_data = json.loads(base64.b64decode(cookie_payload_b64 + '=' * (-len(cookie_payload_b64) % 4)).decode())
    assert list(cookie_data.keys()) == ['sid']

    # 2. All normal API endpoints are blocked with 403 until password is changed
    assert client.get('/api/v1/ops/jobs').status_code == 403
    assert client.get('/api/v1/auth/session').json()['password_change_required'] is True

    # 3. Missing CSRF on /change-password fails with 403; valid CSRF succeeds and unblocks API
    assert client.post(
        '/api/v1/auth/change-password',
        json={'current_password': temp_pw, 'new_password': 'brand-new-strong-password-456'},
    ).status_code == 403
    changed = client.post(
        '/api/v1/auth/change-password',
        json={'current_password': temp_pw, 'new_password': 'brand-new-strong-password-456'},
        headers={'X-CSRF-Token': user_csrf},
    )
    assert changed.status_code == 200
    new_headers = {'X-CSRF-Token': changed.json()['csrf']}
    assert client.get('/api/v1/ops/jobs', headers=new_headers).status_code == 200

    # 4. CSRF is enforced on /totp/enroll as well
    assert client.post('/api/v1/auth/totp/enroll').status_code == 403
    assert client.post('/api/v1/auth/totp/enroll', headers=new_headers).status_code == 200

    # 5. Deleting session from server store (simulating Redis deletion on another replica) fails closed without fallback
    app.state.session_store._mem.clear()
    assert client.get('/api/v1/ops/jobs', headers=new_headers).status_code == 401


@respx.mock
@pytest.mark.asyncio
async def test_audit_review_broker_multitenant_creds_kms_vault_and_dns_pinning(
    app, db, default_tenant_id, second_tenant, settings, monkeypatch
):
    from app.core import crypto as crypto_mod
    from app.integrations.outbound import request_with_retry
    from app.models.actions import ActionRequest

    # 1. broker.build_context populates _tenant_slug and _multi_tenant=True when >1 tenant exists
    monkeypatch.setenv('ACTIONS_GITHUB_TOKEN', 'global-leaked-gh-token')
    tenant = db.get(Tenant, default_tenant_id)
    dummy_action = next(iter(catalog.all()))
    dummy_req = ActionRequest(tenant_id=default_tenant_id, action_type=dummy_action.name, params_json='{}', reason='r', risk='low')
    fresh_settings = settings.model_copy()
    fresh_settings.model_fields_set.discard('allow_env_action_credentials')
    ctx = broker.build_context(fresh_settings, tenant, dummy_req, dummy_action, db=db)
    assert ctx.tenant_settings['_tenant_slug'] == 'default'
    assert ctx.tenant_settings['_multi_tenant'] is True
    assert credentials.resolve('github', 'token', fresh_settings, ctx.tenant_settings) == ''

    # 2. Vault Transit KMS envelope encryption & decryption with per-tenant DEK wrapping + AAD binding
    wrapped_store: dict[str, str] = {}

    def _vault_encrypt(request: httpx.Request) -> httpx.Response:
        import json as _json

        data = _json.loads(request.content.decode())
        token_ct = f"vault:v1:{data['context']}:{data['plaintext']}"
        wrapped_store[token_ct] = data['plaintext']
        return httpx.Response(200, json={'data': {'ciphertext': token_ct}})

    def _vault_decrypt(request: httpx.Request) -> httpx.Response:
        import json as _json

        data = _json.loads(request.content.decode())
        ct = data['ciphertext']
        expected_ctx = ct.split(':', 3)[2]
        if data['context'] != expected_ctx:
            return httpx.Response(400, json={'errors': ['context mismatch']})
        return httpx.Response(200, json={'data': {'plaintext': wrapped_store[ct]}})

    respx.post('https://vault.internal.test/v1/transit/encrypt/argus-kek').mock(side_effect=_vault_encrypt)
    respx.post('https://vault.internal.test/v1/transit/decrypt/argus-kek').mock(side_effect=_vault_decrypt)
    prev_keys, prev_curr = dict(crypto_mod._keys), crypto_mod._current
    try:
        crypto_mod.configure(
            kms_provider='vault_transit',
            kms_key_id='argus-kek',
            vault_addr='https://vault.internal.test',
            vault_token='s.vault-test-tok',
        )
        aad = bind_aad(tenant_id='t-bank', table='findings', column='evidence')
        ct = encrypt('kms-protected-evidence', tenant_id='t-bank', aad=aad)
        assert ct is not None and ct.startswith('enc:kms:v2:vault_transit:t-bank:')
        crypto_mod._kms_unwrap_cache.clear()  # force real Vault decrypt round-trip
        assert decrypt(ct, tenant_id='t-bank', aad=aad) == 'kms-protected-evidence'
        with pytest.raises(ValueError, match='cannot decrypt kms v2 value'):
            decrypt(ct, tenant_id='t-other', aad=aad)
    finally:
        crypto_mod._keys, crypto_mod._current = prev_keys, prev_curr
        crypto_mod._kms_provider = 'local'
        crypto_mod._kms_key_id = ''

    # 3. Send-time DNS pinning rewrites outbound URL host to validated IP while keeping Host & SNI
    monkeypatch.setattr(
        'socket.getaddrinfo',
        lambda host, port, *a, **kw: [(2, 1, 6, '', ('93.184.216.34', port or 443))],
    )
    captured: list[httpx.Request] = []

    def _pinned_target(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200, json={'ok': True})

    respx.post('https://93.184.216.34/webhook').mock(side_effect=_pinned_target)
    resp, err = await request_with_retry(
        lambda c: c.post('https://hooks.customer-siem.org/webhook', json={'ping': 1}),
        pin_dns=True,
    )
    assert err == '' and resp is not None and resp.status_code == 200
    assert captured[0].url.host == '93.184.216.34'
    assert captured[0].headers['Host'] == 'hooks.customer-siem.org'
    assert captured[0].extensions.get('sni_hostname') == 'hooks.customer-siem.org'

