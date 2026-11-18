"""Regression tests for the identity and separation-of-duties findings from the second security review:
fabricated WebAuthn credentials, a non-SAML "SAML" endpoint, uncapped custom permissions, and approver pools an
administrator could staff alone. Each test is written from the attacker's side."""
from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import pytest
from app.models import Membership, OidcIdentity, User
from fastapi.testclient import TestClient
from sqlalchemy import select
from tests.conftest import ADMIN_EMAIL, login
from tests.support.samlidp import TestIdP
from tests.support.softkey import SoftKey
from tests.test_actions import PW, as_user, enable_actions, fakes, make_request  # noqa: F401 - fakes is a fixture

API = '/api/v1/auth'


# ---------------------------------------------------------------- WebAuthn


def _register(client, headers, key: SoftKey, **overrides):
    options = client.post(f'{API}/webauthn/register/begin', headers=headers)
    assert options.status_code == 200, options.text
    return client.post(f'{API}/webauthn/register/complete',
                       json={'credential': key.attestation(options.json(), **overrides), 'name': 'test key'}, headers=headers)


def _assert(client, headers, key: SoftKey, **overrides):
    options = client.post(f'{API}/webauthn/authenticate/begin', headers=headers)
    assert options.status_code == 200, options.text
    return client.post(f'{API}/webauthn/authenticate/complete', json={'credential': key.assertion(options.json(), **overrides)}, headers=headers)


def test_webauthn_register_then_authenticate(owner, app, db):
    client, headers = owner
    key = SoftKey()
    done = _register(client, headers, key)
    assert done.status_code == 201, done.text
    headers = {'X-CSRF-Token': done.json()['csrf']}
    ok = _assert(client, headers, key)
    assert ok.status_code == 200, ok.text
    # the stored counter follows the authenticator, which is what detects a cloned key
    from app.models import WebAuthnCredential
    assert db.execute(select(WebAuthnCredential.sign_count)).scalar_one() == key.sign_count == 1


def test_webauthn_rejects_a_made_up_credential(owner):
    """The earlier implementation stored any string as the 'public key' and accepted an HMAC of it."""
    client, headers = owner
    options = client.post(f'{API}/webauthn/register/begin', headers=headers).json()
    legacy = client.post(f'{API}/webauthn/register/complete', headers=headers,
                         json={'credential_id': 'x', 'public_key': 'attacker-chosen-string', 'challenge': options['challenge']})
    assert legacy.status_code == 422
    client.post(f'{API}/webauthn/register/begin', headers=headers)
    forged = client.post(f'{API}/webauthn/register/complete', headers=headers,
                         json={'credential': {'id': 'eA', 'rawId': 'eA', 'type': 'public-key',
                                              'response': {'clientDataJSON': 'e30', 'attestationObject': 'e30'}}})
    assert forged.status_code == 401
    assert client.post(f'{API}/webauthn/authenticate/begin', headers=headers).status_code == 409  # nothing was stored


def test_webauthn_binds_to_origin_key_and_challenge(owner):
    client, headers = owner
    key = SoftKey()
    assert _register(client, headers, SoftKey(), origin='https://argus.evil.example').status_code == 401  # wrong origin at registration
    done = _register(client, headers, key)
    headers = {'X-CSRF-Token': done.json()['csrf']}
    # an assertion relayed from a look-alike site carries that site's origin and never verifies here
    assert _assert(client, headers, key, origin='https://argus.evil.example').status_code == 401
    assert _assert(client, headers, key, rp_id='evil.example').status_code == 401
    assert _assert(client, headers, key, signing_key=SoftKey().private_key).status_code == 401
    assert _assert(client, headers, key, user_verified=False).status_code == 401
    # a captured assertion cannot be replayed: its challenge was consumed
    options = client.post(f'{API}/webauthn/authenticate/begin', headers=headers).json()
    captured = key.assertion(options)
    assert client.post(f'{API}/webauthn/authenticate/complete', json={'credential': captured}, headers=headers).status_code == 200
    assert client.post(f'{API}/webauthn/authenticate/complete', json={'credential': captured}, headers=headers).status_code == 401


def test_password_alone_cannot_attach_an_authenticator_when_codes_are_required(app, client, make_user, owner):
    owner_client, owner_headers = owner
    app.state.settings.totp_required = True
    app.state.settings.totp_require_enrollment_code = True
    try:
        uid = make_user('victim@test.local', PW, 'operator')
        attacker = TestClient(app)
        r = attacker.post(f'{API}/login', json={'email': 'victim@test.local', 'password': PW})
        headers = {'X-CSRF-Token': r.json()['csrf']}
        assert r.json().get('mfa_required') is True
        assert attacker.post(f'{API}/webauthn/register/begin', headers=headers).status_code == 403
        assert attacker.post(f'{API}/totp/enroll', headers=headers).status_code == 403
        assert attacker.get('/api/v1/findings').status_code == 401
        # with the administrator's one-time code the real user can enrol, and the code is single use
        app.state.settings.totp_required = False
        code = owner_client.post(f'/api/v1/admin/users/{uid}/totp-enrollment-token', headers=owner_headers)
        app.state.settings.totp_required = True
        if code.status_code == 200:
            token = code.json()['enrollment_code']
            begin = attacker.post(f'{API}/webauthn/register/begin', json={'enrollment_code': token}, headers=headers)
            assert begin.status_code == 200
            assert attacker.post(f'{API}/webauthn/register/begin', json={'enrollment_code': token}, headers=headers).status_code == 403
    finally:
        app.state.settings.totp_required = False
        app.state.settings.totp_require_enrollment_code = False


def test_a_registered_passkey_is_required_at_sign_in(app, client, make_user):
    make_user('pk@test.local', PW, 'operator')
    first = TestClient(app)
    headers = login(first, 'pk@test.local', PW)
    key = SoftKey()
    done = _register(first, headers, key)
    assert done.status_code == 201
    # a later password-only sign-in is not enough any more
    second = TestClient(app)
    r = second.post(f'{API}/login', json={'email': 'pk@test.local', 'password': PW})
    assert r.status_code == 200 and r.json().get('mfa_required') is True
    headers2 = {'X-CSRF-Token': r.json()['csrf']}
    assert second.get('/api/v1/findings').status_code == 401
    # ...and that half-authenticated session cannot add a second authenticator of its own
    assert second.post(f'{API}/webauthn/register/begin', headers=headers2).status_code == 403
    assert second.post(f'{API}/totp/enroll', headers=headers2).status_code == 403
    assert _assert(second, headers2, key).status_code == 200
    assert second.get('/api/v1/findings').status_code == 200


# ---------------------------------------------------------------- SAML


@pytest.fixture
def idp(app):
    provider = TestIdP()
    s = app.state.settings
    s.saml_idp_entity_id, s.saml_idp_sso_url, s.saml_idp_cert_pem = provider.entity_id, 'https://idp.corp.example/sso', provider.cert_pem
    yield provider
    s.saml_idp_entity_id = s.saml_idp_sso_url = s.saml_idp_cert_pem = ''
    s.oidc_group_role_map = ''


def _start(client) -> tuple[str, str]:
    """Begin SP-initiated sign-in; returns (AuthnRequest ID, RelayState) the way an IdP would see them."""
    import base64
    import zlib
    redirect = client.get(f'{API}/saml/login', follow_redirects=False)
    assert redirect.status_code == 302, redirect.text
    query = parse_qs(urlparse(redirect.headers['location']).query)
    xml = zlib.decompress(base64.b64decode(query['SAMLRequest'][0]), -15).decode()
    return xml.split(' ID="', 1)[1].split('"', 1)[0], query['RelayState'][0]


def _post(client, saml_response: str, relay_state: str):
    return client.post(f'{API}/saml/acs', data={'SAMLResponse': saml_response, 'RelayState': relay_state}, follow_redirects=False)


def test_saml_sign_in_with_a_signed_assertion(app, client, idp, db):
    app.state.settings.oidc_group_role_map = 'saml-analysts=default:analyst'
    base = app.state.settings.base_url
    assert 'AssertionConsumerService' in client.get(f'{API}/saml/metadata').text
    request_id, relay = _start(client)
    response = idp.response(base_url=base, in_response_to=request_id, email='saml-user@test.local', groups=['saml-analysts'],
                            extra_attributes={'department': ['saml-admins']})
    done = _post(client, response, relay)
    assert done.status_code == 303, done.text
    session = client.get(f'{API}/session').json()
    assert session['authenticated'] and session['user']['email'] == 'saml-user@test.local' and session['role'] == 'analyst'
    user = db.execute(select(User).where(User.email == 'saml-user@test.local')).scalar_one()
    assert db.execute(select(OidcIdentity).where(OidcIdentity.user_id == user.id)).scalar_one().issuer == idp.entity_id
    # the same response a second time: its request ID was consumed
    assert _post(TestClient(app), response, relay).status_code == 401


def test_saml_rejects_forged_and_out_of_context_responses(app, client, idp):
    base = app.state.settings.base_url
    cases = {
        'unsigned': dict(sign=False),
        'wrong audience': dict(audience='https://other-sp.example/metadata'),
        'wrong recipient': dict(recipient='https://other-sp.example/acs'),
        'expired': dict(valid_for=-120),
    }
    for label, kwargs in cases.items():
        request_id, relay = _start(client)
        r = _post(client, idp.response(base_url=base, in_response_to=request_id, email='x@test.local', **kwargs), relay)
        assert r.status_code == 401, label
    # signed by a key that is not the configured IdP's
    request_id, relay = _start(client)
    assert _post(client, TestIdP().response(base_url=base, in_response_to=request_id, email='x@test.local'), relay).status_code == 401
    # a response nobody asked for (IdP-initiated, or one minted for a different sign-in)
    request_id, relay = _start(client)
    assert _post(client, idp.response(base_url=base, in_response_to=request_id, email='x@test.local'), '').status_code == 401
    other_id, other_relay = _start(client)
    assert _post(client, idp.response(base_url=base, in_response_to='_someone-elses-request', email='x@test.local'), other_relay).status_code == 401
    assert client.get(f'{API}/session').json()['authenticated'] is False


def test_saml_does_not_sign_in_a_disabled_account(app, client, idp, make_user, db):
    uid = make_user('gone@test.local', PW, 'operator')
    db.get(User, uid).is_active = False
    db.commit()
    request_id, relay = _start(client)
    r = _post(client, idp.response(base_url=app.state.settings.base_url, in_response_to=request_id, email='gone@test.local'), relay)
    assert r.status_code == 403, r.text


# ---------------------------------------------------------------- permission ceiling


def _member(client, headers, email):
    return next(u for u in client.get('/api/v1/admin/users', headers=headers).json()['items'] if u['email'] == email)


def test_custom_permissions_cannot_exceed_the_granter(app, owner, make_user):
    owner_client, owner_headers = owner
    make_user('ua@test.local', PW, 'user_admin')
    make_user('peer@test.local', PW, 'viewer')
    ua, ua_headers = as_user(app, 'ua@test.local', PW)
    me, peer = _member(ua, ua_headers, 'ua@test.local'), _member(ua, ua_headers, 'peer@test.local')
    # on create
    r = ua.post('/api/v1/admin/users', json={'email': 'puppet@test.local', 'role': 'viewer', 'password': PW,
                                             'permissions': ['actions:approve']}, headers=ua_headers)
    assert r.status_code == 403
    # on an existing member, and on themselves
    for target in (peer, me):
        r = ua.post('/api/v1/admin/memberships', json={'user_id': target['id'], 'role': target['role'], 'permissions': ['admin:tenant']}, headers=ua_headers)
        assert r.status_code == 403, target['email']
    assert ua.post('/api/v1/admin/tenants', json={'slug': 'evil', 'name': 'evil'}, headers=ua_headers).status_code == 403
    # names that are not permissions are refused rather than stored
    r = ua.post('/api/v1/admin/memberships', json={'user_id': peer['id'], 'role': 'viewer', 'permissions': ['root:everything']}, headers=ua_headers)
    assert r.status_code == 400
    # what the granter holds, they can delegate; a deny entry only removes access
    r = ua.post('/api/v1/admin/memberships', json={'user_id': peer['id'], 'role': 'viewer', 'permissions': ['admin:users', '-findings:read']}, headers=ua_headers)
    assert r.status_code == 200 and r.json()['permissions'] == ['-findings:read', 'admin:users']
    # ...but lifting a deny for a permission they lack is a grant, and is held to the same ceiling
    owner_client.post('/api/v1/admin/memberships', json={'user_id': peer['id'], 'role': 'viewer', 'permissions': ['-actions:approve']}, headers=owner_headers)
    r = ua.post('/api/v1/admin/memberships', json={'user_id': peer['id'], 'role': 'viewer', 'permissions': []}, headers=ua_headers)
    assert r.status_code == 403
    # nobody edits their own grants, not even the owner
    own = _member(owner_client, owner_headers, ADMIN_EMAIL)
    r = owner_client.post('/api/v1/admin/memberships', json={'user_id': own['id'], 'role': 'owner', 'permissions': ['-audit:read']}, headers=owner_headers)
    assert r.status_code == 403


# ---------------------------------------------------------------- separation of duties


def test_an_account_cannot_approve_requests_from_accounts_it_created(app, owner, fakes):  # noqa: F811
    owner_client, owner_headers = owner
    enable_actions(owner_client, owner_headers)
    created = owner_client.post('/api/v1/admin/users', json={'email': 'made@test.local', 'role': 'operator', 'password': PW}, headers=owner_headers)
    assert created.status_code == 201
    made, made_headers = as_user(app, 'made@test.local', PW)
    rid = make_request(made, made_headers, action_type='test.fake.high', target='srv-1')['id']
    r = owner_client.post(f'/api/v1/actions/requests/{rid}/approve', json={'decision': 'approve'}, headers=owner_headers)
    assert r.status_code == 403 and 'created the requesting account' in r.text


def test_federated_approvers_only(app, owner, make_user, fakes, db):  # noqa: F811
    """With the requirement on, accounts an administrator can mint locally do not count as approvers."""
    owner_client, owner_headers = owner
    enable_actions(owner_client, owner_headers)
    make_user('req@test.local', PW, 'operator')
    local_id = make_user('local@test.local', PW, 'operator')
    sso_id = make_user('sso@test.local', PW, 'operator')
    db.add(OidcIdentity(user_id=sso_id, issuer='https://idp.example.test', subject='sub-1'))
    db.commit()
    requester, rh = as_user(app, 'req@test.local', PW)
    rid = make_request(requester, rh, action_type='test.fake.medium', target='srv-2')['id']
    app.state.settings.approvers_must_be_federated = True
    try:
        local, lh = as_user(app, 'local@test.local', PW)
        r = local.post(f'/api/v1/actions/requests/{rid}/approve', json={'decision': 'approve'}, headers=lh)
        assert r.status_code == 403 and 'identity provider' in r.text
        # a key minted by the local account inherits its (non-federated) identity
        key = owner_client.post(f'{API}/api-keys', json={'name': 'k', 'role': 'operator'}, headers=owner_headers).json()['key']
        r = TestClient(app).post(f'/api/v1/actions/requests/{rid}/approve', json={'decision': 'approve'}, headers={'X-API-Key': key})
        assert r.status_code == 403
        sso, sh = as_user(app, 'sso@test.local', PW)
        r = sso.post(f'/api/v1/actions/requests/{rid}/approve', json={'decision': 'approve'}, headers=sh)
        assert r.status_code == 200, r.text
    finally:
        app.state.settings.approvers_must_be_federated = None
    assert local_id and db.execute(select(Membership).where(Membership.user_id == local_id)).scalar_one().role == 'operator'


def test_federated_approvers_default_follows_production_sso(settings):
    assert settings.federated_approvers_required is False
    prod = settings.model_copy(update={'app_env': 'production', 'oidc_issuer': 'https://idp.example.test'})
    assert prod.federated_approvers_required is True
    assert prod.model_copy(update={'approvers_must_be_federated': False}).federated_approvers_required is False


# ---------------------------------------------------------------- SCIM

SCIM = '/api/v1/scim/v2'
SCIM_TOKEN = 'scim-provisioning-token-0123456789abcdef'


@pytest.fixture
def scim(app):
    app.state.settings.scim_bearer_token = SCIM_TOKEN
    yield {'Authorization': f'Bearer {SCIM_TOKEN}'}
    app.state.settings.scim_bearer_token = ''


def test_scim_accepts_only_the_provisioning_token(app, owner, scim, make_user):
    owner_client, owner_headers = owner
    # a signed-in administrator is not the identity provider (this path used to crash with a 500)
    assert owner_client.get(f'{SCIM}/Users', headers=owner_headers).status_code == 401
    assert TestClient(app).get(f'{SCIM}/Users', headers={'Authorization': 'Bearer wrong'}).status_code == 401
    app.state.settings.scim_bearer_token = ''
    assert TestClient(app).get(f'{SCIM}/Users', headers=scim).status_code == 404
    app.state.settings.scim_bearer_token = SCIM_TOKEN
    assert TestClient(app).get(f'{SCIM}/ServiceProviderConfig', headers=scim).json()['filter']['supported'] is True


def test_scim_lookup_by_username_and_paging(app, client, scim, make_user):
    for n in range(3):
        make_user(f'person{n}@test.local', PW, 'viewer')
    found = client.get(f'{SCIM}/Users', params={'filter': 'userName eq "Person1@test.local"'}, headers=scim).json()
    assert found['totalResults'] == 1 and found['Resources'][0]['userName'] == 'person1@test.local'
    assert client.get(f'{SCIM}/Users/{found["Resources"][0]["id"]}', headers=scim).json()['userName'] == 'person1@test.local'
    missing = client.get(f'{SCIM}/Users', params={'filter': 'userName eq "nobody@test.local"'}, headers=scim).json()
    assert missing['totalResults'] == 0 and missing['Resources'] == []
    page = client.get(f'{SCIM}/Users', params={'startIndex': 2, 'count': 2}, headers=scim).json()
    assert page['totalResults'] == 4 and page['itemsPerPage'] == 2 and page['startIndex'] == 2
    assert client.get(f'{SCIM}/Users', params={'filter': 'emails.value co "test"'}, headers=scim).status_code == 400


def test_scim_deprovisioning_respects_owners_and_other_tenants(app, client, scim, make_user, second_tenant, db):
    owner_row = client.get(f'{SCIM}/Users', params={'filter': f'userName eq "{ADMIN_EMAIL}"'}, headers=scim).json()['Resources'][0]
    assert client.delete(f'{SCIM}/Users/{owner_row["id"]}', headers=scim).status_code == 409  # never lock the tenant out
    shared = make_user('shared@test.local', PW, 'operator')
    make_user('shared@test.local', PW, 'operator', tenant_id=second_tenant['tenant_id'])
    assert client.delete(f'{SCIM}/Users/{shared}', headers=scim).status_code == 204
    db.expire_all()
    assert db.get(User, shared).is_active is True  # still a member of the other tenant, so the account stays usable there
    assert db.execute(select(Membership).where(Membership.user_id == shared)).scalar_one().tenant_id == second_tenant['tenant_id']
    solo = make_user('solo@test.local', PW, 'operator')
    assert client.delete(f'{SCIM}/Users/{solo}', headers=scim).status_code == 204
    db.expire_all()
    assert db.get(User, solo).is_active is False


# ---------------------------------------------------------------- per-tenant sealing of encrypted columns


def test_encrypted_columns_are_sealed_under_the_writing_tenant(app, client, second_tenant, default_tenant_id):
    from app.core import crypto
    from app.core.db import set_tenant_context
    from app.models import Finding
    from sqlalchemy import text

    ids = {}
    for tenant_id in (default_tenant_id, second_tenant['tenant_id']):
        with app.state.db_factory() as db:
            set_tenant_context(db, tenant_id)
            row = Finding(tenant_id=tenant_id, source='t', rule='r', title='t', description='d', remediation='r', severity=1,
                          fingerprint=f'fp-{tenant_id}', evidence='{"secret": "same plaintext"}')
            db.add(row)
            db.commit()
            ids[tenant_id] = row.id
    with app.state.db_factory() as db:
        raw = {t: db.execute(text('SELECT evidence FROM findings WHERE id = :i'), {'i': i}).scalar_one() for t, i in ids.items()}
    for tenant_id, blob in raw.items():
        assert blob.startswith(crypto.PREFIX_V2) and f':{tenant_id}:' in blob and 'same plaintext' not in blob
        assert crypto.decrypt(blob) == '{"secret": "same plaintext"}'
    # each tenant's rows are under a different derived key: relabelling a ciphertext to another tenant does not decrypt
    a, b = default_tenant_id, second_tenant['tenant_id']
    with pytest.raises(ValueError):
        crypto.decrypt(raw[a].replace(f':{a}:', f':{b}:'))
    # account-level columns stay unbound, so a user who belongs to two tenants can always be read
    assert crypto.flush_tenant.get() == ''


# ---------------------------------------------------------------- tenant-scoped secret references


def test_a_tenant_cannot_resolve_another_tenants_secret(app, db, settings, second_tenant, default_tenant_id, monkeypatch):
    from app.core.security import tenant_secret_scope
    from app.integrations.delivery import resolve_secrets

    monkeypatch.setenv('ARGUS_SECRET_ACME_SLACK', 'acme-webhook-secret')
    monkeypatch.setenv('ARGUS_SECRET_DEFAULT_SLACK', 'default-webhook-secret')
    assert tenant_secret_scope(db, settings, default_tenant_id) == ('default', True)  # a second tenant exists
    # the default tenant's admin points an integration at the other tenant's variable: nothing comes back
    stolen = resolve_secrets({'token': 'env:ARGUS_SECRET_ACME_SLACK'}, settings, db, default_tenant_id)
    assert stolen == {}
    assert resolve_secrets({'token': 'env:ARGUS_SECRET_DEFAULT_SLACK'}, settings, db, default_tenant_id) == {'token': 'default-webhook-secret'}
    assert resolve_secrets({'token': 'env:ARGUS_SECRET_ACME_SLACK'}, settings, db, second_tenant['tenant_id']) == {'token': 'acme-webhook-secret'}
    # an unknown tenant id fails closed rather than falling back to the shared namespace
    assert resolve_secrets({'token': 'env:ARGUS_SECRET_ACME_SLACK'}, settings, db, 'no-such-tenant') == {}
    # operators can still switch isolation off explicitly
    relaxed = settings.model_copy(update={'tenant_secret_isolation': False})
    assert resolve_secrets({'token': 'env:ARGUS_SECRET_ACME_SLACK'}, relaxed, db, default_tenant_id) == {'token': 'acme-webhook-secret'}


def test_single_tenant_deployments_keep_plain_secret_names(app, client, db, settings, default_tenant_id, monkeypatch):
    from app.integrations.delivery import resolve_secrets

    monkeypatch.setenv('ARGUS_SECRET_SLACK', 'plain')
    assert resolve_secrets({'token': 'env:ARGUS_SECRET_SLACK'}, settings, db, default_tenant_id) == {'token': 'plain'}


# ---------------------------------------------------------------- audit delivery runs on a schedule


def test_scheduler_retries_audit_delivery_and_anchors_the_chain(app, client, db, default_tenant_id):
    """Retry and anchoring used to happen only when an administrator called an endpoint."""
    import asyncio
    import time
    from datetime import timedelta

    from app.core import audit as audit_mod
    from app.core.audit import AuditSink, record_audit
    from app.models import utcnow
    from app.models.audit import AuditOutbox
    from app.ops import audit_tick, maintain_audit

    seen = {'writes': 0, 'anchors': []}

    class Flaky(AuditSink):
        name = 'flaky_worm'

        def write(self, record: dict) -> None:
            if record.get('kind') == 'chain_head_anchor':
                seen['anchors'].append(record)
                return
            seen['writes'] += 1
            if seen['writes'] == 1:
                raise RuntimeError('sink timeout')

    sink = Flaky()
    audit_mod._sinks.append(sink)
    try:
        record_audit(db, 'admin@test.local', 'test.outbox', 's', {'k': 'v'}, tenant_id=default_tenant_id)
        db.commit()
        pending = db.execute(select(AuditOutbox).where(AuditOutbox.sink_name == 'flaky_worm', AuditOutbox.delivered_at.is_(None))).scalars().all()
        assert len(pending) == 1
        pending[0].next_attempt_at = utcnow() - timedelta(seconds=1)
        db.commit()
        # what the job does
        result = maintain_audit(app.state.db_factory, default_tenant_id, anchor=True)
        assert result['delivered'] == 1 and result['backlog'] == 0
        assert seen['anchors'][-1]['tenant_id'] == default_tenant_id and seen['anchors'][-1]['head_entry_id'] == result['anchored_entry_id'] > 0
        # and the periodic tick is what runs it: one job per active tenant, anchoring on the first tick of the hour
        hour = 3600 * 500_000
        anchors_before = len(seen['anchors'])
        assert len(asyncio.run(audit_tick(app, now=hour + 5))) == 1
        deadline = time.time() + 20
        while len(seen['anchors']) == anchors_before and time.time() < deadline:
            time.sleep(0.1)
        assert len(seen['anchors']) == anchors_before + 1
    finally:
        audit_mod._sinks.remove(sink)
