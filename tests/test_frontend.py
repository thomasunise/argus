"""Browser tests for the operations console (app/static). A real uvicorn server runs in a thread on a
free port with a temporary SQLite database seeded from scripts/seed_demo.py; Playwright drives the
system Microsoft Edge. Skipped entirely when Edge or Playwright is unavailable.

Also produces docs/screenshots/*.png (overview, findings, graph, actions in both themes).
"""
from __future__ import annotations

import os
import socket
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

os.environ.setdefault('ARGUS_LAZY_APP', '1')
os.environ['ADMIN_PASSWORD'] = 'test-password-very-long-123456'
os.environ['ADMIN_EMAIL'] = 'admin@test.local'
os.environ['SESSION_SECRET'] = 'session-secret-testing-longer-than-32-characters'
os.environ['INGEST_API_KEY'] = 'argus_0123abcd_ingest-key-testing-longer-than-24-characters'
os.environ.pop('AI_PROVIDER', None)
os.environ.pop('REDIS_URL', None)

ROOT = Path(__file__).resolve().parents[1]
SCREENSHOTS = ROOT / 'docs' / 'screenshots'
ADMIN_EMAIL = 'admin@test.local'
ADMIN_PASSWORD = 'test-password-very-long-123456'
OPERATOR_EMAIL = 'operator@test.local'
OPERATOR_PASSWORD = 'operator-password-long-123456'
ANALYST_EMAIL = 'analyst@test.local'
ANALYST_PASSWORD = 'analyst-password-long-123456'

PAGES = [
    'overview', 'assets', 'findings', 'events', 'graph', 'graph/paths', 'graph/exposures',
    'detections', 'detections/rules', 'detections/canaries', 'collectors', 'collectors/types',
    'agents', 'agents/runs', 'agents/evals', 'agents/tools', 'testing', 'testing/plans', 'testing/runs', 'testing/adapters',
    'actions', 'actions/requests', 'actions/runs', 'actions/requests/new',
    'integrations', 'integrations/types', 'integrations/ingest', 'integrations/deliveries', 'integrations/batches',
    'audit', 'reports', 'reports/compliance', 'reports/trends', 'admin', 'admin/keys', 'admin/tenants', 'admin/settings',
]


def _edge_available() -> bool:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return False
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(channel='msedge', headless=True)
            browser.close()
        return True
    except Exception:
        return False


EDGE = _edge_available()
pytestmark = pytest.mark.skipif(not EDGE, reason='Microsoft Edge (Playwright channel msedge) is not available')


# ---------------------------------------------------------------- server


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def seed(app) -> dict:
    """Seed the default tenant with the synthetic DEMO records from scripts/seed_demo.py plus extra users and graph edges."""
    import sys

    sys.path.insert(0, str(ROOT / 'scripts'))
    import seed_demo  # noqa: E402
    from sqlalchemy import select

    from app.core.findings import refresh_open_metrics
    from app.core.security import hash_password
    from app.graph import service as graph
    from app.models import Finding, Membership, User

    settings = app.state.settings
    tenant_id = app.state.default_tenant_id
    now = datetime.now(timezone.utc)
    out: dict = {'tenant_id': tenant_id}
    with app.state.db_factory() as db:
        owner = db.execute(select(User).where(User.email == ADMIN_EMAIL)).scalar_one()
        for email, password, role in ((OPERATOR_EMAIL, OPERATOR_PASSWORD, 'operator'), (ANALYST_EMAIL, ANALYST_PASSWORD, 'analyst')):
            user = User(email=email, display_name=email.split('@')[0], password_hash=hash_password(password))
            db.add(user)
            db.flush()
            db.add(Membership(user_id=user.id, tenant_id=tenant_id, role=role))
        assets = seed_demo._assets(db, tenant_id, owner.id, now)
        seed_demo._events(db, tenant_id, assets, now)
        seed_demo._findings(db, tenant_id, assets)
        seed_demo._canary(db, tenant_id, owner.id, settings)
        bucket = db.execute(select(Finding).where(Finding.tenant_id == tenant_id, Finding.rule == 'demo.public_bucket')).scalar_one()
        seed_demo._agent_run(db, tenant_id, owner.id, bucket.id, now)
        refresh_open_metrics(db, tenant_id)
        # a small evidence graph so the neighbourhood view and attack paths have something to draw
        for asset in assets.values():
            graph.link_asset(db, asset)
        internet = graph.upsert_node(db, tenant_id, 'exposure', 'internet:portal.demo.example:443', {'port': 443, 'internet_facing': True}, 'demo', label='Internet exposure :443')
        orders = graph.upsert_node(db, tenant_id, 'data_store', 'postgres:orders-db', {'engine': 'postgres', 'pii': True}, 'demo', label='Orders database', criticality='critical')
        deployer = graph.upsert_node(db, tenant_id, 'identity', 'aws:iam:user/demo-ci-deployer', {'provider': 'aws'}, 'demo', label='demo-ci-deployer', criticality='high')
        portal = db.get(type(internet), assets['web_prod'].graph_node_id)
        bucket_node = db.get(type(internet), assets['bucket'].graph_node_id)
        graph.upsert_edge(db, tenant_id, internet.id, portal.id, 'exposes', {}, 'demo')
        graph.upsert_edge(db, tenant_id, portal.id, orders.id, 'connects_to', {'port': 5432}, 'demo')
        graph.upsert_edge(db, tenant_id, deployer.id, bucket_node.id, 'can_write', {}, 'demo')
        graph.upsert_edge(db, tenant_id, deployer.id, portal.id, 'deploys', {}, 'demo')
        graph.recompute(db, tenant_id)
        seed_demo._run_detections(db, tenant_id, settings)
        db.commit()
        out['finding_id'] = bucket.id
        out['portal_node_id'] = portal.id
        out['asset_ids'] = {k: a.id for k, a in assets.items()}
    return out


def boot_server(tmp_dir: Path) -> dict:
    """Start uvicorn on a free port in a daemon thread and seed the database. Returns a context dict."""
    import uvicorn

    from app.core.config import Settings
    from app.main import create_app

    port = _free_port()
    settings = Settings(database_url=f'sqlite:///{tmp_dir}/frontend.db', scan_root=tmp_dir / 'repos', autoscan_enabled=False, enable_trivy=False,
                        ai_provider='none', allow_private_targets=False, metrics_enabled=False, audit_jsonl_path=str(tmp_dir / 'audit.jsonl'),
                        audit_signing_key='test-signing-key', app_env='development', workers_inprocess=True, worker_concurrency=2,
                        actions_kill_switch=False, base_url=f'http://127.0.0.1:{port}')
    app = create_app(settings)
    server = uvicorn.Server(uvicorn.Config(app, host='127.0.0.1', port=port, log_level='warning', lifespan='on'))
    thread = threading.Thread(target=server.run, daemon=True, name='argus-frontend-test')
    thread.start()
    import urllib.request

    deadline = time.time() + 30
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f'http://127.0.0.1:{port}/health', timeout=1) as resp:
                if resp.status == 200 and getattr(app.state, 'default_tenant_id', None):
                    break
        except Exception:
            time.sleep(0.1)
    else:
        raise RuntimeError('server did not start')
    ctx = {'url': f'http://127.0.0.1:{port}', 'app': app, 'server': server, 'thread': thread}
    ctx.update(seed(app))
    return ctx


@pytest.fixture(scope='module')
def server(tmp_path_factory):
    ctx = boot_server(tmp_path_factory.mktemp('frontend'))
    yield ctx
    ctx['server'].should_exit = True
    ctx['thread'].join(timeout=10)


@pytest.fixture(scope='module')
def browser():
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        browser = p.chromium.launch(channel='msedge', headless=True)
        yield browser
        browser.close()


class Session:
    def __init__(self, browser, url: str, viewport=(1400, 900)):
        self.context = browser.new_context(viewport={'width': viewport[0], 'height': viewport[1]}, device_scale_factor=1)
        self.page = self.context.new_page()
        self.url = url
        self.errors: list[str] = []
        self.page.on('console', lambda m: self.errors.append(f'console.{m.type}: {m.text}') if m.type == 'error' else None)
        self.page.on('pageerror', lambda e: self.errors.append(f'pageerror: {e}'))
        self.page.on('response', lambda r: self.errors.append(f'http {r.status} {r.request.method} {r.url}') if r.status >= 400 else None)

    def login(self, email: str, password: str):
        self.page.goto(self.url + '/')
        self.page.wait_for_selector('#login-form input[name=email]')
        self.page.fill('#login-form input[name=email]', email)
        self.page.fill('#login-form input[name=password]', password)
        self.page.click('#login-form button[type=submit]')
        self.page.wait_for_selector('#shell:not(.hidden)')
        wait_overview(self)
        return self

    def goto(self, route: str, settle: float = 0.4):
        self.page.goto(f'{self.url}/#/{route}')
        self.page.wait_for_selector('#main .page-heading', timeout=15000)
        self.page.wait_for_function("() => !document.querySelector('#main .loading')", timeout=15000)
        self.page.wait_for_timeout(int(settle * 1000))
        return self

    def close(self):
        self.context.close()


@pytest.fixture
def session(browser, server):
    s = Session(browser, server['url'])
    yield s
    s.close()


def wait_toast(page, text: str, timeout: int = 10000):
    try:
        page.wait_for_selector(f'#toast-area .toast:has-text("{text}")', timeout=timeout)
    except Exception as exc:  # report what the page showed instead, for diagnosis
        shown = page.inner_text('#toast-area') if page.query_selector('#toast-area') else '<no toast area>'
        drawer = page.inner_text('#drawer') if page.query_selector('#drawer') else ''
        raise AssertionError(f'toast {text!r} not shown; toasts={shown!r}; drawer={drawer[:400]!r}') from exc


def wait_overview(s: Session, timeout: int = 15000):
    """Wait for the overview metric strip; on timeout raise with the page state for diagnosis."""
    try:
        s.page.wait_for_selector('#main .metric-grid', timeout=timeout)
    except Exception as exc:  # noqa: BLE001
        raise AssertionError(f'overview did not render: {exc.__class__.__name__}; url={s.page.url}; errors={s.errors[:5]}; '
                             f'main={s.page.inner_text("#main")[:300]!r}') from None


# ---------------------------------------------------------------- tests


def test_login_shows_shell_and_session(session, server):
    s = session.login(ADMIN_EMAIL, ADMIN_PASSWORD)
    assert s.page.inner_text('#profile-name') == 'Administrator' or 'admin' in s.page.inner_text('#profile-name').lower()
    assert 'owner' in s.page.inner_text('#profile-role').lower()
    assert s.page.locator('#navigation .nav-item').count() >= 14
    assert not s.errors, s.errors


def test_wrong_password_is_reported_inline(session):
    page = session.page
    page.goto(session.url + '/')
    page.wait_for_selector('#login-form input[name=email]')
    page.fill('#login-form input[name=email]', ADMIN_EMAIL)
    page.fill('#login-form input[name=password]', 'definitely-wrong-password')
    page.click('#login-form button[type=submit]')
    page.wait_for_selector('#login-error:not(:empty)')
    assert 'Invalid credentials' in page.inner_text('#login-error')
    assert page.locator('#shell').get_attribute('class') and 'hidden' in page.locator('#shell').get_attribute('class')


def test_every_page_renders_without_console_errors(session):
    s = session.login(ADMIN_EMAIL, ADMIN_PASSWORD)
    failures = []
    for route in PAGES:
        s.errors.clear()
        try:
            s.goto(route)
        except Exception as exc:  # noqa: BLE001 - we want the full list
            failures.append(f'{route}: did not render ({type(exc).__name__}: {str(exc)[:120]})')
            continue
        if s.page.locator('#main .error-box').count():
            failures.append(f'{route}: error box: {s.page.locator("#main .error-box").first.inner_text()[:160]}')
        if s.errors:
            failures.append(f'{route}: {s.errors[:3]}')
    assert not failures, '\n'.join(failures)


def test_viewer_role_hides_write_actions(session, server):
    s = session.login(ANALYST_EMAIL, ANALYST_PASSWORD)
    s.goto('assets')
    assert s.page.locator('[data-act=create]').count() == 0
    assert s.page.locator('#navigation [data-page=admin]').count() == 0
    s.goto('findings')
    s.page.click('#main tbody tr[data-act=open]')
    s.page.wait_for_selector('#drawer [data-act=status]')  # analysts can change status
    assert not s.errors, s.errors


def test_create_asset_and_authorize(session):
    s = session.login(ADMIN_EMAIL, ADMIN_PASSWORD)
    s.goto('assets')
    s.page.click('[data-act=create]')
    s.page.wait_for_selector('#drawer form')
    s.page.fill('#drawer form [name=name]', 'Browser test portal')
    s.page.select_option('#drawer form [name=kind]', 'web')
    s.page.fill('#drawer form [name=target]', 'https://browser-test.example.com')
    s.page.select_option('#drawer form [name=environment]', 'staging')
    s.page.fill('#drawer form [name=tags]', 'browser, e2e')
    s.page.click('#drawer form button[type=submit]')
    wait_toast(s.page, 'Registered Browser test portal')
    s.page.wait_for_selector('#main tbody tr:has-text("Browser test portal")')
    s.page.click('#main tbody tr:has-text("Browser test portal")')
    s.page.wait_for_selector('#main [data-act=authorize]')
    s.page.click('#main [data-act=authorize]')
    s.page.wait_for_selector('#drawer form [name=attestation]')
    s.page.fill('#drawer form [name=attestation]', 'I confirm that the browser test team controls browser-test.example.com and may test it.')
    s.page.check('#drawer form [name=allow_active]')
    s.page.fill('#drawer form [name=scope_document_ref]', 'E2E-SCOPE-1')
    s.page.click('#drawer form button[type=submit]')
    wait_toast(s.page, 'Authorization recorded')
    s.page.wait_for_selector('#main [data-act=revoke]')
    assert 'E2E-SCOPE-1' in s.page.inner_text('#main')
    assert not s.errors, s.errors


def test_change_finding_status_through_drawer(session, server):
    s = session.login(ADMIN_EMAIL, ADMIN_PASSWORD)
    s.goto(f'findings/{server["finding_id"]}')
    s.page.wait_for_selector('#drawer [data-act=status][data-status=investigating]')
    s.page.click('#drawer [data-act=status][data-status=investigating]')
    wait_toast(s.page, 'Status set to Investigating')
    s.page.wait_for_selector('#drawer .state-tag.investigating')
    # and back, so other tests see an open finding
    s.page.click('#drawer [data-act=status][data-status=open]')
    wait_toast(s.page, 'Status set to Open')
    s.page.wait_for_selector('#drawer .state-tag.open')
    assert not s.errors, s.errors


def test_create_canary_and_copy_url(session):
    s = session.login(ADMIN_EMAIL, ADMIN_PASSWORD)
    s.goto('detections/canaries')
    s.page.click('[data-act=canary-create]')
    s.page.wait_for_selector('#drawer form [name=label]')
    s.page.select_option('#drawer form [name=kind]', 'url')
    s.page.fill('#drawer form [name=label]', 'Browser test canary')
    s.page.fill('#drawer form [name=placement]', 'README of the test repository')
    s.page.click('#drawer form button[type=submit]')
    wait_toast(s.page, 'Canary Browser test canary created')
    row = s.page.locator('#main tbody tr:has-text("Browser test canary")')
    row.wait_for()
    row.locator('[data-act=canary]').click()
    s.page.wait_for_selector('#drawer .code-block:has-text("/api/v1/canaries/")')
    assert not s.errors, s.errors


def test_action_request_approved_by_second_user_and_executed(browser, server):
    admin = Session(browser, server['url']).login(ADMIN_EMAIL, ADMIN_PASSWORD)
    try:
        admin.goto('actions')
        # the tenant starts with actions disabled: the banner must be visible, then disengage the kill switch
        assert not admin.page.locator('#kill-banner').evaluate('el => el.classList.contains("hidden")')
        admin.page.click('[data-act=kill]')
        admin.page.fill('#modal [data-comment]', 'browser test')
        admin.page.click('#modal [data-act=yes]')
        wait_toast(admin.page, 'Kill switch disengaged')
        admin.page.wait_for_function("() => document.querySelector('#kill-banner').classList.contains('hidden')")
        admin.page.wait_for_timeout(500)  # the API commits after responding; let the tenant flag land before requesting
        admin.goto(f'actions/requests/new?finding_id={server["finding_id"]}')
        admin.page.select_option('#main form [name=action_type]', 'argus.finding.update_status')
        admin.page.wait_for_selector('#main form [name="params.status"]')
        admin.page.select_option('#main form [name="params.status"]', 'investigating')
        admin.page.fill('#main form [name=reason]', 'Browser test: move the public bucket finding into investigation')
        admin.page.click('#main form button[type=submit]')
        try:
            admin.page.wait_for_selector('#main .page-heading h1:has-text("argus.finding.update_status")', timeout=15000)
        except Exception:  # noqa: BLE001
            raise AssertionError(f'request was not created: form error={admin.page.inner_text("#main [data-form-error]")!r}; '
                                 f'toasts={[t.inner_text() for t in admin.page.locator("#toast-area .toast").all()]}; errors={admin.errors[:4]}') from None
        admin.page.wait_for_selector('#main .state-tag.pending')
        request_url = admin.page.url
        assert admin.page.locator('#main [data-act=approve]').count() == 0, 'requester must not see approve'
    finally:
        admin_errors = list(admin.errors)
        admin.close()
    assert not admin_errors, admin_errors
    operator = Session(browser, server['url']).login(OPERATOR_EMAIL, OPERATOR_PASSWORD)
    try:
        operator.page.goto(request_url)
        operator.page.wait_for_selector('#main [data-act=approve]')
        operator.page.click('#main [data-act=approve]')
        operator.page.fill('#modal [data-comment]', 'approved by browser test')
        operator.page.click('#modal [data-act=yes]')
        try:
            wait_toast(operator.page, 'Approval recorded')
        except Exception:  # noqa: BLE001
            raise AssertionError(f'approval failed: toasts={[t.inner_text() for t in operator.page.locator("#toast-area .toast").all()]}; '
                                 f'errors={operator.errors[:4]}; chips={[t.inner_text() for t in operator.page.locator("#main .chip-row .state-tag").all()]}') from None
        operator.page.wait_for_selector('#main .state-tag.approved')
        operator.page.click('#main [data-act=execute]')
        operator.page.click('#modal [data-act=yes]')
        operator.page.wait_for_selector('#main .state-tag.executed', timeout=20000)
        assert operator.page.locator('#main tbody tr').count() >= 1
    finally:
        operator_errors = list(operator.errors)
        operator.close()
    assert not operator_errors, operator_errors


def test_get_started_checklist_reflects_data_and_hides(session):
    s = session.login(ADMIN_EMAIL, ADMIN_PASSWORD)
    s.page.wait_for_selector('#main .checklist')
    done = {step.get_attribute('data-step'): 'done' in (step.get_attribute('class') or '')
            for step in s.page.locator('#main .checklist-step').all()}
    # the demo seed has events, an agent run and three members, but no collector and no triaged detection
    assert done == {'source': False, 'events': True, 'triage': False, 'agent': True, 'team': True}
    assert '3 of 5 done' in s.page.inner_text('#main .checklist .panel-head')
    assert s.page.get_attribute('#main [data-step=source] a', 'href') == '#/collectors/types'
    s.page.click('#main [data-act=hide-checklist]')
    assert s.page.locator('#main .checklist').count() == 0
    s.page.reload()
    wait_overview(s)
    s.page.wait_for_timeout(500)
    assert s.page.locator('#main .checklist').count() == 0
    assert not s.errors, s.errors


def test_get_started_checklist_respects_role(session):
    s = session.login(ANALYST_EMAIL, ANALYST_PASSWORD)
    s.page.wait_for_selector('#main .checklist')
    assert 'Needs admin' in s.page.inner_text('#main [data-step=source]')
    assert s.page.locator('#main [data-step=triage] a').count() == 1  # analysts can triage
    assert not s.errors, s.errors


def test_theme_toggle_persists_across_reload(session):
    s = session.login(ADMIN_EMAIL, ADMIN_PASSWORD)
    assert s.page.evaluate('document.documentElement.dataset.theme') is None
    s.page.click('#theme-toggle')
    assert s.page.evaluate('document.documentElement.dataset.theme') == 'dark'
    s.page.reload()
    wait_overview(s)
    assert s.page.evaluate('document.documentElement.dataset.theme') == 'dark'
    assert s.page.evaluate('localStorage.getItem("argus-theme")') == '"dark"'
    s.page.click('#theme-toggle')
    assert s.page.evaluate('document.documentElement.dataset.theme') is None


def test_totp_enrolment_renders_qr_and_verifies(session, server):
    from app.core.security import _totp_code

    s = session.login(ANALYST_EMAIL, ANALYST_PASSWORD)
    s.page.click('#user-menu-btn')
    s.page.click('#user-menu [data-act=enroll-totp]')
    s.page.wait_for_selector('#modal svg.qr')
    secret = s.page.inner_text('#modal .secret-box').strip()
    assert len(secret) >= 16
    assert 'otpauth://totp/' in s.page.inner_text('#modal')
    s.page.fill('#modal form [name=code]', _totp_code(secret, int(time.time()) // 30))
    s.page.click('#modal form button[type=submit]')
    wait_toast(s.page, 'Authenticator enrolled')
    assert not s.errors, s.errors


def test_tenant_switcher_appears_for_multi_tenant_user(session, server):
    s = session.login(ADMIN_EMAIL, ADMIN_PASSWORD)
    s.goto('admin/tenants')
    s.page.click('[data-act=tenant-new]')
    s.page.fill('#drawer form [name=slug]', 'browser-second')
    s.page.fill('#drawer form [name=name]', 'Browser second tenant')
    s.page.click('#drawer form button[type=submit]')
    wait_toast(s.page, 'Tenant created')
    s.page.reload()
    s.page.wait_for_selector('#tenant-select')
    s.page.select_option('#tenant-select', 'browser-second')
    wait_toast(s.page, 'Switched to Browser second tenant')
    s.page.wait_for_selector('#tenant-pill:has-text("Browser second tenant")')
    s.page.select_option('#tenant-select', 'default')
    wait_toast(s.page, 'Switched to')
    assert not s.errors, s.errors


def test_api_key_is_shown_once(session):
    s = session.login(ADMIN_EMAIL, ADMIN_PASSWORD)
    s.goto('admin/keys')
    s.page.click('[data-act=key-new]')
    s.page.fill('#drawer form [name=name]', 'browser-sensor')
    s.page.check('#drawer form input[value=ingest]')
    s.page.click('#drawer form button[type=submit]')
    s.page.wait_for_selector('#modal .key-once code')
    assert s.page.inner_text('#modal .key-once code').startswith('sk_') or len(s.page.inner_text('#modal .key-once code')) > 20
    s.page.click('#modal [data-act=done]')
    s.page.wait_for_selector('#main tbody tr:has-text("browser-sensor")')
    assert not s.errors, s.errors


def test_screenshots_both_themes(session, server):
    SCREENSHOTS.mkdir(parents=True, exist_ok=True)
    s = session.login(ADMIN_EMAIL, ADMIN_PASSWORD)
    s.page.wait_for_selector('#main .checklist')
    s.page.click('#main [data-act=hide-checklist]')  # keep the README screenshots on the dashboard itself
    shots = [('overview', 'overview'), ('findings', 'findings'), (f'graph/nodes/{server["portal_node_id"]}', 'graph'), ('actions/requests', 'actions')]
    for theme in ('light', 'dark'):
        s.page.goto(f'{s.url}/#/overview')
        s.page.evaluate(f"""() => {{ localStorage.setItem('argus-theme', JSON.stringify('{theme}')); }}""")
        s.page.reload()
        wait_overview(s)
        assert (s.page.evaluate('document.documentElement.dataset.theme') == 'dark') == (theme == 'dark')
        for route, name in shots:
            s.goto(route, settle=0.8)
            s.page.screenshot(path=str(SCREENSHOTS / f'{name}-{theme}.png'), full_page=False)
    s.page.evaluate("() => localStorage.removeItem('argus-theme')")
    assert not s.errors, s.errors
