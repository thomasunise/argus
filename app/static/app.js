// Shell: boot, hash router, navigation, login, user menu, tenant switcher, kill-switch banner, theme.
import { api, get, post } from './api.js';
import { store, prefSet } from './store.js';
import { $, $$, bind, closeDrawer, closeModal, esc, fields, formActions, loading, errorBox, modal, nice, onSubmit, readFields, toast } from './ui.js';
import { qrSvg } from './qr.js';

const NAV = [
  { group: 'Workspace', items: [
    { id: 'overview', label: 'Overview', perm: 'reports:read' },
    { id: 'assets', label: 'Assets', perm: 'assets:read' },
    { id: 'findings', label: 'Findings', perm: 'findings:read' },
    { id: 'events', label: 'Events', perm: 'events:read' },
    { id: 'graph', label: 'Graph', perm: 'graph:read' },
  ] },
  { group: 'Detection', items: [
    { id: 'detections', label: 'Detections', perm: 'detections:read' },
    { id: 'collectors', label: 'Collectors', perm: 'collectors:read' },
    { id: 'agents', label: 'Agents', perm: 'agents:read' },
    { id: 'testing', label: 'Testing', perm: 'tests:read' },
  ] },
  { group: 'Response', items: [
    { id: 'actions', label: 'Actions', perm: 'actions:read' },
    { id: 'integrations', label: 'Integrations', perm: 'integrations:read' },
  ] },
  { group: 'Governance', items: [
    { id: 'audit', label: 'Audit', perm: 'audit:read' },
    { id: 'reports', label: 'Reports', perm: 'reports:read' },
    { id: 'admin', label: 'Admin', perm: 'admin:users' },
  ] },
];
const PAGE_LABELS = Object.fromEntries(NAV.flatMap((g) => g.items.map((i) => [i.id, i.label])));

let cleanup = null;
let currentPath = '';
let healthTimer = null;

// ---------------------------------------------------------------- router

export function parseHash(hash = location.hash) {
  const raw = hash.replace(/^#\/?/, '');
  const [pathPart, queryPart = ''] = raw.split('?');
  const segments = pathPart.split('/').filter(Boolean).map(decodeURIComponent);
  const query = Object.fromEntries(new URLSearchParams(queryPart));
  return { page: segments[0] || 'overview', params: segments.slice(1), query, path: raw };
}

export function navigate(path, { replace = false } = {}) {
  const hash = `#/${path.replace(/^#?\/?/, '')}`;
  if (replace) history.replaceState(null, '', hash); else location.hash = hash;
}

/** Navigate and render even when the hash does not change. */
function go(path) {
  const hash = `#/${path.replace(/^#?\/?/, '')}`;
  currentPath = '';
  if (location.hash === hash) route(); else location.hash = hash;
}

async function route() {
  if (!store.authenticated) return;
  const { page, params, query, path } = parseHash();
  if (path === currentPath && cleanup && cleanup.keep) return;
  currentPath = path;
  const nav = NAV.flatMap((g) => g.items).find((i) => i.id === page);
  if (!nav) { navigate('overview', { replace: true }); return route(); }
  if (!store.can(nav.perm)) {
    $('#main').innerHTML = errorBox({ message: `Your role (${store.role}) cannot open ${nav.label}.`, code: 'forbidden' }, false);
    return;
  }
  $$('.nav-item').forEach((node) => node.classList.toggle('active', node.dataset.page === page));
  $('#breadcrumb').innerHTML = `Security / <strong>${esc(PAGE_LABELS[page] || nice(page))}</strong>`;
  document.title = `${PAGE_LABELS[page] || nice(page)} — Argus`;
  $('#sidebar').classList.remove('is-open');
  closeDrawer();
  closeModal();
  if (typeof cleanup === 'function') { try { cleanup(); } catch { /* ignore */ } }
  cleanup = null;
  const main = $('#main');
  main.innerHTML = loading();
  try {
    const module = await import(`./pages/${page}.js`);
    const root = document.createElement('div');
    root.className = 'page';
    root.dataset.page = page;
    main.replaceChildren(root);
    const result = await module.default.render({ root, params, query, navigate, page });
    if (typeof result === 'function') cleanup = result;
  } catch (err) {
    if (err?.status === 401) return;
    console.error(err);
    main.innerHTML = errorBox(err);
    bind(main, { retry: () => route() });
  }
  refreshKillSwitch();
}

// ---------------------------------------------------------------- shell

function renderNav() {
  const nav = $('#navigation');
  nav.innerHTML = NAV.map((group) => {
    const items = group.items.filter((i) => store.can(i.perm));
    if (!items.length) return '';
    return `<div class="nav-group-title ${group.group === 'Workspace' ? '' : 'group-gap'}">${esc(group.group)}</div><nav>${items.map((i) => `<a class="nav-item" href="#/${i.id}" data-page="${i.id}">${esc(i.label)}</a>`).join('')}</nav>`;
  }).join('');
  const session = store.session;
  $('#profile-name').textContent = session.user?.display_name || session.user?.email || 'User';
  $('#profile-role').textContent = `${nice(session.role)} · ${session.tenant?.name || session.tenant?.slug || ''}`;
  $('#tenant-pill').textContent = session.tenant?.name || 'Connected';
  const switcher = $('#tenant-switch');
  if ((session.tenants || []).length > 1) {
    switcher.classList.remove('hidden');
    switcher.innerHTML = `<label class="field-label" for="tenant-select">Tenant</label><select class="select" id="tenant-select">${session.tenants.map((t) => `<option value="${esc(t.slug)}" ${t.id === session.tenant?.id ? 'selected' : ''}>${esc(t.name)} (${esc(t.role)})</option>`).join('')}</select>`;
    $('#tenant-select').addEventListener('change', async (event) => {
      try {
        const result = await post('/auth/switch-tenant', { tenant: event.target.value });
        store.csrf = result.csrf;
        await loadSession();
        renderNav();
        renderUserMenu();
        toast(`Switched to ${store.tenant?.name || event.target.value}`);
        go('overview');
      } catch { /* toasted */ }
    });
  } else {
    switcher.classList.add('hidden');
    switcher.innerHTML = '';
  }
}

function renderUserMenu() {
  const menu = $('#user-menu');
  const session = store.session;
  menu.innerHTML = `<div class="menu-head"><strong>${esc(session.user?.email || '')}</strong><small>${esc(nice(session.role))} · ${esc(session.auth)}${session.user?.totp_enabled ? ' · TOTP on' : ''}</small></div>
    ${session.user?.totp_enabled ? '' : '<button role="menuitem" data-act="enroll-totp">Enrol authenticator (TOTP)</button>'}
    <button role="menuitem" data-act="session-info">Session details</button>
    <button role="menuitem" data-act="logout">Sign out</button>`;
}

function toggleUserMenu(force) {
  const menu = $('#user-menu');
  const open = force !== undefined ? force : menu.classList.contains('hidden');
  menu.classList.toggle('hidden', !open);
  $('#user-menu-btn').setAttribute('aria-expanded', String(open));
}

async function enrolTotp() {
  let data;
  try { data = await post('/auth/totp/enroll'); } catch { return; }
  const body = modal('Enrol authenticator', `<p class="info-line">Scan the QR code with an authenticator app, or enter the secret by hand, then confirm with a code.</p>${qrSvg(data.uri)}<div class="secret-box">${esc(data.secret)}</div><p class="form-hint wrap-text">${esc(data.uri)}</p><form class="form-stack">${fields([{ name: 'code', label: 'Six-digit code', type: 'text', required: true, minlength: 6, maxlength: 8, autocomplete: 'one-time-code', pattern: '[0-9]{6,8}' }])}${formActions('Confirm')}</form>`);
  const form = $('form', body);
  bind(body, { close: () => closeModal() });
  onSubmit(form, async () => {
    const { code } = readFields(form, [{ name: 'code', type: 'text', label: 'Code' }]);
    const result = await post('/auth/totp/verify', { code: code.trim() }, { silent: true });
    store.csrf = result.csrf || store.csrf;
    closeModal();
    toast('Authenticator enrolled');
    await loadSession();
    renderUserMenu();
  });
}

function sessionInfo() {
  const s = store.session;
  modal('Session', `<dl class="kv stack"><div><dt>User</dt><dd>${esc(s.user?.email)} (${esc(s.user?.display_name || '')})</dd></div><div><dt>Role</dt><dd>${esc(s.role)}</dd></div><div><dt>Tenant</dt><dd>${esc(s.tenant?.name)} <span class="mono">${esc(s.tenant?.slug)}</span></dd></div><div><dt>Actions enabled</dt><dd>${s.tenant?.actions_enabled ? 'yes' : 'no'}</dd></div><div><dt>Authentication</dt><dd>${esc(s.auth)}${s.user?.totp_enabled ? ', TOTP enrolled' : ''}</dd></div><div><dt>Memberships</dt><dd>${(s.tenants || []).map((t) => `${esc(t.name)} (${esc(t.role)})`).join(', ') || '—'}</dd></div></dl>`);
}

async function logout() {
  try { await post('/auth/logout'); } catch { /* ignore */ }
  store.setSession(null);
  showLogin();
}

// ---------------------------------------------------------------- kill switch banner

export async function refreshKillSwitch() {
  if (!store.authenticated || !store.can('actions:read')) return;
  try {
    applyKillSwitch(await get('/actions/kill-switch', null, { silent: true }));
  } catch { /* banner keeps its last state */ }
}

/** Update the app-wide banner from a kill-switch state payload (GET or POST /actions/kill-switch). */
export function applyKillSwitch(state) {
  store.killSwitch = state;
  store.emit('killswitch', state);
  const banner = $('#kill-banner');
  if (state?.effective) {
    const why = state.global ? 'the global ACTIONS_KILL_SWITCH is set' : `the tenant kill switch is engaged${state.detail?.reason ? `: ${state.detail.reason}` : ''}`;
    banner.innerHTML = `<span><strong>Actions are halted</strong> — ${esc(why)}. Requests are recorded but nothing executes.</span><a href="#/actions">Open actions</a>`;
    banner.classList.remove('hidden');
    $('.topbar').classList.add('under-banner');
  } else {
    banner.classList.add('hidden');
    $('.topbar').classList.remove('under-banner');
  }
}

// ---------------------------------------------------------------- login

function showLogin(step = 'password', context = {}) {
  $('#shell').classList.add('hidden');
  $('#login').classList.remove('hidden');
  closeDrawer();
  closeModal();
  const card = $('#login-card');
  const foot = '<div class="login-foot"><span class="status-led"></span> Self-hosted · Restricted access</div>';
  if (step === 'totp') {
    card.innerHTML = `<h1>Argus</h1><p>Two-factor verification</p><form id="login-form" class="form-stack">${fields([{ name: 'code', label: 'Authenticator code', type: 'text', required: true, autocomplete: 'one-time-code', minlength: 6, maxlength: 8 }])}<button type="submit" class="btn primary full">Verify</button><div class="login-error" id="login-error"></div></form><button class="ghost-link" data-act="restart">Start over</button>${foot}`;
  } else if (step === 'enroll') {
    card.innerHTML = `<h1>Argus</h1><p>Set up an authenticator to continue</p>${qrSvg(context.uri)}<div class="secret-box">${esc(context.secret)}</div><form id="login-form" class="form-stack">${fields([{ name: 'code', label: 'Six-digit code', type: 'text', required: true, autocomplete: 'one-time-code', minlength: 6, maxlength: 8 }])}<button type="submit" class="btn primary full">Confirm</button><div class="login-error" id="login-error"></div></form>${foot}`;
  } else {
    card.innerHTML = `<h1>Argus</h1><p>Security operations</p><form id="login-form" class="form-stack">${fields([
      { name: 'email', label: 'Email', type: 'email', required: true, autocomplete: 'username', value: context.email || '' },
      { name: 'password', label: 'Password', type: 'password', required: true, autocomplete: 'current-password' },
      ...(context.needTotp ? [{ name: 'totp', label: 'Authenticator code', type: 'text', required: true, autocomplete: 'one-time-code', minlength: 6, maxlength: 8 }] : []),
      ...(context.tenant !== undefined ? [{ name: 'tenant', label: 'Tenant (optional)', type: 'text', value: context.tenant || '', hint: 'Leave empty for your default tenant.' }] : []),
    ])}<button type="submit" class="btn primary full">Sign in</button><div class="login-error" id="login-error"></div></form>
    ${context.oidc ? '<div class="or">or</div><a class="btn full" href="/api/v1/auth/oidc/start">Continue with SSO</a>' : ''}
    ${context.tenant === undefined ? '<button class="ghost-link" data-act="tenant">Sign in to a specific tenant</button>' : ''}${foot}`;
  }
  const form = $('#login-form');
  const errorLine = $('#login-error');
  const first = $('input', form);
  if (first) first.focus();
  bind(card, {
    restart: () => showLogin('password', { oidc: context.oidc }),
    tenant: () => showLogin('password', { ...context, tenant: '' }),
  });
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    errorLine.textContent = '';
    const data = Object.fromEntries(new FormData(form));
    const button = $('button[type=submit]', form);
    button.disabled = true;
    try {
      if (step === 'password') {
        const result = await api('/auth/login', { method: 'POST', body: { email: data.email, password: data.password, totp: data.totp || '', tenant: data.tenant || '' }, silent: true });
        store.csrf = result.csrf;
        if (result.mfa_required) {
          const enrol = await post('/auth/totp/enroll', {}, { silent: true }).catch(() => null);
          if (enrol) showLogin('enroll', { ...enrol, oidc: context.oidc }); else showLogin('totp', { oidc: context.oidc });
          return;
        }
        await enterApp();
      } else {
        const result = await post('/auth/totp/verify', { code: data.code.trim() }, { silent: true });
        store.csrf = result.csrf || store.csrf;
        await enterApp();
      }
    } catch (err) {
      if (step === 'password' && err.status === 401 && /totp/i.test(err.message) && !context.needTotp) {
        showLogin('password', { ...context, email: data.email, needTotp: true });
        $('#login-error').textContent = 'This account uses an authenticator app. Enter the current code.';
        return;
      }
      errorLine.textContent = err.message || 'Sign in failed';
    } finally {
      button.disabled = false;
    }
  });
}

async function loadSession() {
  const session = await get('/auth/session', null, { silent: true });
  store.setSession(session);
  return session;
}

async function enterApp() {
  const session = await loadSession();
  if (!session.authenticated) { showLogin('password', { oidc: session.oidc_enabled }); return; }
  $('#login').classList.add('hidden');
  $('#shell').classList.remove('hidden');
  renderNav();
  renderUserMenu();
  if (!location.hash) navigate('overview', { replace: true });
  currentPath = '';
  route();
  pollHealth();
}

async function pollHealth() {
  clearTimeout(healthTimer);
  try {
    const response = await fetch('/ready', { credentials: 'same-origin' });
    const data = await response.json();
    $('#side-health').textContent = response.ok ? `${data.queue} queue · ${data.provider}` : 'Degraded';
    $('#side-led').style.background = response.ok ? 'var(--ok)' : 'var(--bad)';
  } catch {
    $('#side-health').textContent = 'Unreachable';
    $('#side-led').style.background = 'var(--bad)';
  }
  healthTimer = setTimeout(pollHealth, 60000);
}

// ---------------------------------------------------------------- boot

function initTheme() {
  const button = $('#theme-toggle');
  const root = document.documentElement;
  const sync = () => { button.textContent = root.dataset.theme === 'dark' ? 'Light' : 'Dark'; };
  button.addEventListener('click', () => {
    const dark = root.dataset.theme !== 'dark';
    if (dark) root.dataset.theme = 'dark'; else delete root.dataset.theme;
    prefSet('theme', dark ? 'dark' : 'light');
    sync();
  });
  sync();
}

function initShell() {
  $('#display-date').textContent = new Date().toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
  initTheme();
  $('#menu-toggle').addEventListener('click', () => $('#sidebar').classList.toggle('is-open'));
  $('#refresh').addEventListener('click', () => { currentPath = ''; route().then(() => toast('Refreshed')); });
  $('#user-menu-btn').addEventListener('click', (event) => { event.stopPropagation(); toggleUserMenu(); });
  document.addEventListener('click', (event) => { if (!event.target.closest('#user-menu') && !event.target.closest('#user-menu-btn')) toggleUserMenu(false); });
  bind($('#user-menu'), { 'enroll-totp': () => { toggleUserMenu(false); enrolTotp(); }, 'session-info': () => { toggleUserMenu(false); sessionInfo(); }, logout: () => { toggleUserMenu(false); logout(); } });
  for (const id of ['drawer', 'modal']) {
    const backdrop = $(`#${id}`);
    backdrop.addEventListener('click', (event) => {
      if (event.target === backdrop || event.target.closest('[data-close]')) {
        backdrop.dispatchEvent(new CustomEvent('overlay:dismiss'));
        if (id === 'drawer') closeDrawer(); else closeModal();
      }
    });
  }
  window.addEventListener('keydown', (event) => {
    if (event.key !== 'Escape') return;
    if (!$('#modal').classList.contains('hidden')) { $('#modal').dispatchEvent(new CustomEvent('overlay:dismiss')); closeModal(); } else if (!$('#drawer').classList.contains('hidden')) closeDrawer();
  });
  window.addEventListener('hashchange', route);
  store.on('unauthorized', () => { if (store.authenticated) { store.setSession(null); showLogin(); toast('Session expired, please sign in again', 'error'); } });
}

async function boot() {
  initShell();
  try {
    const session = await get('/auth/session', null, { silent: true });
    if (session.authenticated) { store.setSession(session); await enterApp(); return; }
    if (session.mfa_required) {
      const enrol = await post('/auth/totp/enroll', {}, { silent: true }).catch(() => null);
      if (enrol) showLogin('enroll', { ...enrol, oidc: session.oidc_enabled }); else showLogin('totp', { oidc: session.oidc_enabled });
      return;
    }
    showLogin('password', { oidc: session.oidc_enabled });
  } catch (err) {
    showLogin('password', {});
    toast(err.message || 'API unreachable', 'error');
  }
}

boot();
