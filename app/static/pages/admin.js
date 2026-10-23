import { get, post, patch, del } from '../api.js';
import { store, ROLES } from '../store.js';
import { section } from '../common.js';
import { $, bind, closeDrawer, closeModal, confirm, copy, drawer, empty, esc, fields, formActions, heading, kv, metrics, modal, onSubmit, panel, readFields, table, tabs, tag, time, toast, fmt, num, yesno } from '../ui.js';

const PERMS = ['assets:read', 'assets:write', 'assets:authorize', 'findings:read', 'findings:write', 'events:read', 'graph:read', 'detections:read', 'detections:write', 'detections:run', 'canaries:read', 'canaries:write', 'collectors:read', 'collectors:write', 'collectors:run', 'agents:read', 'agents:run', 'evals:read', 'evals:run', 'tests:read', 'tests:write', 'tests:run', 'tests:scopes', 'scans:read', 'scans:run', 'actions:read', 'actions:request', 'actions:approve', 'actions:execute', 'actions:rollback', 'integrations:read', 'integrations:write', 'audit:read', 'reports:read', 'investigations:read', 'approvals:read', 'approvals:write', 'ingest'];
const grantable = () => ROLES.slice(0, ROLES.indexOf(store.role) + 1);

function keyOnce(key) {
  modal('API key created', `<p class="info-line">Copy this key now. It is shown once and stored only as a hash.</p><div class="key-once"><strong>${esc(key.name)}</strong> · ${esc(key.role)}${key.scopes?.length ? ` · scopes ${esc(key.scopes.join(', '))}` : ''}<code>${esc(key.key)}</code></div><div class="form-actions"><button class="btn" data-act="copy">Copy key</button><button class="btn primary" data-act="done">Done</button></div>`);
  bind($('#modal .overlay-body'), { copy: () => copy(key.key, 'API key copied'), done: closeModal });
}

function userForm(reload) {
  const defs = [
    { name: 'email', label: 'Email', type: 'email', required: true },
    { name: 'display_name', label: 'Display name', type: 'text', maxlength: 120 },
    { name: 'role', label: 'Role', type: 'select', options: grantable(), value: 'viewer' },
    { name: 'invite', label: 'Invite', type: 'checkbox', text: 'Invite only (no password; signs in through SSO or after a reset)' },
    { name: 'password', label: 'Initial password (optional, 14+ chars)', type: 'password', minlength: 14, omitEmpty: true, autocomplete: 'new-password', hint: 'Leave empty to generate a temporary password shown once.' },
  ];
  const body = drawer('Create user', `<form class="form-stack">${fields(defs)}${formActions('Create user')}</form>`);
  bind(body, { close: closeDrawer });
  onSubmit($('form', body), async (form) => {
    const values = readFields(form, defs);
    const user = await post('/admin/users', { ...values, password: values.password || null }, { silent: true });
    closeDrawer();
    reload();
    if (user.temporary_password) modal('Temporary password', `<p class="info-line">Share this once with ${esc(user.email)}; it is not stored in clear text.</p><div class="key-once"><code>${esc(user.temporary_password)}</code></div><div class="form-actions"><button class="btn primary" data-act="done">Done</button></div>`), bind($('#modal .overlay-body'), { done: closeModal });
    else toast(user.created ? 'User created' : 'Existing user added to tenant');
  });
}

async function usersTab(node) {
  node.innerHTML = `<div class="toolbar"><span class="muted" data-count></span><button class="btn primary" data-act="user-new">Create user</button></div><div class="panel" data-list></div>`;
  const me = store.user?.id;
  const list = section($('[data-list]', node), () => get('/admin/users', { limit: 200 }), (data) => {
    $('[data-count]', node).textContent = `${data.items.length} members`;
    return table({ columns: [
      { label: 'User', render: (u) => `<span class="cell-main">${esc(u.email)}${u.id === me ? ' <span class="subtle">(you)</span>' : ''}</span><span class="cell-sub">${esc(u.display_name || '')}</span>` },
      { label: 'Role', render: (u) => `<select class="select" data-change="role" data-id="${esc(u.id)}" ${u.id === me || (u.role === 'owner' && store.role !== 'owner') ? 'disabled' : ''}>${ROLES.map((r) => `<option value="${r}" ${r === u.role ? 'selected' : ''} ${grantable().includes(r) ? '' : 'disabled'}>${r}</option>`).join('')}</select>` },
      { label: 'State', render: (u) => `${tag(u.is_active ? 'active' : 'disabled')}${u.totp_enabled ? ' <span class="pill">TOTP</span>' : ''}${u.has_password ? '' : ' <span class="pill">SSO / invited</span>'}` }, { label: 'Last login', render: (u) => time(u.last_login_at) }, { label: 'Member since', render: (u) => esc(fmt(u.member_since)) },
      { label: '', render: (u) => `<div class="inline-actions"><button class="btn small" data-act="reset" data-id="${esc(u.id)}" data-email="${esc(u.email)}">Reset password</button>${u.id !== me ? `<button class="btn small" data-act="toggle" data-id="${esc(u.id)}" data-active="${u.is_active ? '1' : ''}">${u.is_active ? 'Deactivate' : 'Activate'}</button><button class="btn small negative" data-act="remove" data-id="${esc(u.id)}" data-email="${esc(u.email)}">Remove</button>` : ''}</div>` }],
    rows: data.items, empty: 'No members' });
  });
  bind(node, {
    'user-new': () => userForm(() => { store.forget('users:'); list.reload(true); }),
    reset: async (el) => {
      const result = await confirm(`Reset the password for ${el.dataset.email}? Leave the field empty to generate a temporary password.`, { label: 'Reset', comment: 'New password (optional, 14+ characters)' });
      if (!result) return;
      const r = await post(`/admin/users/${el.dataset.id}/reset-password`, result.comment ? { password: result.comment } : {});
      if (r.temporary_password) { modal('Temporary password', `<div class="key-once"><code>${esc(r.temporary_password)}</code></div><div class="form-actions"><button class="btn primary" data-act="done">Done</button></div>`); bind($('#modal .overlay-body'), { done: closeModal }); } else toast('Password reset');
    },
    toggle: async (el) => { await patch(`/admin/users/${el.dataset.id}`, { is_active: !el.dataset.active }); toast(el.dataset.active ? 'User deactivated' : 'User activated'); list.reload(true); },
    remove: async (el) => { if (!(await confirm(`Remove ${el.dataset.email} from this tenant?`, { label: 'Remove', danger: true }))) return; await del(`/admin/users/${el.dataset.id}`); toast('Membership removed'); store.forget('users:'); list.reload(true); },
  }, { role: async (el) => { await post('/admin/memberships', { user_id: el.dataset.id, role: el.value }).catch(() => list.reload(true)); toast(`Role set to ${el.value}`); } });
}

async function keysTab(node) {
  node.innerHTML = `<div class="toolbar"><span class="muted">Ingest keys should be viewer role with the ingest scope.</span><button class="btn primary" data-act="key-new">Create API key</button></div><div class="panel" data-list></div>`;
  const list = section($('[data-list]', node), () => get('/auth/api-keys'), (data) => table({ columns: [
    { label: 'Key', render: (k) => `<span class="cell-main">${esc(k.name)}</span><span class="cell-sub mono">${esc(k.prefix)}…</span>` }, { label: 'Role', render: (k) => esc(k.role) }, { label: 'Scopes', render: (k) => (k.scopes?.length ? k.scopes.map((s) => `<span class="pill">${esc(s)}</span>`).join(' ') : '<span class="subtle">role default</span>') }, { label: 'State', render: (k) => tag(k.revoked_at ? 'revoked' : 'active') }, { label: 'Last used', render: (k) => time(k.last_used_at) }, { label: 'Created', render: (k) => esc(fmt(k.created_at)) },
    { label: '', render: (k) => (k.revoked_at ? '' : `<button class="btn small negative" data-act="revoke" data-id="${esc(k.id)}" data-name="${esc(k.name)}">Revoke</button>`) }], rows: data.items, empty: 'No API keys' }));
  bind(node, {
    'key-new': () => {
      const defs = [{ name: 'name', label: 'Name', type: 'text', required: true, maxlength: 120 }, { name: 'role', label: 'Role', type: 'select', options: store.role === 'owner' ? ROLES : ROLES.slice(0, 3), value: 'viewer' }, { name: 'scopes', label: 'Scopes (optional, restricts the key within its role)', type: 'multiselect', options: PERMS }];
      const body = drawer('Create API key', `<form class="form-stack">${fields(defs)}${formActions('Create key')}</form>`);
      bind(body, { close: closeDrawer });
      onSubmit($('form', body), async (form) => { const values = readFields(form, defs); const key = await post('/auth/api-keys', values, { silent: true }); closeDrawer(); list.reload(true); keyOnce(key); });
    },
    revoke: async (el) => { if (!(await confirm(`Revoke API key ${el.dataset.name}? Clients using it fail immediately.`, { label: 'Revoke', danger: true }))) return; await del(`/auth/api-keys/${el.dataset.id}`); toast('Key revoked'); list.reload(true); },
  });
}

async function tenantsTab(node) {
  node.innerHTML = `<div class="toolbar"><span class="muted">You become the owner of tenants you create.</span><button class="btn primary" data-act="tenant-new">Create tenant</button></div><div class="panel" data-list></div>`;
  const list = section($('[data-list]', node), () => get('/admin/tenants'), (data) => table({ columns: [
    { label: 'Tenant', render: (t) => `<span class="cell-main">${esc(t.name)}</span><span class="cell-sub mono">${esc(t.slug)}</span>` }, { label: 'Your role', render: (t) => esc(t.role || '') }, { label: 'Active', render: (t) => yesno(t.is_active, 'active', 'inactive') }, { label: 'Actions', render: (t) => yesno(t.actions_enabled, 'enabled', 'disabled') }, { label: 'Created', render: (t) => esc(fmt(t.created_at)) },
    { label: '', render: (t) => `<div class="inline-actions"><button class="btn small" data-act="rename" data-id="${esc(t.id)}" data-name="${esc(t.name)}">Rename</button><button class="btn small" data-act="actions" data-id="${esc(t.id)}" data-enabled="${t.actions_enabled ? '1' : ''}">${t.actions_enabled ? 'Disable actions' : 'Enable actions'}</button>${t.id !== store.tenant?.id ? `<button class="btn small ${t.is_active ? 'negative' : ''}" data-act="active" data-id="${esc(t.id)}" data-active="${t.is_active ? '1' : ''}">${t.is_active ? 'Deactivate' : 'Activate'}</button>` : ''}</div>` }], rows: data.items, empty: 'No tenants' }));
  bind(node, {
    'tenant-new': () => {
      const defs = [{ name: 'slug', label: 'Slug', type: 'text', required: true, pattern: '[a-z0-9][a-z0-9\\-]{1,62}', hint: '2–64 lowercase letters, digits or hyphens' }, { name: 'name', label: 'Name', type: 'text', required: true, minlength: 2 }];
      const body = drawer('Create tenant', `<form class="form-stack">${fields(defs)}${formActions('Create tenant')}</form>`);
      bind(body, { close: closeDrawer });
      onSubmit($('form', body), async (form) => { await post('/admin/tenants', readFields(form, defs), { silent: true }); closeDrawer(); toast('Tenant created; sign in again to see it in the switcher'); list.reload(true); });
    },
    rename: async (el) => { const r = await confirm(`Rename ${el.dataset.name}`, { label: 'Rename', comment: 'New name' }); if (!r || !r.comment) return; await patch(`/admin/tenants/${el.dataset.id}`, { name: r.comment }); toast('Tenant renamed'); list.reload(true); },
    actions: async (el) => { await patch(`/admin/tenants/${el.dataset.id}`, { actions_enabled: !el.dataset.enabled }); toast(el.dataset.enabled ? 'Actions disabled' : 'Actions enabled'); list.reload(true); },
    active: async (el) => { if (!(await confirm(el.dataset.active ? 'Deactivate this tenant? Its members can no longer sign in to it.' : 'Reactivate this tenant?', { label: el.dataset.active ? 'Deactivate' : 'Activate', danger: Boolean(el.dataset.active) }))) return; await patch(`/admin/tenants/${el.dataset.id}`, { is_active: !el.dataset.active }); list.reload(true); },
  });
}

async function settingsTab(node) {
  const view = section(node, () => get('/admin/settings'), (s) => {
    const defs = [
      { name: 'ai_provider', label: 'AI provider override', type: 'select', options: [{ value: '', label: `server default (${s.effective_ai_provider})` }, ...s.available_providers.map((p) => ({ value: p, label: p }))], value: s.ai_provider || '' },
      { name: 'default_min_severity_for_notifications', label: 'Minimum severity for notifications', type: 'select', options: ['critical', 'high', 'medium', 'low', 'informational'], value: s.default_min_severity_for_notifications },
      { name: 'retention_days', label: 'Retention (days, 7–3650, empty = default)', type: 'number', min: 7, max: 3650, value: s.retention_days ?? '' },
      ...(store.role === 'owner' ? [{ name: 'actions_enabled', label: 'Actions enabled', type: 'checkbox', text: 'Allow the action broker to execute approved actions for this tenant', value: s.actions_enabled }] : []),
      { name: 'action_credentials', label: 'Action credentials (JSON of name → secret reference)', type: 'json', value: s.action_credentials || {}, hint: 'Values must be env:, file: or secrets: references; inline secrets are rejected.' },
    ];
    return `<div class="two-col"><form class="panel"><div class="panel-head"><div><h2>Tenant settings</h2><small>Whitelisted keys; every change is audited</small></div></div><div class="panel-body form-stack">${fields(defs)}${formActions('Save settings', null)}</div></form>
      ${panel({ title: 'Effective state', body: kv([['Effective AI provider', esc(s.effective_ai_provider)], ['Actions enabled', yesno(s.actions_enabled)], ['Global kill switch', s.kill_switch ? '<span class="bad-text">engaged</span>' : 'off'], ['Credential names', Object.keys(s.action_credentials || {}).map((k) => `<span class="pill">${esc(k)}</span>`).join(' ') || '—']]) })}</div>`;
  }, { onRender: (s, root) => {
    const form = $('form', root);
    onSubmit(form, async () => {
      const defs = [{ name: 'ai_provider', type: 'select' }, { name: 'default_min_severity_for_notifications', type: 'select' }, { name: 'retention_days', type: 'number' }, ...(store.role === 'owner' ? [{ name: 'actions_enabled', type: 'checkbox' }] : []), { name: 'action_credentials', type: 'json', label: 'Action credentials' }];
      const values = readFields(form, defs);
      const payload = { ...values, ai_provider: values.ai_provider || null };
      await patch('/admin/settings', payload, { silent: true });
      toast('Settings saved');
      view.reload(true);
    });
  } });
}

export default {
  async render({ root, params, navigate }) {
    const available = [store.can('admin:users') && { id: 'users', label: 'Users' }, store.can('admin:api_keys') && { id: 'keys', label: 'API keys' }, store.can('admin:tenant') && { id: 'tenants', label: 'Tenants' }, store.can('admin:settings') && { id: 'settings', label: 'Settings' }].filter(Boolean);
    const tab = available.some((t) => t.id === params[0]) ? params[0] : available[0]?.id;
    root.innerHTML = `${heading('Administration', 'Admin', 'Members, API keys, tenants and tenant-level settings.')}<div data-overview></div>${tabs(available, tab)}<div data-body></div>`;
    if (store.can('admin:users')) section($('[data-overview]', root), () => get('/admin/overview'), (o) => metrics([
      { label: 'Members', value: o.members?.total, caption: Object.entries(o.members?.by_role || {}).map(([r, n]) => `${r} ${n}`).join(' · ') }, { label: 'API keys', value: o.api_keys?.active, caption: `${o.api_keys?.revoked || 0} revoked` }, { label: 'Open findings', value: o.findings_open, caption: `${num(o.assets)} assets` }, { label: 'Audit entries', value: o.audit_entries, caption: `${num(o.events)} events retained` }]));
    const node = $('[data-body]', root);
    if (tab === 'users') usersTab(node); else if (tab === 'keys') keysTab(node); else if (tab === 'tenants') tenantsTab(node); else if (tab === 'settings') settingsTab(node); else node.innerHTML = empty('Nothing to administer with your role');
    root.querySelector('.tabs')?.addEventListener('click', (event) => { const t = event.target.closest('[data-tab]'); if (t) navigate(`admin/${t.dataset.tab}`); });
  },
};
