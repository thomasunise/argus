import { get, post } from '../api.js';
import { store } from '../store.js';
import { assetMap, assetName, section, readFilters, setQuery, trackJob } from '../common.js';
import { $, bind, closeDrawer, confirm, drawer, esc, fields, formActions, heading, json, kv, newPager, onSubmit, pageNext, pagePrev, pageReset, pager, panel, readFields, selectHtml, sev, table, tabs, tag, time, toast, mono, link, fmt, num } from '../ui.js';

const TIERS = ['passive', 'active', 'intrusive'];
const ENVS = ['production', 'staging', 'lab', 'development'];
const RUN_STATUSES = ['queued', 'running', 'completed', 'failed', 'denied', 'cancelled'];

async function scopeForm(reload) {
  const assets = [...(await assetMap()).values()];
  const defs = [
    { name: 'name', label: 'Name', type: 'text', required: true, maxlength: 120 },
    { name: 'asset_ids', label: 'Assets (empty = any authorized asset)', type: 'multiselect', options: assets.map((a) => ({ value: a.id, label: `${a.name} (${a.kind})` })) },
    { name: 'allowed_tiers', label: 'Allowed tiers', type: 'multiselect', options: TIERS, value: ['passive'] },
    { name: 'environments', label: 'Environments (empty = any)', type: 'multiselect', options: ENVS },
    { name: 'window_start', label: 'Window start (UTC HH:MM)', type: 'text', placeholder: '22:00', pattern: '([01][0-9]|2[0-3]):[0-5][0-9]' },
    { name: 'window_end', label: 'Window end (UTC HH:MM)', type: 'text', placeholder: '06:00', pattern: '([01][0-9]|2[0-3]):[0-5][0-9]' },
    { name: 'max_rps', label: 'Max requests per second', type: 'number', value: 5, min: 0.1, max: 100, step: 'any' },
    { name: 'max_concurrency', label: 'Max concurrency', type: 'number', value: 1, min: 1, max: 50 },
    { name: 'signed_document_ref', label: 'Signed rules-of-engagement reference', type: 'text', placeholder: 'ROE-2026-03.pdf', maxlength: 512 },
    { name: 'expires_at', label: 'Expires at', type: 'datetime-local' },
  ];
  const body = drawer('Create test scope', `<p class="info-line">A scope is the rules of engagement: which assets, which tiers, when and how fast. Every run re-checks it.</p><form class="form-stack">${fields(defs)}${formActions('Create scope')}</form>`, { wide: true });
  bind(body, { close: closeDrawer });
  onSubmit($('form', body), async (form) => {
    const values = readFields(form, defs);
    if (!values.allowed_tiers.length) throw new Error('Choose at least one tier');
    const payload = { ...values, expires_at: values.expires_at ? new Date(values.expires_at).toISOString() : null };
    await post('/tests/scopes', payload, { silent: true });
    closeDrawer();
    toast('Scope created');
    reload();
  });
}

async function planForm(reload) {
  const [scopes, adapters] = await Promise.all([get('/tests/scopes', { limit: 200 }), get('/tests/adapters')]);
  const active = scopes.items.filter((s) => !s.revoked_at);
  const defs = [
    { name: 'name', label: 'Name', type: 'text', required: true, maxlength: 120 },
    { name: 'scope_id', label: 'Scope', type: 'select', required: true, options: active.map((s) => ({ value: s.id, label: `${s.name} · ${s.allowed_tiers.join('/')}` })), hint: active.length ? '' : 'Create a scope first.' },
    { name: 'adapters', label: 'Adapters', type: 'multiselect', options: adapters.items.map((a) => ({ value: a.name, label: `${a.name} (${a.tier}${a.available ? '' : ', not installed'})` })) },
    { name: 'params', label: 'Adapter params (JSON)', type: 'json', value: {} },
    { name: 'schedule_minutes', label: 'Schedule (minutes, empty = manual)', type: 'number', min: 5, max: 10080, omitEmpty: true },
    { name: 'enabled', label: 'Enabled', type: 'checkbox', value: true },
  ];
  const body = drawer('Create test plan', `<form class="form-stack">${fields(defs)}${formActions('Create plan')}</form>`);
  bind(body, { close: closeDrawer });
  onSubmit($('form', body), async (form) => {
    const values = readFields(form, defs);
    if (!values.adapters.length) throw new Error('Choose at least one adapter');
    await post('/tests/plans', { ...values, schedule_minutes: values.schedule_minutes ?? null }, { silent: true });
    closeDrawer();
    toast('Plan created');
    reload();
  });
}

async function renderRunDetail({ root, params }) {
  const id = params[1];
  root.innerHTML = `<p><a href="#/testing/runs" class="ghost-link">← Runs</a></p><div data-run></div>`;
  let timer = null;
  const view = section($('[data-run]', root), async () => { const [run, assets] = await Promise.all([get(`/tests/runs/${id}`), assetMap().catch(() => new Map())]); return { run, assets }; }, ({ run: r, assets }) => {
    if (['queued', 'running'].includes(r.status)) timer = setTimeout(() => view.reload(true), 2000);
    return `${heading('Test run', `${r.adapter} · ${assetName(assets, r.asset_id)}`, '')}<div class="chip-row">${tag(r.status)}<span class="pill">${esc(r.tier)}</span><span class="pill">${esc(r.triggered_by)}</span>${r.plan_id ? `<span class="pill">plan ${esc(r.plan_id.slice(0, 8))}</span>` : '<span class="pill">ad-hoc scan</span>'}</div>
      ${r.error ? `<div class="callout warning-callout"><strong>Error</strong> ${esc(r.error)}</div>` : ''}
      <div class="two-col">${panel({ title: 'Run', body: kv([['Asset', r.asset_id ? link(`#/assets/${r.asset_id}`, assetName(assets, r.asset_id)) : ''], ['Scope', mono(r.scope_id)], ['Created', esc(fmt(r.created_at))], ['Started', esc(fmt(r.started_at))], ['Finished', esc(fmt(r.finished_at))], ['Results', esc(num(r.result_count))], ['Job', mono(r.job_id)]]) })}${panel({ title: 'Stats', body: json(r.stats) })}</div>
      ${panel({ title: `Results (${(r.results || []).length})`, flush: true, body: table({ columns: [
        { label: 'Result', render: (x) => `<span class="cell-main limit-lines" style="max-width:420px">${esc(x.title)}</span><span class="cell-sub">${esc(x.rule)}</span>` }, { label: 'Severity', render: (x) => sev(x.severity) }, { label: 'Finding', render: (x) => (x.finding_id ? link(`#/findings/${x.finding_id}`, x.finding_id.slice(0, 8)) : '—') }, { label: '', render: (x) => `<button class="btn small" data-act="evidence" data-id="${esc(x.id)}">Evidence</button>` }],
      rows: r.results || [], empty: 'No results', emptySub: r.status === 'completed' ? 'The adapter reported nothing for this target.' : 'Results appear when the run completes.' }) })}`;
  });
  bind(root, { evidence: async (el) => { const r = await get(`/tests/runs/${id}`); const x = r.results.find((y) => y.id === el.dataset.id); drawer(x.title, `<div class="chip-row">${sev(x.severity)}<span class="pill">${esc(x.rule)}</span></div>${json(x.evidence)}`); } });
  return () => clearTimeout(timer);
}

async function renderIndex({ root, params, query, navigate }) {
  const tab = ['plans', 'runs', 'adapters'].includes(params[0]) ? params[0] : 'scopes';
  const state = newPager();
  root.innerHTML = `${heading('Authorized testing', 'Testing', 'Scopes define rules of engagement, plans schedule adapters inside them, runs record what happened.',
    `${tab === 'scopes' && store.can('tests:scopes') ? '<button class="btn primary" data-act="scope-new">Create scope</button>' : ''}${tab === 'plans' && store.can('tests:write') ? '<button class="btn primary" data-act="plan-new">Create plan</button>' : ''}`)}
    ${tabs([{ id: 'scopes', label: 'Scopes' }, { id: 'plans', label: 'Plans' }, { id: 'runs', label: 'Runs' }, { id: 'adapters', label: 'Adapters' }], tab)}<div data-body></div>`;
  const node = $('[data-body]', root);
  let list;
  if (tab === 'scopes') {
    node.innerHTML = '<div class="panel" data-list></div>';
    list = section($('[data-list]', node), async () => { const [data, assets] = await Promise.all([get('/tests/scopes', { limit: 50, cursor: state.cursor }), assetMap().catch(() => new Map())]); return { data, assets }; }, ({ data, assets }) => {
      state.next_cursor = data.next_cursor;
      return table({ columns: [
        { label: 'Scope', render: (s) => `<span class="cell-main">${esc(s.name)}</span><span class="cell-sub">${s.asset_ids.length ? s.asset_ids.map((id) => esc(assetName(assets, id))).join(', ') : 'any authorized asset'}</span>` },
        { label: 'State', render: (s) => tag(s.revoked_at ? 'revoked' : s.expires_at && new Date(s.expires_at) < new Date() ? 'expired' : 'active') }, { label: 'Tiers', render: (s) => s.allowed_tiers.map((t) => `<span class="pill">${esc(t)}</span>`).join(' ') },
        { label: 'Environments', render: (s) => esc(s.environments.join(', ') || 'any') }, { label: 'Window (UTC)', render: (s) => esc(s.window_start ? `${s.window_start}–${s.window_end}` : 'any time') }, { label: 'Limits', render: (s) => `${esc(s.max_rps)} rps · ${esc(s.max_concurrency)} conc.` }, { label: 'Expires', render: (s) => esc(fmt(s.expires_at)) },
        { label: '', render: (s) => `<div class="inline-actions"><button class="btn small" data-act="scope" data-id="${esc(s.id)}">Detail</button>${store.can('tests:scopes') && !s.revoked_at ? `<button class="btn small negative" data-act="scope-revoke" data-id="${esc(s.id)}">Revoke</button>` : ''}</div>` }],
      rows: data.items, empty: 'No scopes', emptySub: 'A scope records the signed rules of engagement before any active testing.' }) + pager(state, data.items.length);
    });
  } else if (tab === 'plans') {
    node.innerHTML = '<div class="panel" data-list></div>';
    list = section($('[data-list]', node), () => get('/tests/plans', { limit: 50, cursor: state.cursor }), (data) => {
      state.next_cursor = data.next_cursor;
      return table({ columns: [
        { label: 'Plan', render: (p) => `<span class="cell-main">${esc(p.name)}</span><span class="cell-sub">scope ${esc(p.scope_id.slice(0, 8))}</span>` }, { label: 'State', render: (p) => tag(p.enabled ? 'enabled' : 'disabled') }, { label: 'Adapters', render: (p) => p.adapters.map((a) => `<span class="pill">${esc(a)}</span>`).join(' ') },
        { label: 'Schedule', render: (p) => (p.schedule_minutes ? `${p.schedule_minutes} min` : 'manual') }, { label: 'Last run', render: (p) => time(p.last_run_at) },
        { label: '', render: (p) => `<div class="inline-actions">${store.can('tests:run') ? `<button class="btn small primary" data-act="plan-run" data-id="${esc(p.id)}">Run</button>` : ''}<button class="btn small" data-act="plan" data-id="${esc(p.id)}">Detail</button></div>` }],
      rows: data.items, empty: 'No plans', emptySub: 'Plans bind adapters to a scope and can run on a schedule.' }) + pager(state, data.items.length);
    });
  } else if (tab === 'runs') {
    node.innerHTML = `<div class="toolbar"><div class="tool-filters" data-filters>${selectHtml('status', RUN_STATUSES, query.status, { allLabel: 'All statuses', attrs: 'data-change="apply"' })}<input class="field-input" name="asset_id" placeholder="Asset id" value="${esc(query.asset_id || '')}" data-enter="apply"></div></div><div class="panel" data-list></div>`;
    list = section($('[data-list]', node), async () => { const [data, assets] = await Promise.all([get('/tests/runs', { ...readFilters($('[data-filters]', node)), limit: 50, cursor: state.cursor }), assetMap().catch(() => new Map())]); return { data, assets }; }, ({ data, assets }) => {
      state.next_cursor = data.next_cursor;
      return table({ columns: [
        { label: 'Run', render: (r) => `<span class="cell-main">${esc(r.adapter)}</span><span class="cell-sub">${esc(assetName(assets, r.asset_id))} · ${r.plan_id ? 'plan' : 'ad-hoc'}</span>` }, { label: 'Tier', render: (r) => esc(r.tier) }, { label: 'Status', render: (r) => tag(r.status) }, { label: 'Results', render: (r) => esc(num(r.result_count)) }, { label: 'Started', render: (r) => time(r.created_at) }, { label: 'Error', cls: 'wrap', render: (r) => `<span class="limit-lines">${esc(r.error || '')}</span>` }],
      rows: data.items, rowAttr: (r) => `data-act="run" data-id="${esc(r.id)}"`, empty: 'No runs', emptySub: 'Launch a scan from an asset or run a plan.' }) + pager(state, data.items.length);
    });
    bind(node, {}, { apply: () => { pageReset(state); setQuery(navigate, 'testing', ['runs'], readFilters($('[data-filters]', node))); list.reload(); } });
  } else {
    list = section(node, () => get('/tests/adapters'), (data) => `<div class="card-grid">${data.items.map((a) => `<div class="card ${a.available ? '' : 'muted-card'}"><h3>${esc(a.name)}</h3><p>${esc(a.description || '')}</p><div class="chip-row">${tag(a.available ? 'available' : 'unavailable')}<span class="pill">${esc(a.tier)}</span>${(a.target_kinds || []).map((k) => `<span class="pill">${esc(k)}</span>`).join('')}</div></div>`).join('')}</div>`);
  }
  bind(root, {
    'scope-new': () => scopeForm(() => list.reload(true)),
    'plan-new': () => planForm(() => list.reload(true)),
    scope: async (el) => { const s = await get(`/tests/scopes/${el.dataset.id}`); drawer(s.name, `<div class="chip-row">${tag(s.revoked_at ? 'revoked' : 'active')}${s.allowed_tiers.map((t) => `<span class="pill">${esc(t)}</span>`).join('')}</div>${kv([['Assets', s.asset_ids.length ? s.asset_ids.map((id) => mono(id)).join('<br>') : 'any authorized'], ['Environments', esc(s.environments.join(', ') || 'any')], ['Window', esc(s.window_start ? `${s.window_start}–${s.window_end} UTC` : 'any')], ['Max rps', esc(s.max_rps)], ['Max concurrency', esc(s.max_concurrency)], ['Signed document', esc(s.signed_document_ref || '—')], ['Created', `${esc(fmt(s.created_at))} by ${esc(s.created_by)}`], ['Expires', esc(fmt(s.expires_at))], ['Revoked', esc(fmt(s.revoked_at))]])}`); },
    'scope-revoke': async (el) => { if (!(await confirm('Revoke this scope? Running work is denied at its next scope check.', { label: 'Revoke', danger: true }))) return; await post(`/tests/scopes/${el.dataset.id}/revoke`, {}); toast('Scope revoked'); list.reload(true); },
    plan: async (el) => { const p = await get(`/tests/plans/${el.dataset.id}`); drawer(p.name, `<div class="chip-row">${tag(p.enabled ? 'enabled' : 'disabled')}${p.adapters.map((a) => `<span class="pill">${esc(a)}</span>`).join('')}</div>${kv([['Scope', mono(p.scope_id)], ['Schedule', p.schedule_minutes ? `${p.schedule_minutes} min` : 'manual'], ['Created', `${esc(fmt(p.created_at))} by ${esc(p.created_by)}`], ['Last run', esc(fmt(p.last_run_at))]])}<h3>Params</h3>${json(p.params)}`); },
    'plan-run': async (el) => { const result = await post(`/tests/plans/${el.dataset.id}/run`, {}); toast(`${result.items.length} run(s) queued`); for (const r of result.items.slice(0, 3)) trackJob(r.job_id, `${r.adapter} run`); setTimeout(() => list.reload(true), 1500); },
    run: (el) => navigate(`testing/runs/${el.dataset.id}`),
    'page-next': () => { pageNext(state); list.reload(); },
    'page-prev': () => { pagePrev(state); list.reload(); },
  });
  root.querySelector('.tabs').addEventListener('click', (event) => { const t = event.target.closest('[data-tab]'); if (t) navigate(t.dataset.tab === 'scopes' ? 'testing' : `testing/${t.dataset.tab}`); });
}

export default {
  render(ctx) { return ctx.params[0] === 'runs' && ctx.params[1] ? renderRunDetail(ctx) : renderIndex(ctx); },
};
