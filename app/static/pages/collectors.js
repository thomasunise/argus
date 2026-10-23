import { get, post, patch, del } from '../api.js';
import { store } from '../store.js';
import { section, trackJob } from '../common.js';
import { $, bind, closeDrawer, confirm, drawer, esc, fields, formActions, heading, json, kv, newPager, onSubmit, pageNext, pagePrev, pager, panel, readFields, schemaFields, table, tabs, tag, time, toast, mono, nice, fmt, num, yesno } from '../ui.js';

function configForm(type, existing, reload) {
  const defs = [
    { name: 'name', label: 'Name', type: 'text', required: true, maxlength: 120, value: existing?.name || `${type.name} ${existing ? '' : 'collector'}`.trim() },
    { name: 'schedule_minutes', label: 'Schedule (minutes, 0 = manual only)', type: 'number', min: 0, max: 10080, value: existing?.schedule_minutes ?? type.default_schedule_minutes },
    { name: 'enabled', label: 'Enabled', type: 'checkbox', value: existing ? existing.enabled : true },
    ...schemaFields(type.config_schema || {}, existing?.config || {}, { secretFields: type.secret_fields || [], secretRefs: existing?.secret_refs || {}, group: 'config' }),
  ];
  const body = drawer(existing ? `Edit ${existing.name}` : `New ${type.name} collector`, `<p class="info-line">${esc(type.description || '')}</p>${type.available ? '' : `<div class="callout warning-callout">Not available on this server: ${esc(type.install_hint || 'SDK missing')}. You can save the configuration; runs will be refused until it is installed.</div>`}<form class="form-stack">${fields(defs)}${formActions(existing ? 'Save' : 'Create collector')}</form>`);
  bind(body, { close: closeDrawer });
  onSubmit($('form', body), async (form) => {
    const values = readFields(form, defs);
    const payload = { name: values.name, config: values.config || {}, secret_refs: values.secret_refs || {}, enabled: values.enabled, schedule_minutes: values.schedule_minutes ?? 0 };
    if (existing) await patch(`/collectors/${existing.id}`, payload, { silent: true });
    else await post('/collectors', { ...payload, collector: type.name }, { silent: true });
    closeDrawer();
    toast(existing ? 'Collector updated' : 'Collector created');
    reload();
  });
}

async function renderDetail({ root, params, navigate }) {
  const id = params[0];
  const state = newPager();
  root.innerHTML = `<p><a href="#/collectors" class="ghost-link">← Collectors</a></p><div data-detail></div><div style="margin-top:16px" class="panel" data-runs></div>`;
  let config = null;
  const detail = section($('[data-detail]', root), async () => { config = await get(`/collectors/${id}`); return config; }, (c) => `${heading(c.collector, c.name, `${nice(c.kind || '')} collector`, `${store.can('collectors:run') ? '<button class="btn primary" data-act="run">Run now</button>' : ''}${store.can('collectors:write') ? '<button class="btn" data-act="edit">Edit</button><button class="btn subtle" data-act="delete">Delete</button>' : ''}`)}
    <div class="two-col">${panel({ title: 'Status', body: kv([['Enabled', yesno(c.enabled)], ['Available', yesno(c.available, 'yes', 'SDK missing')], ['Schedule', c.schedule_minutes ? `every ${c.schedule_minutes} min` : 'manual'], ['Last run', time(c.last_run_at)], ['Last success', time(c.last_success_at)], ['Last error', c.last_error ? `<span class="bad-text wrap-text">${esc(c.last_error)}</span>` : 'none'], ['Created', `${esc(fmt(c.created_at))} by ${esc(c.created_by)}`]]) })}
    ${panel({ title: 'Configuration', sub: 'secrets are references, resolved at run time', body: `${json(c.config)}<h3>Secret references</h3>${Object.keys(c.secret_refs || {}).length ? kv(Object.entries(c.secret_refs).map(([k, v]) => [k, mono(v)])) : '<p class="form-hint">None</p>'}` })}</div>`);
  const runs = section($('[data-runs]', root), () => get(`/collectors/${id}/runs`, { limit: 25, cursor: state.cursor }), (data) => {
    state.next_cursor = data.next_cursor;
    return `<div class="panel-head"><div><h2>Run history</h2></div></div>${table({ columns: [
      { label: 'Started', render: (r) => esc(fmt(r.created_at)) }, { label: 'Status', render: (r) => tag(r.status) }, { label: 'Trigger', render: (r) => esc(r.triggered_by) },
      { label: 'Stats', cls: 'wrap', render: (r) => Object.entries(r.stats || {}).map(([k, v]) => `${esc(k)} ${esc(num(v))}`).join(' · ') || '—' },
      { label: 'Warnings', render: (r) => (r.warnings?.length ? `<span class="warn-text">${r.warnings.length}</span>` : '0') }, { label: 'Error', cls: 'wrap', render: (r) => esc(r.error || '') },
      { label: '', render: (r) => `<button class="btn small" data-act="run-detail" data-id="${esc(r.id)}">Detail</button>` }], rows: data.items, empty: 'No runs yet' })}${pager(state, data.items.length)}`;
  });
  bind(root, {
    run: async () => {
      const result = await post(`/collectors/${id}/run`, {});
      if (result.already_queued) toast('A run is already queued');
      trackJob(result.job_id, 'Collector run').then(() => { detail.reload(true); runs.reload(true); });
    },
    edit: async () => { const types = await get('/collectors/types'); const type = types.items.find((t) => t.name === config.collector); configForm(type, config, () => detail.reload(true)); },
    delete: async () => { if (!(await confirm('Delete this collector configuration and its run history?', { label: 'Delete', danger: true }))) return; await del(`/collectors/${id}`); toast('Collector deleted'); navigate('collectors'); },
    'run-detail': async (el) => { const r = await get(`/collectors/runs/${el.dataset.id}`); drawer(`Run ${r.id.slice(0, 8)}`, `<div class="chip-row">${tag(r.status)}<span class="pill">${esc(r.triggered_by)}</span></div>${kv([['Created', esc(fmt(r.created_at))], ['Started', esc(fmt(r.started_at))], ['Finished', esc(fmt(r.finished_at))], ['Job', mono(r.job_id)]])}<h3>Stats</h3>${json(r.stats)}${r.warnings?.length ? `<h3>Warnings</h3><ul class="steps">${r.warnings.map((w) => `<li>${esc(w)}</li>`).join('')}</ul>` : ''}${r.error ? `<h3>Error</h3><p class="bad-text">${esc(r.error)}</p>` : ''}`); },
    'page-next': () => { pageNext(state); runs.reload(); },
    'page-prev': () => { pagePrev(state); runs.reload(); },
  });
}

async function renderList({ root, params, navigate }) {
  const tab = params[0] === 'types' ? 'types' : 'configs';
  root.innerHTML = `${heading('Estate collection', 'Collectors', 'Read-only inventory collectors for cloud, identity, code, Kubernetes, endpoint and network sources.')}
    ${tabs([{ id: 'configs', label: 'Configured' }, { id: 'types', label: 'Collector types' }], tab)}<div data-body></div>`;
  const node = $('[data-body]', root);
  let types = [];
  if (tab === 'types') {
    section(node, async () => { types = (await get('/collectors/types')).items; return types; }, (items) => `<div class="card-grid">${items.map((t) => `<div class="card ${t.available ? '' : 'muted-card'}"><h3>${esc(t.name)} <span class="subtle">· ${esc(t.kind)}</span></h3><p>${esc(t.description || '')}</p><div class="chip-row">${tag(t.available ? 'available' : 'unavailable')}${t.secret_fields?.length ? `<span class="pill">secrets: ${esc(t.secret_fields.join(', '))}</span>` : ''}<span class="pill">every ${esc(t.default_schedule_minutes)} min</span></div>${t.available ? '' : `<p class="form-hint">Install hint: <span class="mono">${esc(t.install_hint || 'see docs')}</span></p>`}<div class="inline-actions">${store.can('collectors:write') ? `<button class="btn small primary" data-act="new" data-type="${esc(t.name)}">Configure</button>` : ''}<button class="btn small" data-act="schema" data-type="${esc(t.name)}">Schema</button></div></div>`).join('')}</div>`);
  } else {
    node.innerHTML = `<div class="toolbar"><span class="muted" data-count></span>${store.can('collectors:write') ? '<button class="btn primary" data-act="pick">New collector</button>' : ''}</div><div class="panel" data-list></div>`;
    const list = section($('[data-list]', node), () => get('/collectors', { limit: 100 }), (data) => {
      $('[data-count]', node).textContent = `${data.items.length} configured`;
      return table({ columns: [
        { label: 'Collector', render: (c) => `<span class="cell-main">${esc(c.name)}</span><span class="cell-sub">${esc(c.collector)} · ${esc(nice(c.kind || ''))}</span>` }, { label: 'State', render: (c) => `${tag(c.enabled ? 'enabled' : 'disabled')}${c.available ? '' : ' ' + tag('unavailable')}` },
        { label: 'Schedule', render: (c) => (c.schedule_minutes ? `${c.schedule_minutes} min` : 'manual') }, { label: 'Last run', render: (c) => time(c.last_run_at) }, { label: 'Last success', render: (c) => time(c.last_success_at) },
        { label: 'Last error', cls: 'wrap', render: (c) => (c.last_error ? `<span class="bad-text limit-lines">${esc(c.last_error)}</span>` : '<span class="subtle">—</span>') },
        { label: '', render: (c) => `<div class="inline-actions">${store.can('collectors:run') ? `<button class="btn small" data-act="run" data-id="${esc(c.id)}">Run</button>` : ''}<button class="btn small" data-act="open" data-id="${esc(c.id)}">Open</button></div>` }],
      rows: data.items, empty: 'No collectors configured', emptySub: 'Pick a collector type to start inventorying an estate. Credentials are stored as references only.' });
    });
    bind(node, {
      run: async (el) => { const result = await post(`/collectors/${el.dataset.id}/run`, {}); trackJob(result.job_id, 'Collector run').then(() => list.reload(true)); },
      open: (el) => navigate(`collectors/${el.dataset.id}`),
      pick: () => navigate('collectors/types'),
    });
  }
  bind(root, {
    new: async (el) => { const t = types.find((x) => x.name === el.dataset.type) || (await get('/collectors/types')).items.find((x) => x.name === el.dataset.type); configForm(t, null, () => navigate('collectors')); },
    schema: async (el) => { const t = types.find((x) => x.name === el.dataset.type); drawer(`${t.name} config schema`, json(t.config_schema)); },
  });
  root.querySelector('.tabs').addEventListener('click', (event) => { const t = event.target.closest('[data-tab]'); if (t) navigate(t.dataset.tab === 'types' ? 'collectors/types' : 'collectors'); });
}

export default {
  render(ctx) { return ctx.params[0] && ctx.params[0] !== 'types' ? renderDetail(ctx) : renderList(ctx); },
};
