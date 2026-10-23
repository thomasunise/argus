import { get, post, patch, del, download } from '../api.js';
import { store } from '../store.js';
import { section, readFilters, setQuery, settle, trackJob } from '../common.js';
import { $, bind, closeDrawer, confirm, copy, drawer, esc, fields, formActions, heading, json, kv, metrics, modal, newPager, onSubmit, pageNext, pagePrev, pageReset, pager, readFields, selectHtml, sev, table, tabs, tag, time, toDate, toast, mono, nice, link, fmt, num, setDrawerTitle, SEVERITY_ORDER } from '../ui.js';

const STATUSES = ['open', 'investigating', 'resolved', 'false_positive'];
const CANARY_KINDS = ['token', 'url', 'credential', 'file', 'dns', 'aws_key', 'api_key', 'document'];

export async function openDetection(id, onChange = () => {}) {
  const body = drawer('Detection', '<div class="loading">Loading…</div>');
  const render = async (afterWrite = false) => {
    if (afterWrite) await settle();
    let d;
    try { d = await get(`/detections/${id}`, null, { silent: true }); } catch (err) { body.innerHTML = `<div class="error-box"><strong>Could not load</strong><span>${esc(err.message)}</span></div>`; return; }
    setDrawerTitle(`Detection ${d.id.slice(0, 8)}`);
    body.innerHTML = `<div class="chip-row">${sev(d.severity)}${tag(d.status)}<span class="pill">${esc(d.rule_id)}</span>${d.confidence ? `<span class="pill">confidence ${esc(d.confidence)}</span>` : ''}</div><h3 class="detail-title">${esc(d.title)}</h3>
      ${d.description ? `<p class="info-line">${esc(d.description)}</p>` : ''}
      ${kv([['Entity', mono(d.entity)], ['Entity kind', esc(d.entity_kind)], ['Occurrences', esc(num(d.occurrences))], ['First seen', esc(fmt(d.first_seen_at))], ['Last seen', time(d.last_seen_at)], ['Finding', d.finding_id ? link(`#/findings/${d.finding_id}`, d.finding_id.slice(0, 8)) : ''], ['Tags', (d.tags || []).map((t) => `<span class="pill">${esc(t)}</span>`).join(' ')], ['Fingerprint', mono(d.fingerprint)]])}
      ${store.can('detections:write') ? `<h3>Triage</h3><div class="inline-actions" style="flex-wrap:wrap">${STATUSES.filter((s) => s !== d.status).map((s) => `<button class="btn small" data-act="status" data-status="${s}">${esc(nice(s))}</button>`).join('')}</div>` : ''}
      ${store.can('actions:request') ? `<p style="margin-top:10px"><a class="btn small" href="#/actions/requests/new?detection_id=${esc(d.id)}">Request action</a></p>` : ''}
      <h3>Evidence</h3>${json(d.evidence)}`;
  };
  bind(body, {
    status: async (el) => {
      const result = await confirm(`Set this detection to ${nice(el.dataset.status)}?`, { label: 'Update', comment: 'Note (optional)' });
      if (!result) return;
      await patch(`/detections/${id}`, { status: el.dataset.status, note: result.comment || '' });
      toast('Detection updated');
      onChange();
      render(true);
    },
  });
  await render();
}

function ruleDrawer(rule, reload) {
  const defs = Object.keys(rule.params || {}).map((key) => {
    const value = rule.params[key];
    const type = typeof value === 'boolean' ? 'checkbox' : typeof value === 'number' ? 'number' : Array.isArray(value) ? 'tags' : typeof value === 'object' && value !== null ? 'json' : 'text';
    return { name: key, label: key, type, value, step: 'any', hint: rule.default_params?.[key] !== undefined ? `default: ${JSON.stringify(rule.default_params[key])}` : '' };
  });
  const body = drawer(`Rule · ${rule.name}`, `<div class="chip-row">${sev(rule.severity)}${tag(rule.enabled ? 'enabled' : 'disabled')}<span class="pill">${esc(rule.category || '')}</span>${(rule.tags || []).map((t) => `<span class="pill">${esc(t)}</span>`).join('')}</div><p class="info-line">${esc(rule.description)}</p>${kv([['Rule id', mono(rule.id)], ['Last change', rule.updated_at ? `${esc(fmt(rule.updated_at))} by ${esc(rule.updated_by)}` : 'defaults']])}
    ${store.can('detections:write') ? `<h3>Parameters</h3><form class="form-stack">${defs.length ? fields(defs) : '<p class="form-hint">This rule has no tunable parameters.</p>'}${formActions('Save parameters')}</form>` : `<h3>Effective parameters</h3>${json(rule.params)}`}`);
  bind(body, { close: closeDrawer });
  if (store.can('detections:write')) {
    onSubmit($('form', body), async (form) => {
      const params = readFields(form, defs);
      await patch(`/detections/rules/${rule.id}`, { params }, { silent: true });
      closeDrawer();
      toast('Rule parameters saved');
      reload();
    });
  }
}

function canaryCreate(reload) {
  const defs = [
    { name: 'kind', label: 'Kind', type: 'select', options: CANARY_KINDS, required: true },
    { name: 'label', label: 'Label', type: 'text', required: true, maxlength: 120, placeholder: 'Fake AWS key in /home/deploy/.aws/credentials' },
    { name: 'placement', label: 'Placement notes', type: 'textarea', rows: 3, hint: 'Where you intend to plant it. Free text, redacted before storage.' },
    { name: 'expires_in_days', label: 'Expires in (days)', type: 'number', min: 1, max: 3650, omitEmpty: true },
    { name: 'metadata', label: 'Metadata (JSON)', type: 'json', rows: 3, value: {} },
  ];
  const body = drawer('Create canary', `<form class="form-stack">${fields(defs)}${formActions('Create canary')}</form>`);
  bind(body, { close: closeDrawer });
  onSubmit($('form', body), async (form) => {
    const values = readFields(form, defs);
    const canary = await post('/canaries', values, { silent: true });
    closeDrawer();
    toast(`Canary ${canary.label} created`);
    reload();
  });
}

async function openCanary(c, reload) {
  const hits = await get(`/canaries/${c.id}/hits`, { limit: 50 }).catch(() => ({ items: [] }));
  const url = c.metadata?.url || `${location.origin}/api/v1/canaries/${c.token}/hit`;
  const body = drawer(`Canary · ${c.label}`, `<div class="chip-row"><span class="pill">${esc(c.kind)}</span>${tag(c.active ? 'active' : 'revoked')}${c.hit_count ? `<span class="risk-chip risk-high">${esc(c.hit_count)} hits</span>` : ''}</div>
    ${kv([['Token', mono(c.token)], ['Placement', `<span class="wrap-text">${esc(c.placement || '—')}</span>`], ['Created', `${esc(fmt(c.created_at))} by ${esc(c.created_by)}`], ['Expires', esc(fmt(c.expires_at))], ['Last hit', time(c.last_hit_at)]])}
    <h3>Trigger URL</h3><div class="copy-row"><pre class="code-block">${esc(url)}</pre><button class="btn small" data-act="copy">Copy</button></div>
    <div class="inline-actions" style="margin-top:12px"><button class="btn small" data-act="artifact">Download artifact</button>${store.can('canaries:write') && c.active ? '<button class="btn small negative" data-act="revoke">Revoke</button>' : ''}</div>
    ${Object.keys(c.metadata || {}).length ? `<h3>Metadata</h3>${json(c.metadata)}` : ''}
    <h3>Hits (${hits.items.length})</h3>${table({ columns: [{ label: 'Received', render: (h) => esc(fmt(h.received_at)) }, { label: 'Source IP', render: (h) => mono(h.source_ip) }, { label: 'User agent', cls: 'wrap', render: (h) => esc(h.user_agent || '') }, { label: '', render: (h) => `<button class="btn small" data-act="hit" data-id="${esc(h.id)}">Payload</button>` }], rows: hits.items, empty: 'No hits recorded' })}`);
  bind(body, {
    copy: () => copy(url, 'Trigger URL copied'),
    artifact: () => download(`/canaries/${c.id}/artifact`, `${c.label.replace(/[^a-z0-9]+/gi, '-').toLowerCase()}.canary`).catch(() => {}),
    revoke: async () => { if (!(await confirm('Revoke this canary? Hits will no longer be recorded for its token.', { label: 'Revoke', danger: true }))) return; await del(`/canaries/${c.id}`); closeDrawer(); toast('Canary revoked'); reload(); },
    hit: (el) => { const h = hits.items.find((x) => x.id === el.dataset.id); modal('Canary hit', json({ headers: h.headers, payload: h.payload })); },
  });
}

export default {
  async render({ root, params, query, navigate }) {
    const tab = params[0] === 'rules' ? 'rules' : params[0] === 'canaries' ? 'canaries' : 'detections';
    const state = newPager();
    root.innerHTML = `${heading('Detection engine', 'Detections', 'Rule matches over normalized events, per-tenant rule tuning, and canary tokens.',
      `${store.can('detections:run') && tab !== 'canaries' ? '<button class="btn" data-act="run">Run rules now</button>' : ''}${store.can('canaries:write') && tab === 'canaries' ? '<button class="btn primary" data-act="canary-create">Create canary</button>' : ''}`)}
      <div data-stats></div>
      ${tabs([{ id: 'detections', label: 'Detections' }, { id: 'rules', label: 'Rules' }, { id: 'canaries', label: 'Canaries' }], tab)}
      <div data-tab-body></div>`;
    section($('[data-stats]', root), () => get('/detections/stats'), (s) => metrics([
      { label: 'Open detections', value: Object.values(s.open_by_severity || {}).reduce((a, b) => a + b, 0), caption: `${s.open_by_severity?.critical || 0} critical · ${s.open_by_severity?.high || 0} high` },
      { label: 'Seen in 24h', value: s.last_24h, caption: `${Object.keys(s.by_rule || {}).length} rules have matched` },
      { label: 'Rules registered', value: s.rules_registered, caption: s.last_run ? `last run ${nice(s.last_run.trigger)} ${toDate(s.last_run.started_at).toLocaleTimeString()}` : 'never run' },
      { label: 'Last run', value: s.last_run ? `${num(s.last_run.detections_created)} new` : '—', caption: s.last_run ? `${num(s.last_run.events_scanned)} events scanned · ${s.last_run.errors?.length || 0} errors` : 'queue a run to evaluate rules' },
    ]));
    const bodyNode = $('[data-tab-body]', root);
    let list;
    if (tab === 'detections') {
      bodyNode.innerHTML = `<div class="toolbar"><div class="tool-filters" data-filters>${selectHtml('status', STATUSES, query.status === undefined ? 'open' : query.status, { allLabel: 'All statuses', attrs: 'data-change="apply"' })}${selectHtml('severity', SEVERITY_ORDER, query.severity, { allLabel: 'Any severity', attrs: 'data-change="apply"' })}<input class="field-input" name="rule_id" placeholder="Rule id" value="${esc(query.rule_id || '')}" data-enter="apply"><input class="field-input" name="entity" placeholder="Entity contains" value="${esc(query.entity || '')}" data-enter="apply"></div></div><div class="panel" data-list></div>`;
      list = section($('[data-list]', bodyNode), () => get('/detections', { ...readFilters($('[data-filters]', bodyNode)), limit: 50, cursor: state.cursor }), (data) => {
        state.next_cursor = data.next_cursor;
        return table({ columns: [
          { label: 'Detection', render: (d) => `<span class="cell-main limit-lines" style="max-width:420px">${esc(d.title)}</span><span class="cell-sub">${esc(d.rule_id)} · ${esc(d.entity || '')}</span>` }, { label: 'Severity', render: (d) => sev(d.severity) }, { label: 'Status', render: (d) => tag(d.status) },
          { label: 'Confidence', render: (d) => esc(d.confidence || '—') }, { label: 'Seen', render: (d) => `${esc(num(d.occurrences))}×` }, { label: 'Last seen', render: (d) => time(d.last_seen_at) }],
        rows: data.items, rowAttr: (d) => `data-act="open" data-id="${esc(d.id)}"`, empty: 'No detections', emptySub: 'Rules run over ingested events on a schedule or on demand.' }) + pager(state, data.items.length);
      });
      bind(bodyNode, {}, { apply: () => { pageReset(state); setQuery(navigate, 'detections', [], readFilters($('[data-filters]', bodyNode))); list.reload(); } });
    } else if (tab === 'rules') {
      bodyNode.innerHTML = `<div class="panel" data-list></div>`;
      list = section($('[data-list]', bodyNode), () => get('/detections/rules'), (data) => table({ columns: [
        { label: 'Rule', cls: 'wrap', render: (r) => `<span class="cell-main">${esc(r.name)}</span><span class="cell-sub">${esc(r.id)} · ${esc(r.description)}</span>` }, { label: 'Severity', render: (r) => sev(r.severity) }, { label: 'Category', render: (r) => esc(r.category || '') },
        { label: 'State', render: (r) => tag(r.enabled ? 'enabled' : 'disabled') }, { label: 'Overrides', render: (r) => (Object.keys(r.overrides || {}).length ? `<span class="pill">${Object.keys(r.overrides).length} params</span>` : '<span class="subtle">defaults</span>') },
        { label: '', render: (r) => `<div class="inline-actions"><button class="btn small" data-act="rule" data-id="${esc(r.id)}">${store.can('detections:write') ? 'Edit' : 'View'}</button>${store.can('detections:write') ? `<button class="btn small" data-act="rule-toggle" data-id="${esc(r.id)}" data-enabled="${r.enabled ? '1' : ''}">${r.enabled ? 'Disable' : 'Enable'}</button>` : ''}${store.can('detections:run') ? `<button class="btn small" data-act="rule-run" data-id="${esc(r.id)}">Run</button>` : ''}</div>` }],
      rows: data.items, empty: 'No rules registered' }));
    } else {
      bodyNode.innerHTML = `<div class="toolbar"><div class="tool-filters" data-filters>${selectHtml('kind', CANARY_KINDS, query.kind, { allLabel: 'All kinds', attrs: 'data-change="apply"' })}<label class="check"><input type="checkbox" name="include_revoked" ${query.include_revoked ? 'checked' : ''} data-change="apply"> <span>Include revoked</span></label></div></div><div class="panel" data-list></div>`;
      list = section($('[data-list]', bodyNode), () => get('/canaries', { ...readFilters($('[data-filters]', bodyNode)), limit: 50, cursor: state.cursor }), (data) => {
        state.next_cursor = data.next_cursor;
        return table({ columns: [
          { label: 'Canary', render: (c) => `<span class="cell-main">${esc(c.label)}</span><span class="cell-sub">${esc(c.kind)} · ${esc(c.token.slice(0, 10))}…</span>` }, { label: 'State', render: (c) => tag(c.active ? 'active' : 'revoked') }, { label: 'Hits', render: (c) => (c.hit_count ? `<span class="bad-text">${esc(c.hit_count)}</span>` : '0') },
          { label: 'Last hit', render: (c) => time(c.last_hit_at) }, { label: 'Expires', render: (c) => esc(fmt(c.expires_at)) }, { label: 'Created', render: (c) => time(c.created_at) },
          { label: '', render: (c) => `<div class="inline-actions"><button class="btn small" data-act="canary" data-id="${esc(c.id)}">Open</button><button class="btn small" data-act="canary-copy" data-id="${esc(c.id)}">Copy URL</button></div>` }],
        rows: data.items, empty: 'No canaries', emptySub: 'Create a token, URL, credential or document lure and place it where only an intruder would touch it.' }) + pager(state, data.items.length);
      });
      bind(bodyNode, {}, { apply: () => { pageReset(state); setQuery(navigate, 'detections', ['canaries'], readFilters($('[data-filters]', bodyNode))); list.reload(); } });
    }
    const canaryById = async (id) => { const c = await get(`/canaries`, { include_revoked: true, limit: 500 }); return c.items.find((x) => x.id === id); };
    bind(root, {
      open: (el) => { history.replaceState(null, '', `#/detections/${el.dataset.id}`); openDetection(el.dataset.id, () => list.reload(true)); },
      run: async () => { const r = await post('/detections/run', {}); trackJob(r.job_id, 'Detection run').then(() => { list.reload(true); }); },
      'rule-run': async (el) => { const r = await post('/detections/run', { rule_ids: [el.dataset.id] }); trackJob(r.job_id, `Rule ${el.dataset.id}`).then(() => list.reload(true)); },
      rule: async (el) => { const data = await get('/detections/rules'); const rule = data.items.find((r) => r.id === el.dataset.id); if (rule) ruleDrawer(rule, () => list.reload(true)); },
      'rule-toggle': async (el) => { await patch(`/detections/rules/${el.dataset.id}`, { enabled: !el.dataset.enabled }); toast(el.dataset.enabled ? 'Rule disabled' : 'Rule enabled'); list.reload(true); },
      'canary-create': () => canaryCreate(() => list.reload(true)),
      canary: async (el) => { const c = await canaryById(el.dataset.id); if (c) openCanary(c, () => list.reload(true)); },
      'canary-copy': async (el) => { const c = await canaryById(el.dataset.id); if (c) copy(c.metadata?.url || `${location.origin}/api/v1/canaries/${c.token}/hit`, 'Trigger URL copied'); },
      'page-next': () => { pageNext(state); list.reload(); },
      'page-prev': () => { pagePrev(state); list.reload(); },
    });
    root.querySelector('.tabs').addEventListener('click', (event) => { const t = event.target.closest('[data-tab]'); if (t) navigate(t.dataset.tab === 'detections' ? 'detections' : `detections/${t.dataset.tab}`); });
    if (params[0] && tab === 'detections') openDetection(params[0], () => list.reload(true));
    const onClosed = () => { if (/^#\/detections\/[^/]+$/.test(location.hash) && !['rules', 'canaries'].includes(location.hash.split('/')[2])) history.replaceState(null, '', '#/detections'); };
    document.addEventListener('drawer:closed', onClosed);
    return () => document.removeEventListener('drawer:closed', onClosed);
  },
};
