import { get, post, patch, del } from '../api.js';
import { store } from '../store.js';
import { section, readFilters, setQuery, trackJob } from '../common.js';
import { $, ago, bind, closeDrawer, confirm, drawer, empty, esc, fields, formActions, heading, json, kv, newPager, onSubmit, pageNext, pagePrev, pageReset, pager, panel, readFields, selectHtml, sev, table, tag, time, toast, yesno, mono, nice, link, debounce, fmt } from '../ui.js';

const KINDS = ['web', 'repo', 'cloud_account', 'host', 'k8s_cluster', 'database', 'identity_provider', 'saas', 'network'];
const ENVS = ['production', 'staging', 'lab', 'development'];
const CRITS = ['low', 'medium', 'high', 'critical'];

const assetFields = (values = {}) => [
  { name: 'name', label: 'Name', type: 'text', required: true, minlength: 2, maxlength: 120, value: values.name },
  { name: 'kind', label: 'Kind', type: 'select', options: KINDS, value: values.kind || 'web', disabled: Boolean(values.id) },
  { name: 'target', label: 'Target', type: 'text', required: true, value: values.target, disabled: Boolean(values.id), placeholder: 'https://app.example.com',
    hint: 'web: https origin; repo: path below SCAN_ROOT; cloud_account: aws:123456789012 or an ARN; others are inventory identifiers. Validated by core.policy.' },
  { name: 'environment', label: 'Environment', type: 'select', options: ENVS, value: values.environment || 'production' },
  { name: 'criticality', label: 'Criticality', type: 'select', options: CRITS, value: values.criticality || 'medium' },
  { name: 'owner', label: 'Owner', type: 'text', value: values.owner, maxlength: 120 },
  { name: 'tags', label: 'Tags', type: 'tags', value: values.tags },
  ...(values.id ? [] : [{ name: 'external_id', label: 'External id', type: 'text', value: values.external_id, maxlength: 256 }]),
];

function openCreate(reload) {
  const defs = assetFields();
  const body = drawer('Register asset', `<form class="form-stack">${fields(defs)}${formActions('Register asset')}</form>`);
  bind(body, { close: closeDrawer });
  onSubmit($('form', body), async (form) => {
    const asset = await post('/assets', readFields(form, defs), { silent: true });
    closeDrawer();
    toast(`Registered ${asset.name}`);
    store.forget('assets:');
    reload();
  });
}

function openEdit(asset, reload) {
  const defs = assetFields(asset);
  const body = drawer(`Edit ${asset.name}`, `<form class="form-stack">${fields(defs)}${formActions('Save changes')}</form>`);
  bind(body, { close: closeDrawer });
  onSubmit($('form', body), async (form) => {
    const values = readFields(form, defs);
    await patch(`/assets/${asset.id}`, { name: values.name, environment: values.environment, criticality: values.criticality, owner: values.owner, tags: values.tags }, { silent: true });
    closeDrawer();
    toast('Asset updated');
    store.forget('assets:');
    reload();
  });
}

function openImport(reload) {
  const example = JSON.stringify([{ name: 'Example portal', kind: 'web', target: 'https://portal.example.com', environment: 'production', criticality: 'high', tags: ['imported'] }], null, 2);
  const body = drawer('Import assets', `<p class="info-line">Paste a JSON array of asset objects (same fields as the register form). Rows are validated independently; duplicates by kind and target are skipped.</p><form class="form-stack">${fields([{ name: 'rows', label: 'Rows (JSON array)', type: 'json', rows: 12, value: example, emptyValue: [] }])}${formActions('Import')}</form><div data-result></div>`, { wide: true });
  bind(body, { close: closeDrawer });
  onSubmit($('form', body), async (form) => {
    const { rows } = readFields(form, [{ name: 'rows', type: 'json', label: 'Rows', emptyValue: [] }]);
    if (!Array.isArray(rows)) throw new Error('Rows must be a JSON array');
    const result = await post('/assets/import', rows, { silent: true });
    $('[data-result]', body).innerHTML = `<h3>Result</h3><p class="info-line">${result.created} created, ${result.failed} failed of ${result.received}.</p>${table({ columns: [
      { label: '#', render: (r) => esc(r.index) }, { label: 'Status', render: (r) => (r.ok ? tag('ok') : tag('error')) }, { label: 'Detail', cls: 'wrap', render: (r) => esc(r.ok ? r.id : `${r.error} (${r.code})`) }], rows: result.results })}`;
    store.forget('assets:');
    reload();
  });
}

async function renderList({ root, query, navigate }) {
  const state = newPager();
  state.cursor = query.cursor || '';
  root.innerHTML = `${heading('Discovery & inventory', 'Assets', 'Systems you own or are explicitly authorized to administer. Nothing is tested until an authorization is recorded.',
    store.can('assets:write') ? '<button class="btn" data-act="import">Import JSON</button><button class="btn primary" data-act="create">Register asset</button>' : '')}
    <div class="toolbar"><div class="tool-filters" data-filters>
      <input class="field-input" name="search" placeholder="Search name, target, owner" value="${esc(query.search || '')}" data-enter="apply">
      ${selectHtml('kind', KINDS, query.kind, { allLabel: 'All kinds', attrs: 'data-change="apply"' })}
      ${selectHtml('environment', ENVS, query.environment, { allLabel: 'All environments', attrs: 'data-change="apply"' })}
      ${selectHtml('criticality', CRITS, query.criticality, { allLabel: 'Any criticality', attrs: 'data-change="apply"' })}
      ${selectHtml('approved', [{ value: 'true', label: 'Authorized' }, { value: 'false', label: 'Not authorized' }], query.approved, { allLabel: 'Any authorization', attrs: 'data-change="apply"' })}
    </div><span class="muted" data-count></span></div>
    <div class="panel" data-list></div>`;
  const filters = () => readFilters($('[data-filters]', root));
  const list = section($('[data-list]', root), () => get('/assets', { ...filters(), limit: 50, cursor: state.cursor }), (data) => {
    state.next_cursor = data.next_cursor;
    $('[data-count]', root).textContent = `${data.items.length}${data.next_cursor ? '+' : ''} assets`;
    return table({
      columns: [
        { label: 'Asset', render: (a) => `<span class="cell-main">${esc(a.name)}</span><span class="cell-sub">${esc(nice(a.kind))}${a.owner ? ` · ${esc(a.owner)}` : ''}</span>` },
        { label: 'Target', render: (a) => `<span class="mono truncate" title="${esc(a.target)}">${esc(a.target)}</span>` },
        { label: 'Environment', render: (a) => esc(nice(a.environment)) },
        { label: 'Criticality', render: (a) => tag(a.criticality) },
        { label: 'Authorization', render: (a) => (a.approved ? tag('approved') : tag('none')) },
        { label: 'Tags', render: (a) => (a.tags || []).map((t) => `<span class="pill">${esc(t)}</span>`).join(' ') || '<span class="subtle">—</span>' },
        { label: 'Last seen', render: (a) => time(a.last_seen_at) },
      ],
      rows: data.items, rowAttr: (a) => `data-act="open" data-id="${esc(a.id)}"`,
      empty: 'No assets match', emptySub: store.can('assets:write') ? 'Register an asset or import a JSON list to begin.' : 'Ask an operator to register assets.',
    }) + pager(state, data.items.length);
  });
  const apply = () => { pageReset(state); setQuery(navigate, 'assets', [], filters()); list.reload(); };
  bind(root, {
    create: () => openCreate(() => list.reload(true)),
    import: () => openImport(() => list.reload(true)),
    open: (el) => navigate(`assets/${el.dataset.id}`),
    'page-next': () => { pageNext(state); list.reload(); },
    'page-prev': () => { pagePrev(state); list.reload(); },
  }, { apply });
  $('input[name=search]', root).addEventListener('input', debounce(apply, 350));
}

// ---------------------------------------------------------------- detail

function authorizeDrawer(asset, reload) {
  const defs = [
    { name: 'attestation', label: 'Attestation', type: 'textarea', required: true, rows: 4, placeholder: 'I confirm that my organization controls this asset and I am authorized to request security testing of it.', hint: 'At least 20 characters. Recorded verbatim in the audit log.' },
    { name: 'allow_active', label: 'Allow active testing', type: 'checkbox', text: 'Allow active testing (authenticated probes, non-destructive scanners)' },
    { name: 'allow_intrusive', label: 'Allow intrusive testing', type: 'checkbox', text: 'Allow intrusive testing (staging and lab assets only)', disabled: !['staging', 'lab'].includes(asset.environment) },
    { name: 'expires_in_days', label: 'Expires in (days)', type: 'number', value: 90, min: 1, max: 365, required: true },
    { name: 'scope_document_ref', label: 'Scope document reference', type: 'text', placeholder: 'SOW-2026-014 or a document URL', maxlength: 512 },
  ];
  const body = drawer(`Authorize ${asset.name}`, `<div class="callout">${esc(asset.kind)} · <span class="mono">${esc(asset.target)}</span> · ${esc(asset.environment)}</div><form class="form-stack">${fields(defs)}${formActions('Record authorization')}</form>`);
  bind(body, { close: closeDrawer });
  onSubmit($('form', body), async (form) => {
    const values = readFields(form, defs);
    await post(`/assets/${asset.id}/authorize`, values, { silent: true });
    closeDrawer();
    toast('Authorization recorded');
    store.forget('assets:');
    reload();
  });
}

function scanDrawer(asset, adapters, scopes, reload) {
  const usable = adapters.filter((a) => !a.target_kinds.length || a.target_kinds.includes(asset.kind));
  const activeScopes = scopes.filter((s) => !s.revoked_at && (!s.asset_ids.length || s.asset_ids.includes(asset.id)));
  const defs = [
    { name: 'adapter', label: 'Adapter', type: 'select', required: true, options: usable.map((a) => ({ value: a.name, label: `${a.name} · ${a.tier}${a.available ? '' : ' (not installed)'}` })) },
    { name: 'scope_id', label: 'Scope', type: 'select', required: true, options: activeScopes.map((s) => ({ value: s.id, label: `${s.name} · tiers ${s.allowed_tiers.join('/')}` })), hint: activeScopes.length ? 'The scope is re-checked at execution time.' : 'No active scope covers this asset. Create one under Testing → Scopes.' },
    { name: 'tier', label: 'Tier (optional)', type: 'select', options: [{ value: '', label: 'adapter default' }, 'passive', 'active', 'intrusive'] },
  ];
  const body = drawer(`Launch scan · ${asset.name}`, `<form class="form-stack">${fields(defs)}${formActions('Queue scan')}</form>${usable.length ? '' : `<p class="form-hint">No adapter targets kind ${esc(asset.kind)}.</p>`}`);
  bind(body, { close: closeDrawer });
  onSubmit($('form', body), async (form) => {
    const values = readFields(form, defs);
    const run = await post('/scans', { asset_id: asset.id, adapter: values.adapter, scope_id: values.scope_id, tier: values.tier || null }, { silent: true });
    closeDrawer();
    trackJob(run.job_id, `Scan ${values.adapter}`).then(() => reload());
    reload();
  });
}

async function renderDetail({ root, params, navigate }) {
  const id = params[0];
  root.innerHTML = `<p><a href="#/assets" class="ghost-link">← Assets</a></p><div data-detail></div>`;
  const node = $('[data-detail]', root);
  const view = section(node, async () => {
    const [asset, auths, findings, graph] = await Promise.all([
      get(`/assets/${id}`), get(`/assets/${id}/authorizations`, null, { silent: true }).catch(() => ({ items: [] })),
      get('/findings', { asset_id: id, limit: 50, sort: 'severity' }, { silent: true }).catch(() => ({ items: [] })),
      store.can('graph:read') ? get(`/assets/${id}/graph`, null, { silent: true }).catch(() => null) : null,
    ]);
    return { asset, auths: auths.items || [], findings: findings.items || [], graph };
  }, ({ asset, auths, findings, graph }) => {
    const auth = asset.authorization;
    const canAuth = store.can('assets:authorize');
    const canWrite = store.can('assets:write');
    const actions = `${store.can('scans:run') ? '<button class="btn" data-act="scan">Launch scan</button>' : ''}${canAuth ? (auth ? '<button class="btn negative" data-act="revoke">Revoke authorization</button>' : '') + '<button class="btn primary" data-act="authorize">Authorize</button>' : ''}${canWrite ? '<button class="btn" data-act="edit">Edit</button><button class="btn subtle" data-act="delete">Delete</button>' : ''}`;
    const nodes = graph?.nodes || [];
    const edges = graph?.edges || [];
    const byId = new Map(nodes.map((n) => [n.id, n]));
    return `${heading(nice(asset.kind), asset.name, asset.target, actions)}
      <div class="two-col">${panel({ title: 'Details', body: kv([
        ['Kind', esc(nice(asset.kind))], ['Environment', esc(nice(asset.environment))], ['Criticality', tag(asset.criticality)], ['Owner', esc(asset.owner)],
        ['Tags', (asset.tags || []).map((t) => `<span class="pill">${esc(t)}</span>`).join(' ')], ['Source', esc(asset.source)], ['External id', asset.external_id ? mono(asset.external_id) : ''],
        ['Created', esc(fmt(asset.created_at))], ['Last seen', time(asset.last_seen_at)], ['Last scan', time(asset.last_scan_at)], ['Graph node', asset.graph_node_id ? link(`#/graph/nodes/${asset.graph_node_id}`, asset.graph_node_id.slice(0, 8)) : ''],
      ]) })}
      ${panel({ title: 'Authorization', sub: `Status: ${asset.authorization_status}`, body: auth ? kv([
        ['Active', yesno(auth.active, 'active', 'inactive')], ['Active testing', yesno(auth.allow_active)], ['Intrusive testing', yesno(auth.allow_intrusive)],
        ['Expires', `${esc(fmt(auth.expires_at))} (${esc(ago(auth.expires_at))})`], ['Authorized by', mono(auth.authorized_by)], ['Scope document', esc(auth.scope_document_ref)],
        ['Attestation', `<span class="wrap-text">${esc(auth.attestation)}</span>`],
      ]) : empty('No current authorization', canAuth ? 'Record an attestation to enable testing of this asset.' : 'An operator must record an attestation before testing.') })}</div>
      <div class="two-col">${panel({ title: 'Open findings', sub: `${asset.open_findings?.total || 0} open`, actions: link(`#/findings?asset_id=${asset.id}`, 'All findings →', 'ghost-link'), flush: true, body: table({ columns: [
        { label: 'Finding', render: (f) => `<span class="cell-main limit-lines">${esc(f.title)}</span><span class="cell-sub">${esc(f.source)} · ${esc(f.rule)}</span>` },
        { label: 'Severity', render: (f) => sev(f.severity) }, { label: 'Status', render: (f) => tag(f.status) }, { label: 'Updated', render: (f) => time(f.updated_at) }],
      rows: findings.slice(0, 10), rowAttr: (f) => `data-act="finding" data-id="${esc(f.id)}"`, empty: 'No findings for this asset' }) })}
      ${panel({ title: 'Graph neighbours', sub: graph ? (graph.available ? `${nodes.length} nodes · ${edges.length} edges` : 'graph package not loaded') : 'not visible to your role', actions: asset.graph_node_id ? link(`#/graph/nodes/${asset.graph_node_id}`, 'Explore →', 'ghost-link') : '', body: edges.length ? `<div class="stat-list">${edges.slice(0, 12).map((e) => `<div class="stat-item"><span>${esc(byId.get(e.src_id)?.label || byId.get(e.src_id)?.key || e.src_id.slice(0, 8))} <span class="subtle">→ ${esc(e.rel)} →</span> ${esc(byId.get(e.dst_id)?.label || byId.get(e.dst_id)?.key || e.dst_id.slice(0, 8))}</span><strong>${esc(byId.get(e.dst_id)?.kind || '')}</strong></div>`).join('')}</div>` : empty('No neighbours yet', 'Collectors and test runs populate the evidence graph.') })}</div>
      ${panel({ title: 'Authorization history', flush: true, body: table({ columns: [
        { label: 'Created', render: (a) => esc(fmt(a.created_at)) }, { label: 'Active', render: (a) => yesno(a.active, 'active', a.revoked_at ? 'revoked' : 'expired') }, { label: 'Tiers', render: (a) => `${a.allow_intrusive ? 'intrusive' : a.allow_active ? 'active' : 'passive'}` },
        { label: 'Expires', render: (a) => esc(fmt(a.expires_at)) }, { label: 'By', render: (a) => mono(a.authorized_by) }, { label: 'Scope doc', render: (a) => esc(a.scope_document_ref || '—') }], rows: auths, empty: 'No authorizations recorded' }) })}
      <div style="margin-top:16px">${panel({ title: 'Recent test runs', flush: true, body: table({ columns: [
        { label: 'Adapter', render: (r) => esc(r.adapter) }, { label: 'Tier', render: (r) => esc(r.tier) }, { label: 'Status', render: (r) => tag(r.status) }, { label: 'Results', render: (r) => esc(r.result_count) }, { label: 'Started', render: (r) => time(r.created_at) }, { label: 'Error', cls: 'wrap', render: (r) => esc(r.error || '') }],
      rows: asset.last_runs?.test_runs || [], rowAttr: (r) => `data-act="run" data-id="${esc(r.id)}"`, empty: 'No test runs yet' }) })}</div>`;
  }, { onRender: ({ asset }) => { node.dataset.name = asset.name; } });
  const reload = () => view.reload(true);
  const load = () => get(`/assets/${id}`, null, { silent: true });
  bind(node, {
    authorize: async () => authorizeDrawer(await load(), reload),
    revoke: async () => {
      const result = await confirm('Revoke the current authorization? Active testing of this asset stops at its next scope check.', { label: 'Revoke', danger: true, comment: 'Reason (optional)' });
      if (!result) return;
      await post(`/assets/${id}/revoke-authorization`, { reason: result.comment || '' });
      toast('Authorization revoked');
      store.forget('assets:');
      reload();
    },
    edit: async () => openEdit(await load(), reload),
    delete: async () => {
      if (!(await confirm('Delete this asset? Findings and events are kept and detached. Assets with scan history cannot be deleted.', { label: 'Delete', danger: true }))) return;
      await del(`/assets/${id}`);
      toast('Asset deleted');
      store.forget('assets:');
      navigate('assets');
    },
    scan: async () => {
      const [asset, adapters, scopes] = await Promise.all([load(), get('/tests/adapters'), get('/tests/scopes', { limit: 200 })]);
      scanDrawer(asset, adapters.items, scopes.items, reload);
    },
    finding: (el) => navigate(`findings/${el.dataset.id}`),
    run: (el) => navigate(`testing/runs/${el.dataset.id}`),
  });
}

export default {
  render(ctx) { return ctx.params[0] ? renderDetail(ctx) : renderList(ctx); },
};
