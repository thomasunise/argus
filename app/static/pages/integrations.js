import { get, post, patch, del } from '../api.js';
import { store } from '../store.js';
import { section, readFilters, setQuery, trackJob } from '../common.js';
import { $, bind, closeDrawer, confirm, copy, drawer, esc, fields, formActions, heading, json, kv, newPager, onSubmit, pageNext, pagePrev, pageReset, pager, panel, readFields, schemaFields, selectHtml, table, tabs, tag, time, toast, mono, fmt, num, yesno, SEVERITY_ORDER } from '../ui.js';

const DELIVERY_STATUSES = ['queued', 'sent', 'failed', 'retrying', 'skipped'];

async function types() { return store.memo('integrations:types', () => get('/integrations/types')); }

function configForm(direction, impl, existing, reload) {
  const defs = [
    { name: 'name', label: 'Name', type: 'text', required: true, maxlength: 120, value: existing?.name || '' },
    { name: 'enabled', label: 'Enabled', type: 'checkbox', value: existing ? existing.enabled : true },
    ...schemaFields(impl.config_schema || {}, existing?.config || {}, { secretFields: impl.secret_fields || [], secretRefs: existing?.secret_refs || {}, group: 'config' }),
    ...(direction === 'outbound' ? [
      { name: 'topics', label: 'Topics', type: 'multiselect', options: impl.topics || [], value: existing?.topics || impl.default_topics || [] },
      { name: 'min_severity', label: 'Minimum severity', type: 'select', options: SEVERITY_ORDER, value: existing?.min_severity || 'low' },
    ] : []),
  ];
  const title = existing ? `Edit ${existing.name}` : `New ${impl.kind || impl.name} ${direction} integration`;
  const body = drawer(title, `<p class="info-line">${esc(impl.description || '')}</p><form class="form-stack">${fields(defs)}${formActions(existing ? 'Save' : 'Create integration')}</form>`);
  bind(body, { close: closeDrawer });
  onSubmit($('form', body), async (form) => {
    const values = readFields(form, defs);
    const payload = { name: values.name, enabled: values.enabled, config: values.config || {}, secret_refs: values.secret_refs || {} };
    if (direction === 'outbound') { payload.topics = values.topics; payload.min_severity = values.min_severity; }
    if (existing) await patch(`/integrations/${existing.id}`, payload, { silent: true });
    else await post('/integrations', { ...payload, kind: impl.kind || impl.name }, { silent: true });
    closeDrawer();
    toast(existing ? 'Integration updated' : 'Integration created');
    reload();
  });
}

function curlFor(source, example) {
  const payload = example ? JSON.stringify(example) : '{"events": []}';
  return `curl -X POST ${location.origin}/api/v1/ingest/${source} \\\n  -H "X-API-Key: $ARGUS_INGEST_KEY" \\\n  -H "Content-Type: application/json" \\\n  -H "X-Asset-ID: <optional asset id>" \\\n  -d '${payload.replace(/'/g, "'\\''").slice(0, 1200)}${payload.length > 1200 ? '…' : ''}'`;
}

async function openConfig(id, reload) {
  const c = await get(`/integrations/${id}`);
  const t = await types();
  const impl = c.direction === 'outbound' ? t.outbound.find((x) => x.kind === c.kind) : t.inbound.find((x) => x.name === c.kind || (x.aliases || []).includes(c.kind));
  const body = drawer(c.name, `<div class="chip-row"><span class="pill">${esc(c.kind)}</span><span class="pill">${esc(c.direction)}</span>${tag(c.enabled ? 'enabled' : 'disabled')}${c.last_error ? tag('error') : ''}</div>
    ${kv([['Created', `${esc(fmt(c.created_at))} by ${esc(c.created_by)}`], ['Updated', esc(fmt(c.updated_at))], ['Last delivery', time(c.last_delivery_at)], ['Last error', c.last_error ? `<span class="bad-text wrap-text">${esc(c.last_error)}</span>` : 'none'], ...(c.direction === 'outbound' ? [['Topics', (c.topics || []).map((x) => `<span class="pill">${esc(x)}</span>`).join(' ')], ['Min severity', esc(c.min_severity)]] : [['Verify endpoint', c.supports_verify ? mono(`${location.origin}/api/v1/ingest/${impl?.name || c.kind}/verify?integration=${c.id}`) : 'not supported (use the API-key endpoint)'], ['Pull sync', c.pull ? 'supported' : 'no']])])}
    <div class="inline-actions" style="margin-top:12px;flex-wrap:wrap">${store.can('integrations:write') ? `<button class="btn small primary" data-act="test">Send test</button>${c.pull ? '<button class="btn small" data-act="sync">Sync now</button>' : ''}<button class="btn small" data-act="edit">Edit</button><button class="btn small negative" data-act="delete">Delete</button>` : ''}${c.direction === 'outbound' ? `<a class="btn small" href="#/integrations/deliveries?integration_id=${esc(c.id)}">Deliveries</a>` : ''}</div>
    <div data-test></div>
    <h3>Configuration</h3>${json(c.config)}<h3>Secret references</h3>${Object.keys(c.secret_refs || {}).length ? kv(Object.entries(c.secret_refs).map(([k, v]) => [k, mono(v)])) : '<p class="form-hint">None</p>'}
    ${Object.keys(c.state || {}).length ? `<h3>State</h3>${json(c.state)}` : ''}
    ${c.direction === 'inbound' ? `<h3>Ingest</h3><div class="copy-row"><pre class="code-block">${esc(curlFor(impl?.name || c.kind, impl?.example))}</pre><button class="btn small" data-act="copy-curl">Copy</button></div>` : ''}`);
  bind(body, {
    test: async () => {
      const result = await post(`/integrations/${id}/test`, {});
      $('[data-test]', body).innerHTML = `<div class="callout ${result.ok ? '' : 'warning-callout'}" style="margin-top:12px"><strong>${result.ok ? 'Test succeeded' : 'Test failed'}</strong> · ${esc(result.direction)}${result.status_code ? ` · HTTP ${esc(result.status_code)}` : ''}${result.error ? `<br>${esc(result.error)}` : ''}${result.secrets_missing?.length ? `<br>missing secrets: ${esc(result.secrets_missing.join(', '))}` : ''}${result.ingest_url ? `<br>ingest at <span class="mono">${esc(result.ingest_url)}</span>` : ''}${result.skipped ? '<br>delivery skipped by filters' : ''}</div>`;
      reload();
    },
    sync: async () => { const r = await post(`/integrations/${id}/sync`, {}); trackJob(r.job_id, 'Sync').then(reload); },
    edit: () => { closeDrawer(); configForm(c.direction, impl || { kind: c.kind, config_schema: {}, secret_fields: c.secret_fields }, c, reload); },
    delete: async () => { if (!(await confirm('Delete this integration and its delivery log?', { label: 'Delete', danger: true }))) return; await del(`/integrations/${id}`); closeDrawer(); toast('Integration deleted'); reload(); },
    'copy-curl': () => copy(curlFor(impl?.name || c.kind, impl?.example), 'curl example copied'),
  });
}

function pickType(t, reload) {
  const body = drawer('New integration', `<h3>Inbound sources</h3><p class="form-hint">Events and findings pushed to <span class="mono">/api/v1/ingest/{source}</span> with an ingest-scoped API key, or pulled (Wazuh).</p><div class="card-grid">${t.inbound.map((p) => `<div class="card"><h3>${esc(p.name)}</h3><p>${esc(p.description || '')}</p><div class="chip-row">${p.supports_verify ? '<span class="pill">signed webhook</span>' : ''}${p.pull ? '<span class="pill">pull</span>' : ''}</div><div class="inline-actions"><button class="btn small primary" data-act="pick" data-dir="inbound" data-name="${esc(p.name)}">Configure</button></div></div>`).join('')}</div>
    <h3>Outbound channels</h3><div class="card-grid">${t.outbound.map((c) => `<div class="card"><h3>${esc(c.kind)}</h3><p>${esc(c.description || '')}</p><div class="chip-row">${(c.topics || []).slice(0, 4).map((x) => `<span class="pill">${esc(x)}</span>`).join('')}</div><div class="inline-actions"><button class="btn small primary" data-act="pick" data-dir="outbound" data-name="${esc(c.kind)}">Configure</button></div></div>`).join('')}</div>`, { wide: true });
  bind(body, { pick: (el) => { const impl = el.dataset.dir === 'outbound' ? t.outbound.find((x) => x.kind === el.dataset.name) : t.inbound.find((x) => x.name === el.dataset.name); closeDrawer(); configForm(el.dataset.dir, impl, null, reload); } });
}

export default {
  async render({ root, params, query, navigate }) {
    const tab = ['types', 'deliveries', 'batches', 'ingest'].includes(params[0]) ? params[0] : 'configs';
    const state = newPager();
    root.innerHTML = `${heading('Sensor ecosystem', 'Integrations', 'Inbound sources normalize external telemetry; outbound channels deliver findings and action events.',
      store.can('integrations:write') ? '<button class="btn primary" data-act="new">New integration</button>' : '')}
      ${tabs([{ id: 'configs', label: 'Configured' }, { id: 'types', label: 'Types' }, { id: 'ingest', label: 'Ingest endpoints' }, { id: 'deliveries', label: 'Deliveries' }, { id: 'batches', label: 'Ingest batches' }], tab)}<div data-body></div>`;
    const node = $('[data-body]', root);
    let list;
    if (tab === 'configs') {
      node.innerHTML = `<div class="toolbar"><div class="tool-filters" data-filters>${selectHtml('direction', ['inbound', 'outbound'], query.direction, { allLabel: 'Both directions', attrs: 'data-change="apply"' })}<input class="field-input" name="kind" placeholder="Kind" value="${esc(query.kind || '')}" data-enter="apply"></div></div><div class="panel" data-list></div>`;
      list = section($('[data-list]', node), () => get('/integrations', { ...readFilters($('[data-filters]', node)), limit: 100, cursor: state.cursor }), (data) => {
        state.next_cursor = data.next_cursor;
        return table({ columns: [
          { label: 'Integration', render: (c) => `<span class="cell-main">${esc(c.name)}</span><span class="cell-sub">${esc(c.kind)} · ${esc(c.direction)}</span>` }, { label: 'State', render: (c) => `${tag(c.enabled ? 'enabled' : 'disabled')}${c.last_error ? ' ' + tag('error') : ''}` },
          { label: 'Topics / mode', render: (c) => (c.direction === 'outbound' ? `${(c.topics || []).length} topics · ≥ ${esc(c.min_severity)}` : c.pull ? 'pull' : c.supports_verify ? 'signed webhook' : 'push') }, { label: 'Last delivery', render: (c) => time(c.last_delivery_at) }, { label: 'Updated', render: (c) => time(c.updated_at) },
          { label: '', render: (c) => `<button class="btn small" data-act="open" data-id="${esc(c.id)}">Open</button>` }],
        rows: data.items, empty: 'No integrations configured', emptySub: 'Add an inbound source or an outbound channel. Secrets are stored as references only.' }) + pager(state, data.items.length);
      });
      bind(node, {}, { apply: () => { pageReset(state); setQuery(navigate, 'integrations', [], readFilters($('[data-filters]', node))); list.reload(); } });
    } else if (tab === 'types') {
      list = section(node, types, (t) => `${panel({ title: 'Inbound sources', sub: `${t.inbound.length} parsers`, flush: true, body: table({ columns: [
        { label: 'Source', render: (p) => `<span class="cell-main">${esc(p.name)}</span><span class="cell-sub limit-lines" style="max-width:420px">${esc(p.description || '')}</span>` }, { label: 'Aliases', render: (p) => esc((p.aliases || []).join(', ') || '—') }, { label: 'Kind', render: (p) => esc(p.kind || '') }, { label: 'Signed webhook', render: (p) => yesno(p.supports_verify) }, { label: 'Pull', render: (p) => yesno(p.pull) }, { label: 'Secrets', render: (p) => esc((p.secret_fields || []).join(', ') || '—') },
        { label: '', render: (p) => `<div class="inline-actions"><button class="btn small" data-act="example" data-name="${esc(p.name)}">Example</button>${store.can('integrations:write') ? `<button class="btn small primary" data-act="pick" data-dir="inbound" data-name="${esc(p.name)}">Configure</button>` : ''}</div>` }], rows: t.inbound }) })}
        <div style="margin-top:16px">${panel({ title: 'Outbound channels', sub: `${t.outbound.length} channels`, flush: true, body: table({ columns: [
        { label: 'Channel', render: (c) => `<span class="cell-main">${esc(c.kind)}</span><span class="cell-sub limit-lines" style="max-width:420px">${esc(c.description || '')}</span>` }, { label: 'Topics', cls: 'wrap', render: (c) => (c.topics || []).map((x) => `<span class="pill">${esc(x)}</span>`).join(' ') }, { label: 'Secrets', render: (c) => esc((c.secret_fields || []).join(', ') || '—') },
        { label: '', render: (c) => `<div class="inline-actions"><button class="btn small" data-act="schema" data-name="${esc(c.kind)}">Schema</button>${store.can('integrations:write') ? `<button class="btn small primary" data-act="pick" data-dir="outbound" data-name="${esc(c.kind)}">Configure</button>` : ''}</div>` }], rows: t.outbound }) })}</div>`);
    } else if (tab === 'ingest') {
      list = section(node, types, (t) => `<div class="callout">Inbound endpoint: <span class="mono">POST ${esc(location.origin)}${esc(t.ingest_endpoint)}</span> with an API key that has the <span class="mono">ingest</span> scope (Admin → API keys). Sources with signature verification also accept <span class="mono">${esc(t.verify_endpoint)}</span> without an API key. Never put keys in URLs.</div>
        <div class="card-grid">${t.inbound.map((p) => `<div class="card"><h3>${esc(p.name)}</h3><p>${esc(p.description || '')}</p><pre class="code-block" style="max-height:220px;overflow:auto">${esc(curlFor(p.name, p.example))}</pre><div class="inline-actions"><button class="btn small" data-act="copy" data-name="${esc(p.name)}">Copy curl</button><button class="btn small" data-act="example" data-name="${esc(p.name)}">Example payload</button></div></div>`).join('')}</div>`);
    } else if (tab === 'deliveries') {
      node.innerHTML = `<div class="toolbar"><div class="tool-filters" data-filters>${selectHtml('status', DELIVERY_STATUSES, query.status, { allLabel: 'All statuses', attrs: 'data-change="apply"' })}<input class="field-input" name="integration_id" placeholder="Integration id" value="${esc(query.integration_id || '')}" data-enter="apply"><input class="field-input" name="topic" placeholder="Topic (finding.* allowed)" value="${esc(query.topic || '')}" data-enter="apply"></div></div><div class="panel" data-list></div>`;
      list = section($('[data-list]', node), () => get('/integrations/deliveries', { ...readFilters($('[data-filters]', node)), limit: 50, cursor: state.cursor }), (data) => {
        state.next_cursor = data.next_cursor;
        return table({ columns: [
          { label: 'Delivery', render: (d) => `<span class="cell-main">${esc(d.topic)}</span><span class="cell-sub">integration ${esc(d.integration_id?.slice(0, 8))} · ${esc(d.id.slice(0, 8))}</span>` }, { label: 'Status', render: (d) => tag(d.status) }, { label: 'Attempts', render: (d) => `${num(d.attempts)} / ${num(d.max_attempts)}` }, { label: 'Response', render: (d) => esc(d.response_code ?? '—') }, { label: 'Error', cls: 'wrap', render: (d) => `<span class="limit-lines">${esc(d.last_error || '')}</span>` }, { label: 'Created', render: (d) => time(d.created_at) }, { label: 'Sent', render: (d) => time(d.sent_at) },
          { label: '', render: (d) => `<div class="inline-actions"><button class="btn small" data-act="delivery" data-id="${esc(d.id)}">Payload</button>${store.can('integrations:write') && d.status !== 'sent' ? `<button class="btn small" data-act="retry" data-id="${esc(d.id)}">Retry</button>` : ''}</div>` }],
        rows: data.items, empty: 'No deliveries', emptySub: 'Outbound channels record every attempt here.' }) + pager(state, data.items.length);
      });
      bind(node, {}, { apply: () => { pageReset(state); setQuery(navigate, 'integrations', ['deliveries'], readFilters($('[data-filters]', node))); list.reload(); } });
    } else {
      node.innerHTML = `<div class="toolbar"><div class="tool-filters" data-filters><input class="field-input" name="source" placeholder="Source" value="${esc(query.source || '')}" data-enter="apply"></div></div><div class="panel" data-list></div>`;
      list = section($('[data-list]', node), () => get('/integrations/ingest/batches', { ...readFilters($('[data-filters]', node)), limit: 50, cursor: state.cursor }), (data) => {
        state.next_cursor = data.next_cursor;
        return table({ columns: [
          { label: 'Batch', render: (b) => `<span class="cell-main">${esc(b.source)}</span><span class="cell-sub">${esc(b.id.slice(0, 8))} · key ${esc(b.api_key_id?.slice(0, 8) || 'webhook')}</span>` }, { label: 'Received', render: (b) => esc(num(b.received)) }, { label: 'Accepted', render: (b) => esc(num(b.accepted)) }, { label: 'Duplicates', render: (b) => esc(num(b.duplicates)) }, { label: 'Findings', render: (b) => esc(num(b.findings)) }, { label: 'Errors', render: (b) => (b.errors ? `<span class="bad-text">${esc(num(b.errors))}</span>` : '0') }, { label: 'When', render: (b) => time(b.created_at) },
          { label: '', render: (b) => (b.error_samples?.length ? `<button class="btn small" data-act="errors" data-id="${esc(b.id)}">Errors</button>` : '') }],
        rows: data.items, empty: 'No ingest batches', emptySub: 'Each POST to /ingest/{source} records a batch with counts.' }) + pager(state, data.items.length);
      });
      bind(node, {}, { apply: () => { pageReset(state); setQuery(navigate, 'integrations', ['batches'], readFilters($('[data-filters]', node))); list.reload(); } });
    }
    bind(root, {
      new: async () => pickType(await types(), () => list.reload(true)),
      open: (el) => openConfig(el.dataset.id, () => list.reload(true)),
      pick: async (el) => { const t = await types(); const impl = el.dataset.dir === 'outbound' ? t.outbound.find((x) => x.kind === el.dataset.name) : t.inbound.find((x) => x.name === el.dataset.name); configForm(el.dataset.dir, impl, null, () => navigate('integrations')); },
      example: async (el) => { const t = await types(); const p = t.inbound.find((x) => x.name === el.dataset.name); drawer(`${p.name} example payload`, `<p class="info-line">${esc(p.description || '')}</p>${json(p.example)}<h3>Config schema</h3>${json(p.config_schema)}`); },
      schema: async (el) => { const t = await types(); const c = t.outbound.find((x) => x.kind === el.dataset.name); drawer(`${c.kind} config schema`, json(c.config_schema)); },
      copy: async (el) => { const t = await types(); const p = t.inbound.find((x) => x.name === el.dataset.name); copy(curlFor(p.name, p.example), 'curl example copied'); },
      delivery: async (el) => { const d = await get(`/integrations/deliveries/${el.dataset.id}`); drawer(`Delivery ${d.id.slice(0, 8)}`, `<div class="chip-row">${tag(d.status)}<span class="pill">${esc(d.topic)}</span></div>${kv([['Attempts', `${d.attempts}/${d.max_attempts}`], ['Response', esc(d.response_code ?? '—')], ['External ref', esc(d.external_ref || '—')], ['Next attempt', esc(fmt(d.next_attempt_at))], ['Error', esc(d.last_error || '—')]])}<h3>Payload</h3>${json(d.payload)}`); },
      retry: async (el) => { const r = await post(`/integrations/deliveries/${el.dataset.id}/retry`, {}); trackJob(r.job_id, 'Delivery retry').then(() => list.reload(true)); },
      errors: async (el) => { const data = await get('/integrations/ingest/batches', { limit: 500 }); const b = data.items.find((x) => x.id === el.dataset.id); drawer('Batch errors', json(b?.error_samples)); },
      'page-next': () => { pageNext(state); list.reload(); },
      'page-prev': () => { pagePrev(state); list.reload(); },
    });
    root.querySelector('.tabs').addEventListener('click', (event) => { const t = event.target.closest('[data-tab]'); if (t) navigate(t.dataset.tab === 'configs' ? 'integrations' : `integrations/${t.dataset.tab}`); });
  },
};
