import { get, post, patch, download } from '../api.js';
import { store } from '../store.js';
import { assetMap, assetName, section, readFilters, setQuery, settle, trackJob, userMap, userLabel } from '../common.js';
import { $, bind, drawer, drawerOpen, esc, fields, heading, json, kv, metrics, newPager, onSubmit, pageNext, pagePrev, pageReset, pager, readFields, selectHtml, sev, table, tag, time, toast, mono, nice, link, debounce, fmt, num, setDrawerTitle, SEVERITY_ORDER } from '../ui.js';

const STATUSES = ['open', 'investigating', 'resolved', 'accepted', 'false_positive'];
const TRANSITIONS = { open: ['investigating', 'resolved', 'accepted', 'false_positive'], investigating: ['open', 'resolved', 'accepted', 'false_positive'], resolved: ['open'], accepted: ['open'], false_positive: ['open'] };
const SORTS = [{ value: 'updated', label: 'Recently updated' }, { value: 'severity', label: 'Severity' }, { value: 'created', label: 'Newest' }];

/** Finding detail drawer, reusable from other pages. onChange() is called after any mutation. */
export async function openFinding(id, { onChange = () => {} } = {}) {
  const body = drawer('Finding', '<div class="loading">Loading…</div>');
  const canWrite = store.can('findings:write');
  const render = async (afterWrite = false) => {
    if (afterWrite) await settle();
    let f;
    try { f = await get(`/findings/${id}`, null, { silent: true }); } catch (err) { body.innerHTML = `<div class="error-box"><strong>Could not load</strong><span>${esc(err.message)}</span></div>`; return; }
    const [assets, users] = await Promise.all([assetMap().catch(() => new Map()), userMap().catch(() => new Map())]);
    setDrawerTitle(`Finding ${f.id.slice(0, 8)}`);
    const transitions = TRANSITIONS[f.status] || [];
    const userOptions = [{ value: '', label: 'Unassigned' }, ...[...users.values()].map((u) => ({ value: u.id, label: u.email }))];
    body.innerHTML = `<div class="chip-row">${sev(f.severity)}${tag(f.status)}<span class="pill">${esc(f.source)}</span>${f.kev ? '<span class="risk-chip risk-critical">KEV</span>' : ''}${f.cvss !== null && f.cvss !== undefined ? `<span class="pill" title="CVSS">CVSS ${esc(f.cvss)}</span>` : ''}${f.epss !== null && f.epss !== undefined ? `<span class="pill" title="EPSS">EPSS ${esc(f.epss)}</span>` : ''}</div>
      <h3 class="detail-title">${esc(f.title)}</h3>
      ${kv([['Asset', f.asset ? link(`#/assets/${f.asset.id}`, f.asset.name) : (f.asset_id ? mono(f.asset_id) : '')], ['Rule', mono(f.rule)], ['Occurrences', esc(num(f.occurrences))], ['First seen', esc(fmt(f.created_at))], ['Updated', time(f.updated_at)], ['Assignee', esc(userLabel(users, f.assignee) || '')], ['CVEs', (f.cve_ids || []).map((c) => `<span class="pill">${esc(c)}</span>`).join(' ')], ['Tags', (f.tags || []).map((t) => `<span class="pill">${esc(t)}</span>`).join(' ')]])}
      ${f.description ? `<h3>Description</h3><p class="info-line">${esc(f.description)}</p>` : ''}
      ${f.remediation ? `<h3>Remediation</h3><p class="info-line">${esc(f.remediation)}</p>` : ''}
      ${canWrite ? `<h3>Workflow</h3><div class="inline-actions" style="flex-wrap:wrap">${transitions.map((s) => `<button class="btn small" data-act="status" data-status="${s}">${esc(nice(s))}</button>`).join('')}${store.can('agents:run') ? '<button class="btn small primary" data-act="investigate">Investigate with agent</button>' : ''}</div>
      <form class="form-stack" data-meta style="margin-top:12px">${fields([
        users.size ? { name: 'assignee', label: 'Assignee', type: 'select', options: userOptions, value: f.assignee || '' } : { name: 'assignee', label: 'Assignee (user id)', type: 'text', value: f.assignee || '', hint: 'A user id with a membership in this tenant.' },
        { name: 'tags', label: 'Tags', type: 'tags', value: f.tags || [] },
      ])}<div class="form-error" data-form-error></div><div class="form-actions"><button type="submit" class="btn small">Save assignee and tags</button></div></form>` : ''}
      <h3>Evidence</h3>${json(f.evidence)}
      ${f.detection ? `<h3>Linked detection</h3><div class="stat-list"><div class="stat-item"><span>${link(`#/detections/${f.detection.id}`, f.detection.title || f.detection.id)}</span><strong>${f.detection.available === false ? 'unavailable' : `${esc(f.detection.rule_id || '')} ${tag(f.detection.status)}`}</strong></div></div>` : ''}
      ${(f.action_requests || []).length ? `<h3>Action requests</h3><div class="stat-list">${f.action_requests.map((r) => `<div class="stat-item"><span>${link(`#/actions/requests/${r.id}`, r.action_type)} <span class="subtle">${esc(r.risk)}</span></span><strong>${tag(r.status)}</strong></div>`).join('')}</div>` : ''}
      ${(f.agent_runs || []).length ? `<h3>Agent runs</h3><div class="stat-list">${f.agent_runs.map((r) => `<div class="stat-item"><span>${link(`#/agents/runs/${r.id}`, `${r.spec} · ${r.id.slice(0, 8)}`)} <span class="subtle">${esc(r.model || '')}</span></span><strong>${tag(r.status)}</strong></div>`).join('')}</div>` : ''}
      ${(f.investigations || []).length ? `<h3>Investigations</h3>${f.investigations.map((i) => `<div class="analysis-block" style="margin-bottom:8px"><strong>${esc(i.model)}</strong> · ${esc(i.confidence || '')} · ${esc(fmt(i.created_at))}\n${esc(i.summary)}</div>`).join('')}` : ''}
      ${store.can('actions:request') ? `<h3>Respond</h3><p class="form-hint">Open a policy-checked action request that references this finding.</p><a class="btn small" href="#/actions/requests/new?finding_id=${esc(f.id)}">Request action</a>` : ''}`;
    if (canWrite) {
      onSubmit($('form[data-meta]', body), async (form) => {
        const values = readFields(form, [{ name: 'assignee', type: 'text', label: 'Assignee' }, { name: 'tags', type: 'tags', label: 'Tags' }]);
        await patch(`/findings/${id}`, { assignee: values.assignee ?? '', tags: values.tags }, { silent: true });
        toast('Finding updated');
        onChange();
        render(true);
      });
    }
  };
  bind(body, {
    status: async (el) => {
      await patch(`/findings/${id}`, { status: el.dataset.status });
      toast(`Status set to ${nice(el.dataset.status)}`);
      onChange();
      render(true);
    },
    investigate: async () => {
      const result = await post(`/findings/${id}/investigate`, {});
      toast('Investigation queued');
      trackJob(result.job_id, 'Investigation').then(() => { onChange(); if (drawerOpen()) render(); });
    },
  });
  await render();
}

export default {
  async render({ root, params, query, navigate }) {
    const state = newPager();
    root.innerHTML = `${heading('Risk management', 'Findings', 'Deduplicated, evidence-linked issues from scanners, collectors, detections and ingest.',
      `<button class="btn" data-act="export">Export CSV</button>`)}
      <div data-stats></div>
      <div class="toolbar"><div class="tool-filters" data-filters>
        <input class="field-input" name="search" placeholder="Search title, rule, CVE" value="${esc(query.search || '')}" data-enter="apply">
        ${selectHtml('status', [{ value: 'open,investigating', label: 'Active' }, ...STATUSES], query.status === undefined ? 'open,investigating' : query.status, { allLabel: 'All statuses', attrs: 'data-change="apply"' })}
        ${selectHtml('severity', SEVERITY_ORDER, query.severity, { allLabel: 'Any severity', attrs: 'data-change="apply"' })}
        <input class="field-input" name="source" placeholder="Source" value="${esc(query.source || '')}" style="min-width:120px" data-enter="apply">
        <input class="field-input" name="asset_id" placeholder="Asset id" value="${esc(query.asset_id || '')}" style="min-width:120px" data-enter="apply">
        ${selectHtml('sort', SORTS, query.sort || 'updated', { allLabel: null, attrs: 'data-change="apply"' })}
      </div><span class="muted" data-count></span></div>
      <div class="panel" data-list></div>`;
    const filters = () => readFilters($('[data-filters]', root));
    section($('[data-stats]', root), () => get('/findings/stats'), (s) => metrics([
      { label: 'Open', value: s.open_total, caption: `${s.by_severity?.critical || 0} critical · ${s.by_severity?.high || 0} high` },
      { label: 'Opened / resolved (7d)', value: `${num(s.opened_7d)} / ${num(s.resolved_7d)}`, caption: 'last seven days' },
      { label: 'Mean time to resolve', value: s.mean_time_to_resolve_hours === null ? '—' : `${num(s.mean_time_to_resolve_hours)}h`, caption: `${s.resolved_sample} resolved sampled` },
      { label: 'Known exploited (KEV)', value: s.kev_open, caption: `aging: ${Object.entries(s.aging || {}).map(([k, v]) => `${k} ${v}`).join(' · ')}` },
    ]));
    const list = section($('[data-list]', root), async () => {
      const [data, assets] = await Promise.all([get('/findings', { ...filters(), limit: 50, cursor: state.cursor }), assetMap().catch(() => new Map())]);
      return { data, assets };
    }, ({ data, assets }) => {
      state.next_cursor = data.next_cursor;
      $('[data-count]', root).textContent = `${data.items.length}${data.next_cursor ? '+' : ''} findings`;
      return table({
        columns: [
          { label: 'Finding', render: (f) => `<span class="cell-main limit-lines" style="max-width:420px">${esc(f.title)}</span><span class="cell-sub">${esc(assetName(assets, f.asset_id))} · ${esc(f.rule)}${f.cve_ids?.length ? ` · ${esc(f.cve_ids.slice(0, 2).join(', '))}` : ''}</span>` },
          { label: 'Severity', render: (f) => sev(f.severity) },
          { label: 'Status', render: (f) => tag(f.status) },
          { label: 'Source', render: (f) => esc(f.source) },
          { label: 'Seen', render: (f) => `${esc(num(f.occurrences))}×` },
          { label: 'Updated', render: (f) => time(f.updated_at) },
        ],
        rows: data.items, rowAttr: (f) => `data-act="open" data-id="${esc(f.id)}"`,
        empty: 'No findings match', emptySub: 'Run a scan, connect a collector or send events through ingest to populate findings.',
      }) + pager(state, data.items.length);
    });
    const apply = () => { pageReset(state); setQuery(navigate, 'findings', [], filters()); list.reload(); };
    bind(root, {
      open: (el) => { history.replaceState(null, '', `#/findings/${el.dataset.id}`); openFinding(el.dataset.id, { onChange: () => list.reload(true) }); },
      export: async () => { await download('/findings/export.csv', 'sentinel-findings.csv', filters()); toast('CSV exported (audited)'); },
      'page-next': () => { pageNext(state); list.reload(); },
      'page-prev': () => { pagePrev(state); list.reload(); },
    }, { apply });
    $('input[name=search]', root).addEventListener('input', debounce(apply, 350));
    if (params[0]) openFinding(params[0], { onChange: () => list.reload(true) });
    const onClosed = () => { if (location.hash.startsWith('#/findings/')) history.replaceState(null, '', '#/findings'); };
    document.addEventListener('drawer:closed', onClosed);
    return () => document.removeEventListener('drawer:closed', onClosed);
  },
};
