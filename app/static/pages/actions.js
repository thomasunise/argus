import { get, post } from '../api.js';
import { store } from '../store.js';
import { section, readFilters, setQuery, trackJob } from '../common.js';
import { $, bind, closeDrawer, confirm, drawer, empty, esc, fields, formActions, heading, json, kv, metrics, newPager, onSubmit, pageNext, pagePrev, pageReset, pager, panel, readFields, risk, schemaFields, selectHtml, table, tabs, tag, time, toast, mono, nice, link, fmt, num, yesno } from '../ui.js';
import { applyKillSwitch } from '../app.js';

const REQUEST_STATUSES = ['pending', 'approved', 'auto_approved', 'rejected', 'executing', 'executed', 'failed', 'rolled_back', 'cancelled'];
const RUN_STATUSES = ['queued', 'running', 'executed', 'failed', 'rolled_back', 'rollback_failed'];
const EXECUTABLE = new Set(['approved', 'auto_approved']);

function killSwitchPanel(state) {
  if (!state) return '';
  const engaged = state.effective;
  return `<section class="panel" style="margin-bottom:16px"><div class="panel-head"><div><h2>Kill switch</h2><small>${engaged ? (state.global ? 'Global ACTIONS_KILL_SWITCH is set in the server environment' : `Tenant kill switch engaged${state.detail?.reason ? `: ${esc(state.detail.reason)}` : ''}${state.detail?.by ? ` by ${esc(state.detail.by)}` : ''}`) : 'Actions may execute after policy and approvals'}</small></div><div class="inline-actions">${tag(engaged ? 'engaged' : 'disengaged')}${store.can('actions:kill_switch') && !state.global ? `<button class="btn ${engaged ? 'primary' : 'negative'}" data-act="kill" data-enabled="${engaged ? '' : '1'}">${engaged ? 'Disengage' : 'Engage kill switch'}</button>` : ''}</div></div></section>`;
}

async function toggleKill(enable) {
  const result = await confirm(enable ? 'Engage the tenant kill switch? Every pending and future action request is blocked from executing until it is disengaged.' : 'Disengage the kill switch and allow approved actions to execute?', { label: enable ? 'Engage' : 'Disengage', danger: enable, comment: 'Reason' });
  if (!result) return false;
  const state = await post('/actions/kill-switch', { enabled: enable, reason: result.comment || '' });
  applyKillSwitch(state);
  toast(enable ? 'Kill switch engaged' : 'Kill switch disengaged');
  return true;
}

async function renderNew({ root, query, navigate }) {
  root.innerHTML = `<p><a href="#/actions/requests" class="ghost-link">← Requests</a></p><div data-form></div>`;
  const node = $('[data-form]', root);
  const catalog = (await get('/actions/catalog')).items;
  let actionType = query.action_type || catalog[0]?.name;
  const draw = () => {
    const action = catalog.find((a) => a.name === actionType) || catalog[0];
    const params = { ...(action?.params_schema ? {} : {}) };
    if (query.finding_id && action?.params_schema?.properties?.finding_id) params.finding_id = query.finding_id;
    const defs = [
      { name: 'action_type', label: 'Action type', type: 'select', required: true, options: catalog.map((a) => ({ value: a.name, label: `${a.name} · ${a.risk}${a.reversible ? ', reversible' : ''}${a.available ? '' : ' (unavailable)'}` })), value: actionType },
      ...schemaFields(action?.params_schema || {}, params, { group: 'params' }),
      { name: 'reason', label: 'Reason', type: 'textarea', required: true, rows: 3, placeholder: 'Why this action, referencing the evidence.' },
      { name: 'finding_id', label: 'Finding id (optional)', type: 'text', value: query.finding_id || '', omitEmpty: true },
      { name: 'detection_id', label: 'Detection id (optional)', type: 'text', value: query.detection_id || '', omitEmpty: true },
    ];
    node.innerHTML = `${heading('Action broker', 'New action request', 'Policy decides whether the request is pending approval or auto-approved; a dry run is recorded before anything executes.')}
      <div class="two-col"><form class="panel"><div class="panel-body form-stack" style="padding-top:18px">${fields(defs)}${formActions('Create request', null)}</div></form>
      ${panel({ title: action?.name || 'Action', sub: action?.category || '', body: action ? `<p class="info-line">${esc(action.description)}</p><div class="chip-row">${risk(action.risk)}${yesno(action.reversible, 'reversible', 'irreversible')}${yesno(action.available, 'available', 'unavailable')}${(action.platforms || []).map((p) => `<span class="pill">${esc(p)}</span>`).join('')}</div><h3>Parameter schema</h3>${json(action.params_schema)}` : empty('No action types') })}</div>`;
    const form = $('form', node);
    form.elements.action_type.addEventListener('change', (event) => { actionType = event.target.value; draw(); });
    onSubmit(form, async () => {
      const values = readFields(form, defs);
      const req = await post('/actions/requests', { action_type: values.action_type, params: values.params || {}, reason: values.reason, finding_id: values.finding_id || null, detection_id: values.detection_id || null }, { silent: true });
      toast(`Request ${req.status.replace('_', ' ')}`);
      navigate(`actions/requests/${req.id}`);
    });
  };
  draw();
}

async function renderRequest({ root, params, navigate }) {
  const id = params[1];
  root.innerHTML = `<p><a href="#/actions/requests" class="ghost-link">← Requests</a></p><div data-req></div>`;
  let timer = null;
  const me = store.user?.id;
  const view = section($('[data-req]', root), () => get(`/actions/requests/${id}`), (r) => {
    if (r.status === 'executing') timer = setTimeout(() => view.reload(true), 2000);
    const canApprove = store.can('actions:approve') && r.status === 'pending' && r.requested_by !== me && !(r.approvals || []).some((a) => a.approver_id === me);
    const canExecute = store.can('actions:execute') && EXECUTABLE.has(r.status);
    const canCancel = ['pending', 'approved', 'auto_approved'].includes(r.status) && (r.requested_by === me || store.can('actions:approve'));
    const dry = r.dry_run || {};
    return `${heading('Action request', r.action_type, r.reason, `${canApprove ? '<button class="btn primary" data-act="approve">Approve</button><button class="btn negative" data-act="reject">Reject</button>' : ''}${canExecute ? '<button class="btn primary" data-act="execute">Execute</button>' : ''}${canCancel ? '<button class="btn subtle" data-act="cancel">Cancel request</button>' : ''}`)}
      <div class="chip-row">${tag(r.status)}${risk(r.risk)}${r.agent_originated ? `<span class="pill">agent-originated${r.agent_run_id ? ` · ${link(`#/agents/runs/${r.agent_run_id}`, 'run')}` : ''}</span>` : ''}${r.finding_id ? link(`#/findings/${r.finding_id}`, `finding ${r.finding_id.slice(0, 8)}`) : ''}${r.detection_id ? link(`#/detections/${r.detection_id}`, `detection ${r.detection_id.slice(0, 8)}`) : ''}</div>
      ${metrics([{ label: 'Approvals', value: `${num(r.approval_count || 0)} / ${num(r.required_approvals)}`, caption: r.owner_approval_required ? 'an owner must be among the approvers' : 'any approver with actions:approve' }, { label: 'Dry run', value: dry.ok === undefined ? '—' : dry.ok ? 'ok' : 'failed', caption: dry.summary ? dry.summary.slice(0, 80) : 'not recorded' }, { label: 'Blast radius', value: dry.blast_radius?.entities ?? dry.blast_radius?.count ?? (dry.blast_radius ? Object.keys(dry.blast_radius).length : '—'), caption: dry.blast_radius?.kind ? `${dry.blast_radius.kind}${dry.blast_radius.ids?.length ? `: ${dry.blast_radius.ids.slice(0, 2).join(', ')}` : ''}` : 'entities touched' }, { label: 'Expires', value: `<span style="font-size:16px">${esc(fmt(r.expires_at))}</span>`, caption: `requested ${fmt(r.created_at)}` }])}
      <div class="two-col">${panel({ title: 'Request', body: kv([['Requested by', `${mono(r.requested_by)} <span class="subtle">${esc(r.requested_by_role || '')}</span>`], ['Decided', esc(fmt(r.decided_at))], ['Parameters', json(r.params)]]) })}
      ${panel({ title: 'Policy decision', sub: 'evaluated at request time; re-evaluated at execution', body: r.policy && Object.keys(r.policy).length ? `${(r.policy.reasons || []).length ? `<ul class="steps">${r.policy.reasons.map((x) => `<li>${esc(x)}</li>`).join('')}</ul>` : ''}${json(r.policy)}` : empty('No policy record') })}</div>
      <div class="two-col">${panel({ title: 'Dry run', body: dry && Object.keys(dry).length ? `${dry.warnings?.length ? `<div class="callout warning-callout">${dry.warnings.map(esc).join('<br>')}</div>` : ''}${json(dry)}` : empty('No dry run recorded', 'The broker records a dry run when the request is created.') })}
      ${panel({ title: `Approvals (${(r.approvals || []).length})`, body: (r.approvals || []).length ? `<div class="timeline">${r.approvals.map((a) => `<div class="step ${a.decision === 'reject' ? 'error' : 'model'}"><div class="step-marker"></div><div><div class="step-head"><strong>${esc(nice(a.decision))}</strong><span class="pill">${esc(a.approver_role)}</span>${a.can_approve_critical ? '<span class="pill">owner slot</span>' : ''}<span class="step-meta">${esc(a.approver_id)} · ${esc(fmt(a.created_at))}</span></div>${a.comment ? `<p class="info-line" style="margin:4px 0 0">${esc(a.comment)}</p>` : ''}</div></div>`).join('')}</div>` : empty('No decisions yet', r.status === 'pending' ? 'Waiting for an approver other than the requester.' : '') })}</div>
      ${panel({ title: `Runs (${(r.runs || []).length})`, flush: true, body: table({ columns: [
        { label: 'Run', render: (x) => mono(x.id.slice(0, 8)) }, { label: 'Status', render: (x) => tag(x.status) }, { label: 'Dry run', render: (x) => (x.dry_run ? 'yes' : 'no') }, { label: 'Executed by', render: (x) => mono(x.executed_by) }, { label: 'Started', render: (x) => time(x.started_at || x.created_at) }, { label: 'Rollback', render: (x) => (x.rolled_back_at ? `rolled back ${time(x.rolled_back_at)}` : x.has_rollback_payload ? 'available' : '—') }, { label: '', render: (x) => `<div class="inline-actions"><button class="btn small" data-act="run" data-id="${esc(x.id)}">Detail</button>${store.can('actions:rollback') && x.has_rollback_payload && !x.rolled_back_at && x.status === 'executed' ? `<button class="btn small negative" data-act="rollback" data-id="${esc(x.id)}">Roll back</button>` : ''}</div>` }],
      rows: r.runs || [], empty: 'Not executed yet' }) })}`;
  });
  bind(root, {
    approve: async () => { const result = await confirm('Approve this action request?', { label: 'Approve', comment: 'Comment' }); if (!result) return; await post(`/actions/requests/${id}/approve`, { decision: 'approve', comment: result.comment || '' }); toast('Approval recorded'); view.reload(true); },
    reject: async () => { const result = await confirm('Reject this action request?', { label: 'Reject', danger: true, comment: 'Comment' }); if (!result) return; await post(`/actions/requests/${id}/approve`, { decision: 'reject', comment: result.comment || '' }); toast('Request rejected'); view.reload(true); },
    execute: async () => { if (!(await confirm('Execute this action now? The broker re-checks the kill switch and policy, performs a dry run, then executes.', { label: 'Execute' }))) return; const result = await post(`/actions/requests/${id}/execute`, {}); trackJob(result.job_id, 'Action execution').then(() => view.reload(true)); view.reload(true); },
    cancel: async () => { const result = await confirm('Cancel this request?', { label: 'Cancel request', danger: true, comment: 'Reason' }); if (!result) return; await post(`/actions/requests/${id}/cancel`, { reason: result.comment || '' }); toast('Request cancelled'); view.reload(true); },
    run: (el) => openRun(el.dataset.id, () => view.reload(true)),
    rollback: (el) => rollback(el.dataset.id, () => view.reload(true)),
  });
  return () => clearTimeout(timer);
}

async function rollback(runId, reload) {
  if (!(await confirm('Roll back this run using its recorded rollback payload?', { label: 'Roll back', danger: true }))) return;
  const result = await post(`/actions/runs/${runId}/rollback`, {});
  trackJob(result.job_id, 'Rollback').then(reload);
  reload();
}

export async function openRun(runId, reload = () => {}) {
  const r = await get(`/actions/runs/${runId}`);
  const body = drawer(`Run ${r.id.slice(0, 8)}`, `<div class="chip-row">${tag(r.status)}${r.dry_run ? '<span class="pill">dry run</span>' : ''}${link(`#/actions/requests/${r.request_id}`, 'request')}</div>
    ${kv([['Executed by', mono(r.executed_by)], ['Started', esc(fmt(r.started_at))], ['Finished', esc(fmt(r.finished_at))], ['Job', mono(r.job_id)], ['Rolled back', r.rolled_back_at ? `${esc(fmt(r.rolled_back_at))} by ${esc(r.rolled_back_by)}` : 'no'], ['Rollback payload', r.has_rollback_payload ? 'recorded' : 'none']])}
    ${r.error ? `<div class="callout warning-callout"><strong>Error</strong> ${esc(r.error)}</div>` : ''}
    <h3>Result</h3>${json(r.result)}${r.rollback_payload ? `<h3>Rollback payload</h3>${json(r.rollback_payload)}` : ''}
    ${store.can('actions:rollback') && r.has_rollback_payload && !r.rolled_back_at && r.status === 'executed' ? '<div class="form-actions"><button class="btn negative" data-act="rollback">Roll back</button></div>' : ''}`);
  bind(body, { rollback: async () => { closeDrawer(); await rollback(r.id, reload); } });
}

async function renderIndex({ root, params, query, navigate }) {
  const tab = ['requests', 'runs'].includes(params[0]) ? params[0] : 'catalog';
  const state = newPager();
  root.innerHTML = `${heading('Action broker', 'Actions', 'Typed remediation actions with policy, dual approval, dry runs, rollback and a kill switch.',
    store.can('actions:request') ? '<a class="btn primary" href="#/actions/requests/new">New request</a>' : '')}
    <div data-kill></div>
    ${tabs([{ id: 'catalog', label: 'Catalog' }, { id: 'requests', label: 'Requests' }, { id: 'runs', label: 'Runs' }], tab)}<div data-body></div>`;
  section($('[data-kill]', root), () => get('/actions/kill-switch'), killSwitchPanel);
  const node = $('[data-body]', root);
  let list;
  if (tab === 'catalog') {
    node.innerHTML = `<div class="toolbar"><div class="tool-filters" data-filters><input class="field-input" name="search" placeholder="Filter by name or platform" data-enter="apply"><label class="check"><input type="checkbox" name="available" data-change="apply"> <span>Available only</span></label></div><span class="muted" data-count></span></div><div data-grid></div>`;
    let items = [];
    const draw = () => {
      const f = readFilters($('[data-filters]', node));
      const shown = items.filter((a) => (!f.search || `${a.name} ${a.platforms.join(' ')} ${a.description}`.toLowerCase().includes(f.search.toLowerCase())) && (!f.available || a.available));
      $('[data-count]', node).textContent = `${shown.length} of ${items.length} action types`;
      $('[data-grid]', node).innerHTML = shown.length ? `<div class="card-grid">${shown.map((a) => `<div class="card ${a.available ? '' : 'muted-card'}"><h3>${esc(a.name)}</h3><p>${esc(a.description)}</p><div class="chip-row">${risk(a.risk)}${yesno(a.reversible, 'reversible', 'irreversible')}${tag(a.available ? 'available' : 'unavailable')}</div><p class="form-hint">${esc(a.category)} · ${esc((a.platforms || []).join(', '))}</p><div class="inline-actions"><button class="btn small" data-act="schema" data-name="${esc(a.name)}">Params</button>${store.can('actions:request') ? `<a class="btn small primary" href="#/actions/requests/new?action_type=${encodeURIComponent(a.name)}">Request</a>` : ''}</div></div>`).join('')}</div>` : empty('No action types match');
    };
    list = section($('[data-grid]', node), () => get('/actions/catalog'), (data) => { items = data.items; setTimeout(draw, 0); return ''; });
    bind(node, { schema: (el) => { const a = items.find((x) => x.name === el.dataset.name); drawer(a.name, `<p class="info-line">${esc(a.description)}</p>${json(a.params_schema)}`); } }, { apply: draw });
    $('input[name=search]', node).addEventListener('input', draw);
  } else if (tab === 'requests') {
    node.innerHTML = `<div class="toolbar"><div class="tool-filters" data-filters>${selectHtml('status', REQUEST_STATUSES, query.status, { allLabel: 'All statuses', attrs: 'data-change="apply"' })}<input class="field-input" name="action_type" placeholder="Action type" value="${esc(query.action_type || '')}" data-enter="apply"><label class="check"><input type="checkbox" name="agent_only" ${query.agent_only ? 'checked' : ''} data-change="apply"> <span>Agent-originated only</span></label></div></div><div class="panel" data-list></div>`;
    list = section($('[data-list]', node), () => get('/actions/requests', { ...readFilters($('[data-filters]', node)), limit: 50, cursor: state.cursor }), (data) => {
      state.next_cursor = data.next_cursor;
      return table({ columns: [
        { label: 'Request', render: (r) => `<span class="cell-main">${esc(r.action_type)}</span><span class="cell-sub limit-lines" style="max-width:380px">${esc(r.reason)}</span>` }, { label: 'Status', render: (r) => tag(r.status) }, { label: 'Risk', render: (r) => risk(r.risk) },
        { label: 'Approvals', render: (r) => `${num(r.required_approvals)} needed${r.owner_approval_required ? ' · owner' : ''}` }, { label: 'Requested by', render: (r) => `<span class="mono">${esc(r.requested_by?.slice(0, 12))}</span> <span class="subtle">${esc(r.requested_by_role || '')}${r.agent_originated ? ' · agent' : ''}</span>` }, { label: 'Created', render: (r) => time(r.created_at) }],
      rows: data.items, rowAttr: (r) => `data-act="open" data-id="${esc(r.id)}"`, empty: 'No requests', emptySub: 'Requests come from analysts, operators or agent specialists.' }) + pager(state, data.items.length);
    });
    bind(node, {}, { apply: () => { pageReset(state); setQuery(navigate, 'actions', ['requests'], readFilters($('[data-filters]', node))); list.reload(); } });
  } else {
    node.innerHTML = `<div class="toolbar"><div class="tool-filters" data-filters>${selectHtml('status', RUN_STATUSES, query.status, { allLabel: 'All statuses', attrs: 'data-change="apply"' })}</div></div><div class="panel" data-list></div>`;
    list = section($('[data-list]', node), () => get('/actions/runs', { ...readFilters($('[data-filters]', node)), limit: 50, cursor: state.cursor }), (data) => {
      state.next_cursor = data.next_cursor;
      return table({ columns: [
        { label: 'Run', render: (x) => `<span class="cell-main">${esc(x.id.slice(0, 8))}</span><span class="cell-sub">request ${esc(x.request_id.slice(0, 8))}</span>` }, { label: 'Status', render: (x) => tag(x.status) }, { label: 'Summary', cls: 'wrap', render: (x) => `<span class="limit-lines">${esc(x.result?.summary || x.error || '')}</span>` }, { label: 'Executed by', render: (x) => mono(x.executed_by) }, { label: 'Started', render: (x) => time(x.started_at || x.created_at) }, { label: 'Rollback', render: (x) => (x.rolled_back_at ? tag('rolled_back') : x.has_rollback_payload ? 'available' : '—') },
        { label: '', render: (x) => `<div class="inline-actions"><button class="btn small" data-act="run" data-id="${esc(x.id)}">Detail</button>${store.can('actions:rollback') && x.has_rollback_payload && !x.rolled_back_at && x.status === 'executed' ? `<button class="btn small negative" data-act="rollback" data-id="${esc(x.id)}">Roll back</button>` : ''}</div>` }],
      rows: data.items, empty: 'No runs yet' }) + pager(state, data.items.length);
    });
    bind(node, {}, { apply: () => { pageReset(state); setQuery(navigate, 'actions', ['runs'], readFilters($('[data-filters]', node))); list.reload(); } });
  }
  bind(root, {
    kill: async (el) => { if (await toggleKill(Boolean(el.dataset.enabled))) $('[data-kill]', root).innerHTML = killSwitchPanel(store.killSwitch); },
    open: (el) => navigate(`actions/requests/${el.dataset.id}`),
    run: (el) => openRun(el.dataset.id, () => list.reload(true)),
    rollback: (el) => rollback(el.dataset.id, () => list.reload(true)),
    'page-next': () => { pageNext(state); list.reload(); },
    'page-prev': () => { pagePrev(state); list.reload(); },
  });
  root.querySelector('.tabs').addEventListener('click', (event) => { const t = event.target.closest('[data-tab]'); if (t) navigate(t.dataset.tab === 'catalog' ? 'actions' : `actions/${t.dataset.tab}`); });
}

export default {
  render(ctx) {
    if (ctx.params[0] === 'requests' && ctx.params[1] === 'new') return renderNew(ctx);
    if (ctx.params[0] === 'requests' && ctx.params[1]) return renderRequest(ctx);
    return renderIndex(ctx);
  },
};
