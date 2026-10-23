import { get, post } from '../api.js';
import { store } from '../store.js';
import { section, readFilters, setQuery, trackJob } from '../common.js';
import { $, bind, closeDrawer, confirm, drawer, empty, esc, fields, formActions, heading, json, kv, metrics, ms, newPager, onSubmit, pageNext, pagePrev, pageReset, pager, panel, readFields, selectHtml, table, tabs, tag, time, toDate, toast, mono, link, fmt, num } from '../ui.js';

const RUN_STATUSES = ['queued', 'running', 'completed', 'failed', 'cancelled', 'refused', 'budget_exhausted'];
const TERMINAL = new Set(['completed', 'failed', 'cancelled', 'refused', 'budget_exhausted']);

function runForm(specs, preset = {}, onDone) {
  const allowed = specs.filter((s) => s.allowed);
  const defs = [
    { name: 'spec', label: 'Specialist', type: 'select', required: true, options: allowed.map((s) => ({ value: s.name, label: `${s.name} — ${s.description.slice(0, 70)}` })), value: preset.spec || allowed[0]?.name },
    { name: 'task', label: 'Task', type: 'textarea', rows: 3, placeholder: 'Describe what the specialist should do; defaults to the spec description.', value: preset.task || '' },
    { name: 'finding_id', label: 'Finding id (optional)', type: 'text', value: preset.finding_id || '', omitEmpty: true },
    { name: 'inputs', label: 'Inputs (JSON)', type: 'json', rows: 5, value: preset.inputs || {} },
  ];
  const body = drawer('Run specialist', `${allowed.length ? '' : '<div class="callout warning-callout">Your role cannot run any specialist.</div>'}<form class="form-stack">${fields(defs)}${formActions('Queue run')}</form>`);
  bind(body, { close: closeDrawer });
  onSubmit($('form', body), async (form) => {
    const values = readFields(form, defs);
    const run = await post('/agents/run', { spec: values.spec, task: values.task, inputs: values.inputs, finding_id: values.finding_id || null }, { silent: true });
    closeDrawer();
    toast(`Run ${run.id.slice(0, 8)} queued`);
    onDone(run);
  });
}

function stepHtml(s) {
  return `<div class="step ${s.kind === 'model' ? 'model' : ''} ${s.error ? 'error' : ''}"><div class="step-marker"></div><div><div class="step-head"><span class="pill">${esc(s.kind)}</span><strong>${esc(s.name || '')}</strong><span class="step-meta">#${s.index} · ${esc(ms(s.latency_ms))}${s.tokens_in || s.tokens_out ? ` · ${num(s.tokens_in || 0)} in / ${num(s.tokens_out || 0)} out tokens` : ''} · ${esc(fmt(s.created_at))}</span></div>
    ${s.error ? `<p class="bad-text" style="margin:6px 0 0">${esc(s.error)}</p>` : ''}
    <details><summary>Input and output</summary>${json(s.input)}${json(s.output)}</details></div></div>`;
}

async function renderRun({ root, params, navigate }) {
  const id = params[1];
  root.innerHTML = `<p><a href="#/agents/runs" class="ghost-link">← Runs</a></p><div data-run></div>`;
  let timer = null;
  const view = section($('[data-run]', root), () => get(`/agents/runs/${id}`), (r) => {
    if (!TERMINAL.has(r.status)) timer = setTimeout(() => view.reload(true), 2000);
    return `${heading(r.spec, r.task || `Run ${r.id.slice(0, 8)}`, '', `${store.can('agents:run') && !TERMINAL.has(r.status) ? '<button class="btn negative" data-act="cancel">Cancel run</button>' : ''}${store.can('agents:run') ? '<button class="btn" data-act="rerun">Run again</button>' : ''}`)}
      <div class="chip-row">${tag(r.status)}<span class="pill">${esc(r.provider || 'none')} · ${esc(r.model || 'fallback')}</span>${r.finding_id ? link(`#/findings/${r.finding_id}`, `finding ${r.finding_id.slice(0, 8)}`) : ''}${r.parent_run_id ? link(`#/agents/runs/${r.parent_run_id}`, 'parent run') : ''}</div>
      ${metrics([{ label: 'Steps', value: r.steps_count, caption: `${(r.steps || []).filter((s) => s.kind === 'tool').length} tool · ${(r.steps || []).filter((s) => s.kind === 'model').length} model` }, { label: 'Tokens', value: `${num(r.input_tokens)} / ${num(r.output_tokens)}`, caption: 'input / output' }, { label: 'Cost estimate', value: `$${Number(r.cost_estimate_usd || 0).toFixed(4)}`, caption: 'provider list price' }, { label: 'Duration', value: r.started_at && r.finished_at ? ms(toDate(r.finished_at) - toDate(r.started_at)) : '—', caption: `${r.started_at ? `started ${fmt(r.started_at)}` : 'not started'}` }])}
      ${r.error ? `<div class="callout warning-callout"><strong>Error</strong> ${esc(r.error)}</div>` : ''}
      <div class="two-col">${panel({ title: 'Output', body: r.output && Object.keys(r.output).length ? json(r.output) : empty(TERMINAL.has(r.status) ? 'No output' : 'Waiting for the run to finish') })}${panel({ title: 'Inputs', body: `${json(r.inputs)}${kv([['Created by', mono(r.created_by)], ['Created', esc(fmt(r.created_at))], ['Finished', esc(fmt(r.finished_at))], ['Job', mono(r.job_id)]])}` })}</div>
      ${panel({ title: `Steps (${(r.steps || []).length})`, sub: 'model calls and tool invocations in order', body: (r.steps || []).length ? `<div class="timeline">${r.steps.map(stepHtml).join('')}</div>` : empty('No steps recorded') })}`;
  });
  bind(root, {
    cancel: async () => { if (!(await confirm('Cancel this run?', { label: 'Cancel run', danger: true }))) return; await post(`/agents/runs/${id}/cancel`, {}); toast('Run cancelled'); view.reload(true); },
    rerun: async () => { const [specs, r] = await Promise.all([get('/agents/specs'), get(`/agents/runs/${id}`)]); runForm(specs.items, { spec: r.spec, task: r.task, inputs: r.inputs, finding_id: r.finding_id }, (run) => navigate(`agents/runs/${run.id}`)); },
  });
  return () => clearTimeout(timer);
}

async function renderEval({ root, params }) {
  const id = params[1];
  root.innerHTML = `<p><a href="#/agents/evals" class="ghost-link">← Evals</a></p><div data-eval></div>`;
  let timer = null;
  const view = section($('[data-eval]', root), () => get(`/evals/${id}`), (e) => {
    if (!['completed', 'failed', 'cancelled'].includes(e.status)) timer = setTimeout(() => view.reload(true), 2000);
    const cases = e.report?.cases || e.report?.results || [];
    return `${heading('Eval run', `${e.suite}${e.spec ? ` · ${e.spec}` : ''}`, '')}<div class="chip-row">${tag(e.status)}<span class="pill">${esc(fmt(e.created_at))}</span></div>
      ${metrics([{ label: 'Cases', value: e.total, caption: 'in this run' }, { label: 'Passed', value: e.passed, caption: e.total ? `${Math.round((e.passed / e.total) * 100)}%` : '' }, { label: 'Failed', value: e.failed, caption: '' }, { label: 'Finished', value: `<span style="font-size:16px">${esc(fmt(e.finished_at))}</span>`, caption: `created by ${e.created_by}` }])}
      ${panel({ title: 'Per-case results', flush: true, body: Array.isArray(cases) && cases.length ? table({ columns: [
        { label: 'Case', render: (c) => `<span class="cell-main">${esc(c.id || c.case_id || c.name || '')}</span>${c.description || c.task ? `<span class="cell-sub limit-lines">${esc(c.description || c.task)}</span>` : ''}` }, { label: 'Result', render: (c) => tag(c.passed === true || c.ok === true || c.status === 'passed' ? 'passed' : c.passed === false || c.ok === false ? 'failed' : (c.status || 'unknown')) },
        { label: 'Score', render: (c) => esc(c.score ?? '—') }, { label: 'Detail', cls: 'wrap', render: (c) => `<span class="limit-lines">${esc(c.reason || c.detail || c.error || (c.expected !== undefined ? `expected ${JSON.stringify(c.expected)}` : ''))}</span>` },
        { label: '', render: (c) => `<button class="btn small" data-act="case" data-id="${esc(c.id || c.case_id || c.name || '')}">Raw</button>` }], rows: cases }) : `<div class="panel-body">${e.report && Object.keys(e.report).length ? json(e.report) : empty('No report yet')}</div>` })}`;
  });
  bind(root, { case: async (el) => { const e = await get(`/evals/${id}`); const cases = e.report?.cases || e.report?.results || []; const c = cases.find((x) => (x.id || x.case_id || x.name) === el.dataset.id); drawer(`Case ${el.dataset.id}`, json(c)); } });
  return () => clearTimeout(timer);
}

async function renderIndex({ root, params, query, navigate }) {
  const tab = ['runs', 'evals', 'tools'].includes(params[0]) ? params[0] : 'specs';
  const state = newPager();
  root.innerHTML = `${heading('Agentic operations', 'Agents', 'Sandboxed specialists with typed tools, step budgets and traces. Agents propose; policy and people approve.',
    `${store.can('agents:run') ? '<button class="btn primary" data-act="run">Run specialist</button>' : ''}${store.can('evals:run') && tab === 'evals' ? '<button class="btn" data-act="eval-run">Run eval suite</button>' : ''}`)}
    ${tabs([{ id: 'specs', label: 'Specialists' }, { id: 'runs', label: 'Runs' }, { id: 'evals', label: 'Evals' }, { id: 'tools', label: 'Tools' }], tab)}<div data-body></div>`;
  const node = $('[data-body]', root);
  let list;
  if (tab === 'specs') {
    list = section(node, () => get('/agents/specs'), (data) => `<div class="card-grid">${data.items.map((s) => `<div class="card"><h3>${esc(s.name)}</h3><p>${esc(s.description)}</p><div class="chip-row">${tag(s.allowed ? 'permitted' : 'not permitted')}<span class="pill" title="required permission">${esc(s.required_permission)}</span><span class="pill">${esc(s.max_steps)} steps</span>${s.has_fallback ? '<span class="pill">rules fallback</span>' : ''}</div><p class="form-hint">Tools: ${esc((s.tools || []).join(', ') || 'none')}</p><div class="inline-actions"><button class="btn small" data-act="spec" data-name="${esc(s.name)}">Output schema</button>${store.can('agents:run') && s.allowed ? `<button class="btn small primary" data-act="run" data-spec="${esc(s.name)}">Run</button>` : ''}</div></div>`).join('')}</div>`);
  } else if (tab === 'runs') {
    node.innerHTML = `<div class="toolbar"><div class="tool-filters" data-filters>${selectHtml('status', RUN_STATUSES, query.status, { allLabel: 'All statuses', attrs: 'data-change="apply"' })}<input class="field-input" name="spec" placeholder="Spec" value="${esc(query.spec || '')}" style="min-width:120px" data-enter="apply"><input class="field-input" name="finding_id" placeholder="Finding id" value="${esc(query.finding_id || '')}" data-enter="apply"></div></div><div class="panel" data-list></div>`;
    list = section($('[data-list]', node), () => get('/agents/runs', { ...readFilters($('[data-filters]', node)), limit: 50, cursor: state.cursor }), (data) => {
      state.next_cursor = data.next_cursor;
      return table({ columns: [
        { label: 'Run', render: (r) => `<span class="cell-main">${esc(r.spec)}</span><span class="cell-sub limit-lines" style="max-width:420px">${esc(r.task)}</span>` }, { label: 'Status', render: (r) => tag(r.status) }, { label: 'Model', render: (r) => esc(r.model || r.provider || '—') },
        { label: 'Steps', render: (r) => esc(num(r.steps_count)) }, { label: 'Tokens', render: (r) => `${num(r.input_tokens)}/${num(r.output_tokens)}` }, { label: 'Created', render: (r) => time(r.created_at) }],
      rows: data.items, rowAttr: (r) => `data-act="open-run" data-id="${esc(r.id)}"`, empty: 'No runs', emptySub: 'Queue a specialist or investigate a finding to create a run.' }) + pager(state, data.items.length);
    });
    bind(node, {}, { apply: () => { pageReset(state); setQuery(navigate, 'agents', ['runs'], readFilters($('[data-filters]', node))); list.reload(); } });
  } else if (tab === 'evals') {
    node.innerHTML = `<div data-suites></div><div class="panel" data-list style="margin-top:16px"></div>`;
    section($('[data-suites]', node), () => get('/evals/suites'), (data) => `<div class="card-grid">${data.items.map((s) => `<div class="card"><h3>${esc(s.name)}</h3><p>${esc(s.description || '')}</p><div class="chip-row"><span class="pill">${esc(s.cases)} cases</span>${s.spec ? `<span class="pill">spec ${esc(s.spec)}</span>` : ''}${s.grader ? `<span class="pill">grader ${esc(s.grader)}</span>` : ''}</div>${store.can('evals:run') ? `<div class="inline-actions"><button class="btn small primary" data-act="eval-run" data-suite="${esc(s.name)}">Run suite</button></div>` : ''}</div>`).join('') || empty('No eval suites installed')}</div>`);
    list = section($('[data-list]', node), () => get('/evals', { limit: 50, cursor: state.cursor }), (data) => {
      state.next_cursor = data.next_cursor;
      return `<div class="panel-head"><div><h2>Eval runs</h2></div></div>${table({ columns: [
        { label: 'Suite', render: (e) => `<span class="cell-main">${esc(e.suite)}</span><span class="cell-sub">${esc(e.spec || '')}</span>` }, { label: 'Status', render: (e) => tag(e.status) }, { label: 'Passed / total', render: (e) => `${num(e.passed)} / ${num(e.total)}` }, { label: 'Failed', render: (e) => (e.failed ? `<span class="bad-text">${esc(e.failed)}</span>` : '0') }, { label: 'Created', render: (e) => time(e.created_at) }],
      rows: data.items, rowAttr: (e) => `data-act="open-eval" data-id="${esc(e.id)}"`, empty: 'No eval runs yet' })}${pager(state, data.items.length)}`;
    });
  } else {
    list = section(node, () => get('/agents/tools'), (data) => `<div class="panel">${table({ columns: [
      { label: 'Tool', render: (t) => `<span class="cell-main">${esc(t.name)}</span><span class="cell-sub limit-lines" style="max-width:520px">${esc(t.description)}</span>` }, { label: 'Risk', render: (t) => tag(t.risk) }, { label: 'Tags', render: (t) => (t.tags || []).map((x) => `<span class="pill">${esc(x)}</span>`).join(' ') },
      { label: '', render: (t) => `<button class="btn small" data-act="tool" data-name="${esc(t.name)}">Schema</button>` }], rows: data.items, empty: 'No tools registered' })}</div>`);
  }
  bind(root, {
    run: async (el) => { const specs = await get('/agents/specs'); runForm(specs.items, { spec: el.dataset.spec }, (run) => navigate(`agents/runs/${run.id}`)); },
    spec: async (el) => { const specs = await get('/agents/specs'); const s = specs.items.find((x) => x.name === el.dataset.name); drawer(`${s.name} output schema`, json(s.output_schema)); },
    tool: async (el) => { const tools = await get('/agents/tools'); const t = tools.items.find((x) => x.name === el.dataset.name); drawer(`${t.name} input schema`, `<p class="info-line">${esc(t.description)}</p>${json(t.input_schema)}`); },
    'open-run': (el) => navigate(`agents/runs/${el.dataset.id}`),
    'open-eval': (el) => navigate(`agents/evals/${el.dataset.id}`),
    'eval-run': async (el) => {
      const suites = (await get('/evals/suites')).items;
      const defs = [{ name: 'suite', label: 'Suite', type: 'select', required: true, options: suites.map((s) => s.name), value: el.dataset.suite || suites[0]?.name }, { name: 'spec', label: 'Spec override (optional)', type: 'text', omitEmpty: true }, { name: 'case_ids', label: 'Case ids (optional)', type: 'tags', omitEmpty: true }];
      const body = drawer('Run eval suite', `<form class="form-stack">${fields(defs)}${formActions('Queue eval')}</form>`);
      bind(body, { close: closeDrawer });
      onSubmit($('form', body), async (form) => {
        const values = readFields(form, defs);
        const run = await post('/evals/run', { suite: values.suite, spec: values.spec || null, case_ids: values.case_ids?.length ? values.case_ids : null }, { silent: true });
        closeDrawer();
        trackJob(run.job_id, `Eval ${values.suite}`).then(() => list?.reload(true));
        navigate(`agents/evals/${run.id}`);
      });
    },
    'page-next': () => { pageNext(state); list.reload(); },
    'page-prev': () => { pagePrev(state); list.reload(); },
  });
  root.querySelector('.tabs').addEventListener('click', (event) => { const t = event.target.closest('[data-tab]'); if (t) navigate(t.dataset.tab === 'specs' ? 'agents' : `agents/${t.dataset.tab}`); });
}

export default {
  render(ctx) {
    if (ctx.params[0] === 'runs' && ctx.params[1]) return renderRun(ctx);
    if (ctx.params[0] === 'evals' && ctx.params[1]) return renderEval(ctx);
    return renderIndex(ctx);
  },
};
