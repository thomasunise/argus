import { get } from '../api.js';
import { store, prefGet, prefSet, ROLES, ROLE_PERMS } from '../store.js';
import { section } from '../common.js';
import { $, bind, esc, heading, metrics, panel, severityBar, meter, sparkline, sev, tag, time, num, nice, empty, link } from '../ui.js';

// ---------------------------------------------------------------- get-started checklist

const hiddenKey = () => `onboarding-hidden:${store.tenant?.id || ''}:${store.user?.id || ''}`;
const lowestRole = (perm) => ROLES.find((role) => ROLE_PERMS[role].has(perm)) || 'admin';

function checklistStep(step) {
  const can = store.can(step.perm);
  const side = step.done ? '<span class="subtle">Done</span>'
    : can ? `<a class="ghost-link" href="${esc(step.href)}">Start →</a>`
      : `<span class="subtle" title="Your role cannot do this step">Needs ${esc(lowestRole(step.perm))}</span>`;
  return `<li class="checklist-step${step.done ? ' done' : ''}" data-step="${esc(step.id)}"><span class="checklist-mark" aria-hidden="true">${step.done ? '✓' : ''}</span><div class="checklist-text"><strong>${esc(step.title)}</strong><span>${esc(step.description)}</span></div><div class="checklist-side">${side}<span class="visually-hidden">${step.done ? 'completed' : 'not completed'}</span></div></li>`;
}

/** Shown until every step is done or the user hides it. Steps come from the tenant's own data, never from clicks. */
async function getStarted(node) {
  if (prefGet(hiddenKey(), false)) return;
  let data;
  try { data = await get('/reports/onboarding', null, { silent: true }); } catch { return; }
  const open = data.steps.filter((s) => !s.done);
  if (!open.length || !open.some((s) => store.can(s.perm))) return;
  node.innerHTML = panel({
    cls: 'checklist',
    title: 'Get started with Argus',
    sub: `${data.completed} of ${data.total} done · steps tick off on their own as your workspace fills in`,
    actions: '<button class="btn subtle small" data-act="hide-checklist">Hide</button>',
    body: `${meter(data.completed, data.total)}<ol class="checklist-steps">${data.steps.map(checklistStep).join('')}</ol>`,
  });
  bind(node, { 'hide-checklist': () => { prefSet(hiddenKey(), true); node.innerHTML = ''; } });
}

function posturePanel(p) {
  const rows = Object.entries(p.components || {}).map(([name, c]) =>
    `<div class="component" title="${esc(c.description || '')}"><strong>${esc(nice(name))}</strong>${c.included ? meter(c.score) : '<span class="subtle">not measurable yet</span>'}<span class="subtle">${c.included ? `${c.score}` : '—'} <span class="muted2">· w${c.weight}</span></span></div>`).join('');
  return `<div class="score"><strong>${esc(p.score)}</strong><span>grade ${esc(p.grade)} · heuristic trend indicator</span></div><div style="margin-top:14px">${rows}</div>`;
}

function trendCards(t) {
  const series = t.series || [];
  const defs = [['findings_opened', 'Findings opened'], ['findings_closed', 'Findings closed'], ['events', 'Events'], ['detections', 'Detections']];
  return `<div class="spark-row">${defs.map(([key, label]) => {
    const values = series.map((d) => d[key] ?? 0);
    const total = t.totals?.[key];
    return `<div class="spark-card"><div class="metric-top"><span>${esc(label)}</span><span class="subtle">${t.days}d</span></div><div class="metric-value">${total === null || total === undefined ? '—' : num(total)}</div>${sparkline(values, { label })}</div>`;
  }).join('')}</div>`;
}

export default {
  async render({ root }) {
    root.innerHTML = `${heading('Command center', 'Security overview', 'Live posture, detections and pending work for this tenant.',
      `${store.can('findings:read') ? '<a class="btn" href="#/findings">Open findings</a>' : ''}${store.can('reports:read') ? '<a class="btn" href="#/reports">Reports</a>' : ''}`)}
      <div data-section="onboarding"></div>
      <div data-section="summary">${''}</div>
      <div class="content-grid"><section class="panel"><div class="panel-head"><div><h2>Posture</h2><small>Weighted components from /reports/posture</small></div><a class="ghost-link" href="#/reports/posture">Details →</a></div><div class="panel-body" data-section="posture"></div></section>
      <section class="panel"><div class="panel-head"><div><h2>Open findings</h2><small>By severity</small></div><a class="ghost-link" href="#/findings">View all →</a></div><div class="panel-body" data-section="severity"></div></section></div>
      <div data-section="trends" style="margin-bottom:16px"></div>
      <div class="overview-bottom"><section class="panel"><div class="panel-head"><div><h2>Recent detections</h2><small>Latest rule matches</small></div><a class="ghost-link" href="#/detections">Open detections →</a></div><div class="panel-body" data-section="detections"></div></section>
      <section class="panel"><div class="panel-head"><div><h2>Pending action requests</h2><small>Awaiting approval</small></div><a class="ghost-link" href="#/actions/requests?status=pending">Review →</a></div><div class="panel-body" data-section="requests"></div></section></div>
      <div class="overview-bottom" style="margin-top:16px"><section class="panel"><div class="panel-head"><div><h2>Last runs</h2><small>Collectors, tests and the detection engine</small></div></div><div class="panel-body" data-section="runs"></div></section>
      <section class="panel"><div class="panel-head"><div><h2>Audit chain</h2><small>Tamper-evident hash chain</small></div><a class="ghost-link" href="#/audit">Open audit →</a></div><div class="panel-body" data-section="audit"></div></section></div>
      <p class="footer-note">Findings reflect only attached telemetry and enabled checks. A clean dashboard does not imply that an asset is secure.</p>`;

    getStarted($('[data-section=onboarding]', root));
    section($('[data-section=summary]', root), () => get('/reports/summary'), (s) => {
      const f = s.findings || {};
      return metrics([
        { label: 'Open findings', value: f.open ?? 0, caption: `${f.open_by_severity?.critical || 0} critical · ${f.new_24h || 0} new in 24h` },
        { label: 'Assets', value: s.assets?.total ?? 0, caption: `${s.assets?.approved || 0} with a current authorization` },
        { label: 'Events (24h)', value: s.events?.last_24h ?? 0, caption: `${num(s.events?.total || 0)} retained in total` },
        { label: 'Open detections', value: s.detections?.open ?? 0, caption: s.detections?.available ? `${s.detections.canaries_active || 0} active canaries` : 'detection package not loaded' },
      ]);
    }, {
      onRender(s) {
        $('[data-section=severity]', root).innerHTML = `${severityBar(s.findings?.open_by_severity || {})}<div class="risk-stat-row"><div><strong>${num(s.findings?.total || 0)}</strong><span>TOTAL FINDINGS</span></div><div><strong>${num(s.agent_runs_24h?.total || 0)}</strong><span>AGENT RUNS 24H</span></div><div><strong>${num(s.graph?.attack_paths_open || 0)}</strong><span>OPEN ATTACK PATHS</span></div></div>`;
        const runs = [];
        if (s.collectors?.last_run) runs.push(['Collector', s.collectors.last_run.status, s.collectors.last_run.created_at, `#/collectors/${s.collectors.last_run.config_id}`, s.collectors.last_run.error]);
        if (s.tests?.last_run) runs.push([`Test · ${s.tests.last_run.adapter}`, s.tests.last_run.status, s.tests.last_run.created_at, `#/testing/runs/${s.tests.last_run.id}`, `${s.tests.last_run.result_count} results`]);
        if (s.detections?.last_run) runs.push(['Detection engine', s.detections.last_run.finished_at ? 'completed' : 'running', s.detections.last_run.started_at, '#/detections/rules', `${s.detections.last_run.rules_run} rules · ${s.detections.last_run.detections_created} new`]);
        $('[data-section=runs]', root).innerHTML = runs.length
          ? `<div class="activity-list">${runs.map(([label, status, at, href, extra]) => `<div class="activity-item"><div class="activity-marker"></div><div class="activity-text"><strong>${link(href, label)}</strong><span>${esc(extra || '')} · ${esc(nice(status))} · ${time(at)}</span></div>${tag(status)}</div>`).join('')}</div>`
          : empty('No runs yet', 'Configure a collector or a test plan to see execution history here.');
        const chain = s.audit_chain || {};
        $('[data-section=audit]', root).innerHTML = `<div class="stat-list"><div class="stat-item"><span>Chain</span><strong>${chain.valid ? '<span class="ok-text">valid</span>' : '<span class="bad-text">broken</span>'}</strong></div><div class="stat-item"><span>Entries verified</span><strong>${num(chain.checked || 0)}</strong></div><div class="stat-item"><span>Signed</span><strong>${chain.signed ? 'yes (HMAC)' : 'no signing key'}</strong></div><div class="stat-item"><span>AI provider</span><strong>${esc(s.ai_provider || 'none')}</strong></div><div class="stat-item"><span>Actions</span><strong>${s.tenant?.actions_enabled ? 'enabled' : 'disabled for tenant'}</strong></div></div>`;
      },
    });
    section($('[data-section=posture]', root), () => get('/reports/posture'), posturePanel);
    section($('[data-section=trends]', root), () => get('/reports/trends', { days: 30 }), trendCards);
    if (store.can('detections:read')) {
      section($('[data-section=detections]', root), () => get('/detections', { limit: 6 }), (d) => d.items.length
        ? `<div class="activity-list">${d.items.map((x) => `<div class="activity-item"><div class="activity-marker"></div><div class="activity-text"><strong>${link(`#/detections/${x.id}`, x.title)}</strong><span>${esc(x.rule_id)} · ${esc(x.entity || '')} · ${time(x.last_seen_at)}</span></div>${sev(x.severity)}</div>`).join('')}</div>`
        : empty('No detections', 'Rules run over ingested events; nothing has matched yet.'));
    } else $('[data-section=detections]', root).innerHTML = empty('Not visible to your role');
    section($('[data-section=requests]', root), () => get('/actions/requests', { status: 'pending', limit: 6 }), (d) => d.items.length
      ? `<div class="activity-list">${d.items.map((r) => `<div class="activity-item"><div class="activity-marker"></div><div class="activity-text"><strong>${link(`#/actions/requests/${r.id}`, r.action_type)}</strong><span>${esc(r.reason)} · ${esc(r.requested_by_role || '')} · ${time(r.created_at)}</span></div>${tag(r.status)}</div>`).join('')}</div>`
      : empty('Nothing pending', 'Action requests awaiting approval appear here.'));
  },
};
