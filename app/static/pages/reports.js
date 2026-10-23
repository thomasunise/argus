import { get } from '../api.js';
import { section } from '../common.js';
import { $, bind, drawer, empty, esc, heading, json, kv, meter, metrics, panel, selectHtml, sparkline, table, tabs, tag, nice, fmt, num } from '../ui.js';

function postureView(p) {
  return `${metrics([{ label: 'Posture score', value: `${p.score}`, caption: `grade ${p.grade} · generated ${fmt(p.generated_at)}` }, ...Object.entries(p.components).slice(0, 3).map(([name, c]) => ({ label: nice(name), value: c.included ? `${c.score}` : '—', caption: c.included ? `weight ${c.weight}` : 'not measurable yet' }))])}
    ${panel({ title: 'Components', sub: p.note, body: Object.entries(p.components).map(([name, c]) => `<div class="component"><strong title="${esc(c.description)}">${esc(nice(name))}</strong>${c.included ? meter(c.score) : '<span class="subtle">not measurable yet</span>'}<span class="subtle">${c.included ? c.score : '—'}</span></div>`).join('') })}
    <div style="margin-top:16px">${panel({ title: 'Evidence per component', flush: true, body: table({ columns: [{ label: 'Component', render: ([name]) => esc(nice(name)) }, { label: 'Description', cls: 'wrap', render: ([, c]) => esc(c.description) }, { label: 'Weight', render: ([, c]) => esc(c.weight) }, { label: 'Score', render: ([, c]) => (c.included ? esc(c.score) : '—') }, { label: '', render: ([name]) => `<button class="btn small" data-act="detail" data-name="${esc(name)}">Detail</button>` }], rows: Object.entries(p.components) }) })}</div>`;
}

function complianceView(r) {
  const t = r.totals || {};
  return `${metrics([{ label: 'Satisfied', value: t.satisfied, caption: `${t.automated} automated controls` }, { label: 'Partial', value: t.partial, caption: 'some evidence present' }, { label: 'Missing', value: t.missing, caption: 'no supporting evidence' }, { label: 'Manual', value: t.manual, caption: 'requires documented procedure' }])}
    <div class="callout">${esc(r.disclaimer || '')}</div>
    ${panel({ title: r.name, sub: `${t.controls} controls · satisfied ratio ${t.satisfied_ratio ?? '—'}`, flush: true, body: table({ columns: [
      { label: 'Control', render: (c) => `<span class="cell-main">${esc(c.id)}</span><span class="cell-sub">${esc(c.title)}</span>` }, { label: 'Status', render: (c) => tag(c.status) }, { label: 'Description', cls: 'wrap', render: (c) => `<span class="limit-lines">${esc(c.description)}</span>` },
      { label: 'Evidence', cls: 'wrap', render: (c) => (c.evidence?.length ? c.evidence.map((e) => `<span class="pill" title="${esc(e.summary || '')}">${e.ok === true ? '✓' : e.ok === false ? '✗' : '·'} ${esc(e.key)}</span>`).join(' ') : `<span class="subtle">${esc(c.manual_guidance ? 'manual' : '—')}</span>`) },
      { label: '', render: (c) => `<button class="btn small" data-act="control" data-id="${esc(c.id)}">Detail</button>` }], rows: r.controls }) })}`;
}

function trendsView(t) {
  const keys = [['findings_opened', 'Findings opened'], ['findings_closed', 'Findings closed'], ['events', 'Events'], ['detections', 'Detections']];
  return `<div class="spark-row" style="margin-bottom:16px">${keys.map(([k, label]) => `<div class="spark-card"><div class="metric-top"><span>${esc(label)}</span><span class="subtle">${t.days}d</span></div><div class="metric-value">${t.totals?.[k] === null || t.totals?.[k] === undefined ? '—' : num(t.totals[k])}</div>${sparkline(t.series.map((d) => d[k] ?? 0), { label })}</div>`).join('')}</div>
    ${panel({ title: 'Daily series', sub: t.note, flush: true, body: table({ columns: [{ label: 'Day', render: (d) => esc(d.day) }, ...keys.map(([k, label]) => ({ label, render: (d) => (d[k] === null || d[k] === undefined ? '—' : esc(num(d[k]))) }))], rows: [...t.series].reverse() }) })}`;
}

export default {
  async render({ root, params, query, navigate }) {
    const tab = ['compliance', 'trends'].includes(params[0]) ? params[0] : 'posture';
    root.innerHTML = `${heading('Reporting', 'Reports', 'Posture score, compliance evidence mapping and daily trends, all derived from recorded state.')}
      ${tabs([{ id: 'posture', label: 'Posture' }, { id: 'compliance', label: 'Compliance' }, { id: 'trends', label: 'Trends' }], tab)}<div data-body></div>`;
    const node = $('[data-body]', root);
    let data = null;
    if (tab === 'posture') {
      section(node, async () => (data = await get('/reports/posture')), postureView);
      bind(node, { detail: (el) => { const c = data.components[el.dataset.name]; drawer(nice(el.dataset.name), `<p class="info-line">${esc(c.description)}</p>${kv([['Score', c.included ? esc(c.score) : 'not measurable'], ['Weight', esc(c.weight)]])}<h3>Detail</h3>${json(c.detail)}`); } });
    } else if (tab === 'compliance') {
      const frameworks = await get('/reports/compliance');
      const framework = query.framework || params[1] || frameworks.items[0]?.framework;
      node.innerHTML = `<div class="toolbar"><div class="tool-filters">${selectHtml('framework', frameworks.items.map((f) => ({ value: f.framework, label: `${f.name} (${f.controls} controls)` })), framework, { allLabel: null, attrs: 'data-change="framework"' })}</div><span class="muted">Generating a report is audited as reports.compliance_generated</span></div><div data-report></div>`;
      section($('[data-report]', node), async () => (data = await get(`/reports/compliance/${encodeURIComponent(framework)}`)), (r) => (r.controls?.length ? complianceView(r) : empty('No controls in this framework')));
      bind(node, { control: (el) => { const c = data.controls.find((x) => x.id === el.dataset.id); drawer(`${c.id} · ${c.title}`, `<div class="chip-row">${tag(c.status)}</div><p class="info-line">${esc(c.description)}</p>${c.manual_guidance ? `<h3>Manual guidance</h3><p class="info-line">${esc(c.manual_guidance)}</p>` : ''}<h3>Evidence</h3>${c.evidence?.length ? c.evidence.map((e) => `<div class="callout"><strong>${esc(e.key)}</strong> · ${e.ok === true ? '<span class="ok-text">ok</span>' : e.ok === false ? '<span class="bad-text">not satisfied</span>' : '<span class="subtle">not measurable</span>'}<br>${esc(e.summary || '')}${e.value !== undefined && e.value !== null ? json(e.value) : ''}</div>`).join('') : '<p class="form-hint">No automated evidence; document the procedure manually.</p>'}`); } }, { framework: (el) => navigate(`reports/compliance/${el.value}`) });
    } else {
      const days = Number(query.days) || 30;
      node.innerHTML = `<div class="toolbar"><div class="tool-filters">${selectHtml('days', [{ value: 7, label: '7 days' }, { value: 30, label: '30 days' }, { value: 90, label: '90 days' }], days, { allLabel: null, attrs: 'data-change="days"' })}</div></div><div data-trends></div>`;
      section($('[data-trends]', node), () => get('/reports/trends', { days }), trendsView);
      bind(node, {}, { days: (el) => navigate(`reports/trends?days=${el.value}`) });
    }
    root.querySelector('.tabs').addEventListener('click', (event) => { const t = event.target.closest('[data-tab]'); if (t) navigate(t.dataset.tab === 'posture' ? 'reports' : `reports/${t.dataset.tab}`); });
  },
};
