// Small render helpers. Every helper returns an HTML string built from escaped values, or operates on DOM nodes.
export const esc = (value) => String(value ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
export const $ = (selector, root = document) => root.querySelector(selector);
export const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

export function el(html) {
  const template = document.createElement('template');
  template.innerHTML = html.trim();
  return template.content.firstElementChild;
}

// ---------------------------------------------------------------- formatting

/** The API emits naive UTC timestamps (no Z or offset); treat those as UTC rather than local time. */
export function toDate(value) {
  if (value instanceof Date) return value;
  if (typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?$/.test(value)) return new Date(`${value}Z`);
  return new Date(value);
}

export function ago(value) {
  if (!value) return 'never';
  const seconds = Math.floor((Date.now() - toDate(value).getTime()) / 1000);
  if (!Number.isFinite(seconds)) return 'unknown';
  if (seconds < 0) return 'in ' + duration(-seconds);
  if (seconds < 45) return 'just now';
  return duration(seconds) + ' ago';
}
function duration(seconds) {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`;
  return `${Math.floor(seconds / 86400)}d`;
}
export const fmt = (value) => (value ? toDate(value).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : '—');
export const fmtDate = (value) => (value ? toDate(value).toLocaleDateString(undefined, { dateStyle: 'medium' }) : '—');
const ACRONYMS = new Set(['mttr', 'kev', 'cvss', 'epss', 'api', 'url', 'id', 'aws', 'gcp', 'iam', 's3', 'k8s', 'tls', 'sso', 'totp', 'dns', 'ip', 'ci', 'soc2']);
export const nice = (text) => String(text ?? '').replace(/[-_.]+/g, ' ').replace(/^\w+/, (m) => (ACRONYMS.has(m.toLowerCase()) ? m.toUpperCase() : m[0].toUpperCase() + m.slice(1)));
export const num = (value) => (value === null || value === undefined || value === '' ? '—' : Number(value).toLocaleString());
export const short = (id) => (id ? String(id).slice(0, 8) : '—');
export const time = (value) => `<time datetime="${esc(value || '')}" title="${esc(fmt(value))}">${esc(ago(value))}</time>`;
export const ms = (value) => (value === null || value === undefined ? '—' : value < 1000 ? `${value} ms` : `${(value / 1000).toFixed(1)} s`);

// ---------------------------------------------------------------- chips

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'informational'];
export const SEVERITY_ORDER = SEVERITIES;
export const sev = (s) => (s ? `<span class="severity-pill severity-${esc(s)}">${esc(s)}</span>` : '<span class="subtle">—</span>');
export const tag = (s) => (s === null || s === undefined || s === '' ? '<span class="subtle">—</span>' : `<span class="state-tag ${esc(String(s).replace(/\s+/g, '-'))}">${esc(nice(s))}</span>`);
export const pill = (text, title = '') => `<span class="pill" title="${esc(title)}">${esc(text)}</span>`;
export const risk = (r) => `<span class="risk-chip risk-${esc(r)}">${esc(r)} risk</span>`;
export const yesno = (value, yes = 'yes', no = 'no') => (value ? `<span class="state-tag approved">${esc(yes)}</span>` : `<span class="state-tag">${esc(no)}</span>`);
export const mono = (text) => `<span class="mono">${esc(text)}</span>`;
export const link = (href, text, cls = '') => `<a href="${esc(href)}" class="${esc(cls)}">${esc(text)}</a>`;

// ---------------------------------------------------------------- layout blocks

export const heading = (over, title, description = '', actions = '') =>
  `<div class="page-heading"><div><div class="overline">${esc(over)}</div><h1>${esc(title)}</h1>${description ? `<p>${esc(description)}</p>` : ''}</div>${actions ? `<div class="footer-toolbar">${actions}</div>` : ''}</div>`;

export const section = (title, sub = '', actions = '') =>
  `<div class="section-heading"><div><h2>${esc(title)}</h2>${sub ? `<p>${esc(sub)}</p>` : ''}</div>${actions ? `<div class="inline-actions">${actions}</div>` : ''}</div>`;

export const panel = ({ title = '', sub = '', actions = '', body = '', cls = '', flush = false }) =>
  `<section class="panel ${esc(cls)}">${title || actions ? `<div class="panel-head"><div><h2>${esc(title)}</h2>${sub ? `<small>${esc(sub)}</small>` : ''}</div>${actions ? `<div class="inline-actions">${actions}</div>` : ''}</div>` : ''}<div class="${flush ? 'panel-flush' : 'panel-body'}">${body}</div></section>`;

export const metrics = (items) =>
  `<div class="metric-grid">${items.map((m) => `<div class="metric-card"><div class="metric-top"><span>${esc(m.label)}</span>${m.extra || ''}</div><div class="metric-value">${typeof m.value === 'string' ? m.value : num(m.value)}</div><div class="metric-caption">${esc(m.caption || '')}</div></div>`).join('')}</div>`;

export const empty = (title, sub = '') => `<div class="empty"><strong>${esc(title)}</strong>${esc(sub)}</div>`;
export const loading = (text = 'Loading…') => `<div class="loading">${esc(text)}</div>`;
export const errorBox = (err, retry = true) =>
  `<div class="error-box"><strong>Could not load</strong><span>${esc(err?.message || err || 'Unknown error')}${err?.code ? ` <span class="mono">(${esc(err.code)})</span>` : ''}</span>${retry ? '<button class="btn small" data-act="retry">Retry</button>' : ''}</div>`;
export const note = (text, kind = '') => `<div class="callout ${esc(kind)}">${text}</div>`;

export const kv = (pairs) =>
  `<dl class="kv">${pairs.filter(Boolean).map(([k, v]) => `<div><dt>${esc(k)}</dt><dd>${v === undefined || v === null || v === '' ? '<span class="subtle">—</span>' : v}</dd></div>`).join('')}</dl>`;

export const json = (value, max = 20000) => {
  let text;
  try { text = typeof value === 'string' ? value : JSON.stringify(value ?? null, null, 2); } catch { text = String(value); }
  if (text.length > max) text = text.slice(0, max) + '\n… truncated';
  return `<pre class="code-block">${esc(text)}</pre>`;
};

export const tabs = (items, active) =>
  `<div class="tabs" role="tablist">${items.map((t) => `<button role="tab" class="tab ${t.id === active ? 'active' : ''}" data-tab="${esc(t.id)}" aria-selected="${t.id === active}">${esc(t.label)}${t.count !== undefined ? `<span class="nav-count">${esc(num(t.count))}</span>` : ''}</button>`).join('')}</div>`;

/** columns: [{label, key?, render?(row), cls?, mono?}]. rows: array. rowAttr(row) -> extra attribute string. */
export function table({ columns, rows, empty: emptyText = 'Nothing here yet', emptySub = '', rowAttr = () => '', cls = '' }) {
  const head = columns.map((c) => `<th class="${esc(c.cls || '')}">${esc(c.label)}</th>`).join('');
  const body = rows.length
    ? rows.map((row) => `<tr ${rowAttr(row)}>${columns.map((c) => {
      const value = c.render ? c.render(row) : esc(row[c.key] ?? '');
      return `<td class="${esc(c.cls || '')}${c.mono ? ' mono' : ''}">${value}</td>`;
    }).join('')}</tr>`).join('')
    : `<tr><td colspan="${columns.length}">${empty(emptyText, emptySub)}</td></tr>`;
  return `<div class="table-wrap"><table class="data-table ${esc(cls)}"><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table></div>`;
}

/** Cursor pagination. state = {cursor, next_cursor, history: []}. Emits data-act="page-prev" / "page-next". */
export const pager = (state, count = null) =>
  `<div class="pager"><span class="subtle">${count === null ? '' : `${count} row${count === 1 ? '' : 's'} on this page`}</span><div class="inline-actions"><button class="btn small" data-act="page-prev" ${state.history.length ? '' : 'disabled'}>Previous</button><button class="btn small" data-act="page-next" ${state.next_cursor ? '' : 'disabled'}>Next</button></div></div>`;
export const newPager = () => ({ cursor: '', next_cursor: null, history: [] });
export function pagePrev(state) { state.cursor = state.history.pop() || ''; }
export function pageNext(state) { state.history.push(state.cursor); state.cursor = state.next_cursor; }
export function pageReset(state) { state.cursor = ''; state.history = []; state.next_cursor = null; }

// ---------------------------------------------------------------- forms

const inputName = (f) => (f.group ? `${f.group}.${f.name}` : f.name);

/** field: {name, label, type, value, options, required, hint, placeholder, min, max, rows, group, disabled} */
export function fields(defs, values = {}) {
  return defs.map((f) => {
    const value = f.value !== undefined ? f.value : values[f.name];
    const name = inputName(f);
    const id = `f-${name.replace(/[^a-z0-9_-]/gi, '_')}`;
    const common = `name="${esc(name)}" id="${id}" ${f.required ? 'required' : ''} ${f.disabled ? 'disabled' : ''} data-type="${esc(f.type || 'text')}"`;
    let control;
    switch (f.type) {
      case 'textarea':
      case 'json':
        control = `<textarea class="field-input" rows="${f.rows || (f.type === 'json' ? 6 : 3)}" placeholder="${esc(f.placeholder || (f.type === 'json' ? '{}' : ''))}" ${common}>${esc(f.type === 'json' && typeof value !== 'string' && value !== undefined ? JSON.stringify(value, null, 2) : value ?? '')}</textarea>`;
        break;
      case 'select':
        control = `<select class="select full" ${common}>${(f.options || []).map((o) => {
          const opt = typeof o === 'string' ? { value: o, label: nice(o) } : o;
          return `<option value="${esc(opt.value)}" ${String(opt.value) === String(value ?? '') ? 'selected' : ''}>${esc(opt.label)}</option>`;
        }).join('')}</select>`;
        break;
      case 'checkbox':
        control = `<label class="check"><input type="checkbox" ${common} ${value ? 'checked' : ''}> <span>${esc(f.text || f.label)}</span></label>`;
        break;
      case 'multiselect':
        control = `<div class="check-group" data-multiselect="${esc(name)}">${(f.options || []).map((o) => {
          const opt = typeof o === 'string' ? { value: o, label: nice(o) } : o;
          return `<label class="check"><input type="checkbox" name="${esc(name)}" value="${esc(opt.value)}" ${(value || []).includes(opt.value) ? 'checked' : ''}> <span>${esc(opt.label)}</span></label>`;
        }).join('')}</div>`;
        break;
      case 'number':
        control = `<input type="number" class="field-input" ${common} value="${esc(value ?? '')}" ${f.min !== undefined ? `min="${f.min}"` : ''} ${f.max !== undefined ? `max="${f.max}"` : ''} ${f.step !== undefined ? `step="${f.step}"` : ''} placeholder="${esc(f.placeholder || '')}">`;
        break;
      case 'tags':
        control = `<input type="text" class="field-input" ${common} value="${esc(Array.isArray(value) ? value.join(', ') : value ?? '')}" placeholder="${esc(f.placeholder || 'comma, separated')}">`;
        break;
      default:
        control = `<input type="${esc(f.type || 'text')}" class="field-input" ${common} value="${esc(value ?? '')}" placeholder="${esc(f.placeholder || '')}" ${f.minlength ? `minlength="${f.minlength}"` : ''} ${f.maxlength ? `maxlength="${f.maxlength}"` : ''} ${f.autocomplete ? `autocomplete="${esc(f.autocomplete)}"` : ''} ${f.pattern ? `pattern="${esc(f.pattern)}"` : ''}>`;
    }
    if (f.type === 'checkbox') return `<div class="field">${control}${f.hint ? `<p class="form-hint">${esc(f.hint)}</p>` : ''}</div>`;
    return `<div class="field"><label class="field-label" for="${id}">${esc(f.label)}${f.required ? ' <span class="req">*</span>' : ''}</label>${control}${f.hint ? `<p class="form-hint">${esc(f.hint)}</p>` : ''}</div>`;
  }).join('');
}

export const formActions = (submit = 'Save', cancel = 'Cancel', extra = '') =>
  `<div class="form-error" data-form-error></div><div class="form-actions">${extra}${cancel ? `<button type="button" class="btn subtle" data-act="close">${esc(cancel)}</button>` : ''}<button type="submit" class="btn primary">${esc(submit)}</button></div>`;

/** Read typed values back out of a form built with fields(). Throws Error for invalid JSON. */
export function readFields(form, defs) {
  const out = {};
  for (const f of defs) {
    const target = f.group ? (out[f.group] = out[f.group] || {}) : out;
    let value;
    if (f.type === 'multiselect') {
      value = $$(`[data-multiselect="${CSS.escape(inputName(f))}"] input:checked`, form).map((i) => i.value);
    } else {
      const input = form.elements[inputName(f)];
      if (!input) continue;
      if (f.type === 'checkbox') value = input.checked;
      else if (f.type === 'number') value = input.value === '' ? null : Number(input.value);
      else if (f.type === 'tags') value = input.value.split(',').map((s) => s.trim()).filter(Boolean);
      else if (f.type === 'json') {
        const text = input.value.trim();
        if (!text) value = f.emptyValue !== undefined ? f.emptyValue : {};
        else { try { value = JSON.parse(text); } catch { throw new Error(`${f.label} must be valid JSON`); } }
      } else value = input.value;
    }
    if (f.omitEmpty && (value === '' || value === null || (Array.isArray(value) && !value.length))) continue;
    target[f.name] = value;
  }
  return out;
}

/** Build field definitions from a JSON-schema subset (type, properties, required, enum, description, default, format). */
export function schemaFields(schema, values = {}, { secretFields = [], secretRefs = {}, group } = {}) {
  const props = schema?.properties || {};
  const required = new Set(schema?.required || []);
  const defs = [];
  for (const [name, sub] of Object.entries(props)) {
    if (secretFields.includes(name)) continue;
    const base = { name, label: nice(name), required: required.has(name), hint: sub.description || '', value: values[name] ?? sub.default, group };
    if (sub.enum) defs.push({ ...base, type: 'select', options: (required.has(name) ? [] : [{ value: '', label: '—' }]).concat(sub.enum.map((v) => ({ value: v, label: String(v) }))) });
    else if (sub.type === 'boolean') defs.push({ ...base, type: 'checkbox' });
    else if (sub.type === 'integer' || sub.type === 'number') defs.push({ ...base, type: 'number', min: sub.minimum, max: sub.maximum, step: sub.type === 'integer' ? 1 : 'any', omitEmpty: true });
    else if (sub.type === 'array' && (!sub.items || sub.items.type === 'string')) defs.push({ ...base, type: 'tags', omitEmpty: !required.has(name) });
    else if (sub.type === 'array' || sub.type === 'object') defs.push({ ...base, type: 'json', emptyValue: sub.type === 'array' ? [] : {}, omitEmpty: !required.has(name) });
    else defs.push({ ...base, type: 'text', placeholder: sub.format === 'uri' ? 'https://' : sub.format === 'email' ? 'name@example.com' : sub.pattern || '', omitEmpty: !required.has(name) });
  }
  for (const name of secretFields) {
    defs.push({ name, label: `${nice(name)} (secret reference)`, type: 'text', value: secretRefs[name] ?? '', group: 'secret_refs', placeholder: `env:${name.toUpperCase()}`,
      hint: 'Reference only, never the value: env:NAME, file:/path or secrets:KEY. The server resolves it at run time.', omitEmpty: true });
  }
  return defs;
}

/** Wire a form: disables the submit button while the handler runs and prints errors inline. */
export function onSubmit(form, handler) {
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const button = $('button[type=submit]', form);
    const errorLine = $('[data-form-error]', form);
    if (errorLine) errorLine.textContent = '';
    if (button) button.disabled = true;
    try {
      await handler(form);
    } catch (err) {
      if (errorLine) errorLine.textContent = err?.message || String(err);
    } finally {
      if (button) button.disabled = false;
    }
  });
}

// ---------------------------------------------------------------- events

/** Delegated click handling for [data-act] inside root; handler(el, event). change handlers for [data-change]. */
export function bind(root, actions = {}, changes = {}) {
  root.addEventListener('click', (event) => {
    const target = event.target.closest('[data-act]');
    if (!target || !root.contains(target)) return;
    const handler = actions[target.dataset.act];
    if (!handler) return;
    event.preventDefault();
    Promise.resolve(handler(target, event)).catch((err) => { if (!err?.status) toast(err?.message || String(err), 'error'); });
  });
  root.addEventListener('change', (event) => {
    const target = event.target.closest('[data-change]');
    if (!target || !root.contains(target)) return;
    const handler = changes[target.dataset.change];
    if (handler) Promise.resolve(handler(target, event)).catch((err) => toast(err?.message || String(err), 'error'));
  });
  root.addEventListener('keydown', (event) => {
    if (event.key !== 'Enter') return;
    const target = event.target.closest('[data-enter]');
    if (!target || !root.contains(target)) return;
    const handler = changes[target.dataset.enter];
    if (handler) { event.preventDefault(); Promise.resolve(handler(target, event)).catch((err) => toast(err?.message || String(err), 'error')); }
  });
}

export function debounce(fn, wait = 250) {
  let timer;
  return (...args) => { clearTimeout(timer); timer = setTimeout(() => fn(...args), wait); };
}

// ---------------------------------------------------------------- overlays

export function toast(message, kind = 'info', ttl = 4800) {
  const area = $('#toast-area');
  if (!area) return;
  const node = el(`<div class="toast ${kind === 'error' ? 'error' : ''}" role="status"></div>`);
  node.textContent = message;
  area.append(node);
  setTimeout(() => node.remove(), ttl);
}

export async function copy(text, label = 'Copied to clipboard') {
  try { await navigator.clipboard.writeText(text); toast(label); } catch { toast('Clipboard unavailable; select and copy manually', 'error'); }
}

function openOverlay(id, title, html, cls = '') {
  const backdrop = $(`#${id}`);
  const panelNode = $('.overlay-panel', backdrop);
  panelNode.className = `overlay-panel ${cls}`;
  $('h2', backdrop).textContent = title;
  const body = $('.overlay-body', backdrop);
  body.innerHTML = html;
  backdrop.classList.remove('hidden');
  body.scrollTop = 0;
  const first = $('input:not([type=hidden]), select, textarea, button:not(.close-btn)', body);
  if (first) setTimeout(() => first.focus(), 30);
  return body;
}
export const drawer = (title, html, { wide = false } = {}) => openOverlay('drawer', title, html, wide ? 'wide' : '');
export const modal = (title, html, { wide = false } = {}) => openOverlay('modal', title, html, wide ? 'wide' : '');
export function closeDrawer() { $('#drawer').classList.add('hidden'); $('#drawer .overlay-body').innerHTML = ''; document.dispatchEvent(new CustomEvent('drawer:closed')); }
export function closeModal() { $('#modal').classList.add('hidden'); $('#modal .overlay-body').innerHTML = ''; }
export const drawerOpen = () => !$('#drawer').classList.contains('hidden');
export function setDrawerTitle(title) { $('#drawer h2').textContent = title; }

export function confirm(message, { title = 'Please confirm', label = 'Confirm', danger = false, comment = null } = {}) {
  return new Promise((resolve) => {
    const body = modal(title, `<p class="info-line">${esc(message)}</p>${comment !== null ? `<div class="field"><label class="field-label">${esc(comment)}</label><textarea class="field-input" rows="3" data-comment></textarea></div>` : ''}<div class="form-actions"><button class="btn subtle" data-act="no">Cancel</button><button class="btn ${danger ? 'negative' : 'primary'}" data-act="yes">${esc(label)}</button></div>`);
    const finish = (value) => { closeModal(); resolve(value); };
    $('[data-act=no]', body).addEventListener('click', () => finish(false));
    $('[data-act=yes]', body).addEventListener('click', () => finish(comment !== null ? { ok: true, comment: $('[data-comment]', body).value } : true));
    $('#modal').addEventListener('overlay:dismiss', () => finish(false), { once: true });
  });
}

// ---------------------------------------------------------------- tiny charts (inline SVG, single series, text-colored)

export function sparkline(values, { width = 160, height = 32, label = '' } = {}) {
  const data = values.map((v) => Number(v) || 0);
  if (!data.length) return `<svg class="spark" width="${width}" height="${height}" role="img" aria-label="no data"></svg>`;
  const max = Math.max(...data, 1);
  const min = Math.min(...data, 0);
  const span = max - min || 1;
  const step = data.length > 1 ? (width - 4) / (data.length - 1) : 0;
  const points = data.map((v, i) => [2 + i * step, height - 3 - ((v - min) / span) * (height - 6)]);
  const path = points.map(([x, y], i) => `${i ? 'L' : 'M'}${x.toFixed(1)} ${y.toFixed(1)}`).join(' ');
  const last = points[points.length - 1];
  const hits = points.map(([x, y], i) => `<rect x="${(x - step / 2).toFixed(1)}" y="0" width="${Math.max(step, 4).toFixed(1)}" height="${height}" fill="transparent"><title>${esc(label ? `${label}: ` : '')}${esc(num(data[i]))}</title></rect>`).join('');
  return `<svg class="spark" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" role="img" aria-label="${esc(label)} ${esc(data.join(', '))}"><path d="${path}" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round" stroke-linecap="round"/><circle cx="${last[0].toFixed(1)}" cy="${last[1].toFixed(1)}" r="2.5" fill="currentColor"/>${hits}</svg>`;
}

/** Horizontal segmented bar using the severity tokens, plus a text legend. counts: {critical: n, ...} */
export function severityBar(counts, order = SEVERITIES) {
  const total = order.reduce((sum, key) => sum + (counts?.[key] || 0), 0);
  const bars = total
    ? order.map((key) => `<span class="risk-segment" style="width:${((counts[key] || 0) / total) * 100}%;background:var(--sev-${key})" title="${esc(nice(key))}: ${counts[key] || 0}"></span>`).join('')
    : '<span class="risk-segment" style="width:100%;background:var(--track)"></span>';
  const legend = order.map((key) => `<span class="risk-item"><i class="dot" style="background:var(--sev-${key})"></i>${esc(nice(key))} <strong>${counts?.[key] || 0}</strong></span>`).join('');
  return `<div class="risk-track">${bars}</div><div class="risk-legend">${legend}</div>`;
}

/** Score meter 0..100 drawn as a hairline track. */
export const meter = (value, max = 100) => `<div class="meter"><span style="width:${Math.max(0, Math.min(100, (Number(value) / max) * 100))}%"></span></div>`;

export function selectHtml(name, options, value, { allLabel = 'All', cls = '', attrs = '' } = {}) {
  return `<select class="select ${esc(cls)}" name="${esc(name)}" ${attrs}>${allLabel !== null ? `<option value="">${esc(allLabel)}</option>` : ''}${options.map((o) => {
    const opt = typeof o === 'string' ? { value: o, label: nice(o) } : o;
    return `<option value="${esc(opt.value)}" ${String(opt.value) === String(value ?? '') ? 'selected' : ''}>${esc(opt.label)}</option>`;
  }).join('')}</select>`;
}
