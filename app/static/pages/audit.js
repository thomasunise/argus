import { get, download } from '../api.js';
import { store } from '../store.js';
import { section, readFilters, setQuery } from '../common.js';
import { $, bind, drawer, esc, heading, json, kv, metrics, newPager, pageNext, pagePrev, pageReset, pager, selectHtml, table, time, toast, mono, debounce, fmt } from '../ui.js';

const SINCE = [{ value: '', label: 'All time' }, { value: '1h', label: 'Last hour' }, { value: '24h', label: 'Last 24 hours' }, { value: '7d', label: 'Last 7 days' }, { value: '30d', label: 'Last 30 days' }];

export default {
  async render({ root, query, navigate }) {
    const state = newPager();
    const actions = await get('/audit/actions').catch(() => ({ items: [] }));
    root.innerHTML = `${heading('Governance', 'Audit log', 'Append-only, hash-chained record of every state change. Verify the chain here; anchor exports externally for tamper-proof retention.',
      `<button class="btn" data-act="verify">Verify chain</button>${store.roleAtLeast('admin') ? '<button class="btn" data-act="export">Export JSONL</button>' : ''}`)}
      <div data-verify></div>
      <div class="toolbar"><div class="tool-filters" data-filters>
        <input class="field-input" name="search" placeholder="Search detail" value="${esc(query.search || '')}" data-enter="apply">
        ${selectHtml('action', actions.items.map((a) => ({ value: a.action, label: `${a.action} (${a.count})` })), query.action, { allLabel: 'All actions', attrs: 'data-change="apply"' })}
        ${selectHtml('since', SINCE, query.since === undefined ? '' : query.since, { allLabel: null, attrs: 'data-change="apply"' })}
        <input class="field-input" name="actor" placeholder="Actor (exact)" value="${esc(query.actor || '')}" style="min-width:160px" data-enter="apply">
        <input class="field-input" name="subject" placeholder="Subject id" value="${esc(query.subject || '')}" style="min-width:140px" data-enter="apply">
      </div><span class="muted" data-count></span></div>
      <div class="panel" data-list></div>`;
    const filters = () => readFilters($('[data-filters]', root));
    const verifyNode = $('[data-verify]', root);
    const verify = section(verifyNode, () => get('/audit/verify'), (v) => metrics([
      { label: 'Chain', value: `<span class="${v.valid ? 'ok-text' : 'bad-text'}" style="font-size:20px">${v.valid ? 'valid' : 'broken'}</span>`, caption: v.valid ? 'every entry hash links to its predecessor' : `broken at ${v.broken_at || '?'}${v.reason ? ` (${v.reason})` : ''}` },
      { label: 'Entries checked', value: v.checked, caption: 'in this tenant' },
      { label: 'Signatures', value: `<span style="font-size:20px">${v.signed ? 'HMAC' : 'none'}</span>`, caption: v.signed ? 'AUDIT_SIGNING_KEY configured' : 'set AUDIT_SIGNING_KEY to sign entries' },
      { label: 'Distinct actions', value: actions.items.length, caption: 'action names recorded' },
    ]));
    const list = section($('[data-list]', root), () => get('/audit', { ...filters(), limit: 50, cursor: state.cursor }), (data) => {
      state.next_cursor = data.next_cursor;
      $('[data-count]', root).textContent = `${data.items.length}${data.next_cursor ? '+' : ''} entries`;
      return table({ columns: [
        { label: 'Action', render: (e) => `<span class="cell-main">${esc(e.action)}</span><span class="cell-sub">${esc(e.actor_kind)} · ${esc(e.id.slice ? e.id.slice(0, 8) : e.id)}</span>` }, { label: 'Actor', render: (e) => `<span class="mono truncate" style="max-width:220px" title="${esc(e.actor)}">${esc(e.actor)}</span>` },
        { label: 'Subject', render: (e) => mono(e.subject ? String(e.subject).slice(0, 12) : '—') }, { label: 'Detail', cls: 'wrap', render: (e) => `<span class="limit-lines subtle" style="max-width:360px">${esc(summarize(e.detail))}</span>` },
        { label: 'Signed', render: (e) => (e.signed ? 'yes' : 'no') }, { label: 'When', render: (e) => time(e.created_at) }],
      rows: data.items, rowAttr: (e) => `data-act="open" data-id="${esc(e.id)}"`, empty: 'No audit entries match' }) + pager(state, data.items.length);
    });
    const apply = () => { pageReset(state); setQuery(navigate, 'audit', [], filters()); list.reload(); };
    bind(root, {
      verify: async () => { await verify.reload(); const v = await get('/audit/verify'); toast(v.valid ? `Audit chain verified (${v.checked} entries)` : `Audit chain broken at ${v.broken_at}`, v.valid ? 'info' : 'error'); },
      export: async () => { await download('/audit/export.jsonl', 'argus-audit.jsonl', filters()); toast('Export downloaded (audited)'); },
      open: async (el) => {
        const data = await get('/audit', { ...filters(), limit: 50, cursor: state.cursor });
        const e = data.items.find((x) => String(x.id) === el.dataset.id);
        if (!e) return;
        drawer(e.action, `${kv([['Actor', `${mono(e.actor)} <span class="subtle">${esc(e.actor_kind)}</span>`], ['Subject', mono(e.subject || '—')], ['When', esc(fmt(e.created_at))], ['Request id', mono(e.request_id || '—')], ['Signed', e.signed ? 'yes' : 'no'], ['Entry hash', mono(e.entry_hash)], ['Previous hash', mono(e.previous_hash)]])}<h3>Detail</h3>${json(e.detail)}`);
      },
      'page-next': () => { pageNext(state); list.reload(); },
      'page-prev': () => { pagePrev(state); list.reload(); },
    }, { apply });
    $('input[name=search]', root).addEventListener('input', debounce(apply, 350));
  },
};

function summarize(detail) {
  if (!detail || typeof detail !== 'object') return detail ? String(detail) : '';
  return Object.entries(detail).slice(0, 4).map(([k, v]) => `${k}: ${typeof v === 'object' ? JSON.stringify(v) : v}`).join(' · ');
}
