import { get } from '../api.js';
import { assetMap, assetName, section, readFilters, setQuery } from '../common.js';
import { $, bind, drawer, esc, heading, json, kv, metrics, newPager, pageNext, pagePrev, pageReset, pager, selectHtml, sev, table, time, mono, link, debounce, fmt, num, SEVERITY_ORDER, setDrawerTitle } from '../ui.js';

const SINCE = [{ value: '', label: 'All time' }, { value: '1h', label: 'Last hour' }, { value: '24h', label: 'Last 24 hours' }, { value: '7d', label: 'Last 7 days' }, { value: '30d', label: 'Last 30 days' }];

export async function openEvent(id) {
  const body = drawer('Event', '<div class="loading">Loading…</div>');
  let e;
  try { e = await get(`/events/${id}`, null, { silent: true }); } catch (err) { body.innerHTML = `<div class="error-box"><strong>Could not load</strong><span>${esc(err.message)}</span></div>`; return; }
  const assets = await assetMap().catch(() => new Map());
  setDrawerTitle(`Event ${e.id.slice(0, 8)}`);
  body.innerHTML = `<div class="chip-row">${sev(e.severity)}<span class="pill">${esc(e.source)}</span>${e.category ? `<span class="pill">${esc(e.category)}</span>` : ''}</div><h3 class="detail-title">${esc(e.title)}</h3>
    ${kv([['Actor', mono(e.actor)], ['Entity', mono(e.entity)], ['Action', mono(e.action)], ['Asset', e.asset_id ? link(`#/assets/${e.asset_id}`, assetName(assets, e.asset_id)) : ''], ['External id', mono(e.external_id)], ['Occurred', esc(fmt(e.occurred_at))], ['Received', esc(fmt(e.received_at))]])}
    <h3>Metadata</h3>${json(e.metadata)}
    ${(e.related_by_actor || []).length ? `<h3>Same actor, recent</h3><div class="stat-list">${e.related_by_actor.map((r) => `<div class="stat-item"><span><a href="#/events/${esc(r.id)}">${esc(r.title)}</a> <span class="subtle">${esc(r.source)}</span></span><strong>${time(r.received_at)}</strong></div>`).join('')}</div>` : ''}`;
}

export default {
  async render({ root, params, query, navigate }) {
    const state = newPager();
    root.innerHTML = `${heading('Security telemetry', 'Events', 'Normalized events from ingest, collectors and canaries. Raw logs are not stored here.')}
      <div data-stats></div>
      <div class="toolbar"><div class="tool-filters" data-filters>
        <input class="field-input" name="search" placeholder="Search title, actor, entity, action" value="${esc(query.search || '')}" data-enter="apply">
        ${selectHtml('since', SINCE, query.since === undefined ? '7d' : query.since, { allLabel: null, attrs: 'data-change="apply"' })}
        ${selectHtml('severity', SEVERITY_ORDER, query.severity, { allLabel: 'Any severity', attrs: 'data-change="apply"' })}
        <input class="field-input" name="source" placeholder="Source" value="${esc(query.source || '')}" style="min-width:110px" data-enter="apply">
        <input class="field-input" name="category" placeholder="Category" value="${esc(query.category || '')}" style="min-width:110px" data-enter="apply">
        <input class="field-input" name="actor" placeholder="Actor (exact)" value="${esc(query.actor || '')}" style="min-width:140px" data-enter="apply">
      </div><span class="muted" data-count></span></div>
      <div class="panel" data-list></div>`;
    const filters = () => readFilters($('[data-filters]', root));
    section($('[data-stats]', root), () => get('/events/stats'), (s) => metrics([
      { label: 'Events (24h)', value: s['24h']?.total ?? 0, caption: `${num(s.total)} retained in total` },
      { label: 'Events (7d)', value: s['7d']?.total ?? 0, caption: `${s['7d']?.by_severity?.critical || 0} critical · ${s['7d']?.by_severity?.high || 0} high` },
      { label: 'Sources (7d)', value: Object.keys(s['7d']?.by_source || {}).length, caption: Object.entries(s['7d']?.by_source || {}).slice(0, 3).map(([k, v]) => `${k} ${v}`).join(' · ') || 'none' },
      { label: 'Top actor (7d)', value: `<span style="font-size:16px" class="mono">${esc(s.top_actors?.[0]?.value?.slice(0, 28) || '—')}</span>`, caption: s.top_actors?.[0] ? `${s.top_actors[0].count} events` : 'no actor data' },
    ]));
    const list = section($('[data-list]', root), async () => {
      const [data, assets] = await Promise.all([get('/events', { ...filters(), limit: 50, cursor: state.cursor }), assetMap().catch(() => new Map())]);
      return { data, assets };
    }, ({ data, assets }) => {
      state.next_cursor = data.next_cursor;
      $('[data-count]', root).textContent = `${data.items.length}${data.next_cursor ? '+' : ''} events`;
      return table({
        columns: [
          { label: 'Event', render: (e) => `<span class="cell-main limit-lines" style="max-width:420px">${esc(e.title)}</span><span class="cell-sub">${esc(e.source)}${e.category ? ` · ${esc(e.category)}` : ''}${e.asset_id ? ` · ${esc(assetName(assets, e.asset_id))}` : ''}</span>` },
          { label: 'Severity', render: (e) => sev(e.severity) },
          { label: 'Actor', render: (e) => `<span class="mono truncate" style="max-width:220px" title="${esc(e.actor)}">${esc(e.actor || '—')}</span>` },
          { label: 'Action', render: (e) => mono(e.action || '—') },
          { label: 'Received', render: (e) => time(e.received_at) },
        ],
        rows: data.items, rowAttr: (e) => `data-act="open" data-id="${esc(e.id)}"`, empty: 'No events in this window', emptySub: 'Widen the time range or connect a source under Integrations.',
      }) + pager(state, data.items.length);
    });
    const apply = () => { pageReset(state); setQuery(navigate, 'events', [], filters()); list.reload(); };
    bind(root, {
      open: (el) => { history.replaceState(null, '', `#/events/${el.dataset.id}`); openEvent(el.dataset.id); },
      'page-next': () => { pageNext(state); list.reload(); },
      'page-prev': () => { pagePrev(state); list.reload(); },
    }, { apply });
    $('input[name=search]', root).addEventListener('input', debounce(apply, 350));
    if (params[0]) openEvent(params[0]);
    const onClosed = () => { if (location.hash.startsWith('#/events/')) history.replaceState(null, '', '#/events'); };
    document.addEventListener('drawer:closed', onClosed);
    return () => document.removeEventListener('drawer:closed', onClosed);
  },
};
