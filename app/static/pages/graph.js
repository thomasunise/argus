import { get, post, patch } from '../api.js';
import { store } from '../store.js';
import { section, readFilters, setQuery, trackJob } from '../common.js';
import { $, bind, confirm, drawer, empty, esc, heading, json, kv, metrics, newPager, pageNext, pagePrev, pageReset, pager, panel, selectHtml, table, tabs, tag, time, toast, mono, nice, link, debounce, fmt, num } from '../ui.js';

const PATH_STATUSES = ['open', 'accepted', 'resolved'];
const label = (n) => n.label || n.key || n.id.slice(0, 8);

/** Radial layout: the focus node at the centre, direct neighbours on ring 1, the rest on ring 2 near their parent. */
function radialSvg(center, nodes, edges) {
  const width = 900, height = 520, cx = width / 2, cy = height / 2;
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const adjacent = new Map();
  for (const e of edges) {
    if (!adjacent.has(e.src_id)) adjacent.set(e.src_id, new Set());
    if (!adjacent.has(e.dst_id)) adjacent.set(e.dst_id, new Set());
    adjacent.get(e.src_id).add(e.dst_id);
    adjacent.get(e.dst_id).add(e.src_id);
  }
  const depth = new Map([[center, 0]]);
  const parent = new Map();
  const queue = [center];
  while (queue.length) {
    const id = queue.shift();
    for (const next of adjacent.get(id) || []) if (!depth.has(next)) { depth.set(next, depth.get(id) + 1); parent.set(next, id); queue.push(next); }
  }
  for (const n of nodes) if (!depth.has(n.id)) depth.set(n.id, 3);
  const ring1 = nodes.filter((n) => depth.get(n.id) === 1);
  const outer = nodes.filter((n) => depth.get(n.id) >= 2);
  const pos = new Map([[center, [cx, cy]]]);
  const r1 = Math.min(width, height) * 0.26, r2 = Math.min(width, height) * 0.44;
  ring1.forEach((n, i) => { const a = (i / Math.max(ring1.length, 1)) * Math.PI * 2 - Math.PI / 2; pos.set(n.id, [cx + r1 * Math.cos(a), cy + r1 * Math.sin(a)]); });
  const groups = new Map();
  for (const n of outer) { const p = parent.get(n.id); if (!groups.has(p)) groups.set(p, []); groups.get(p).push(n); }
  const placed = [];
  for (const [p, children] of groups) {
    const [px, py] = pos.get(p) || [cx, cy];
    const base = Math.atan2(py - cy, px - cx) || 0;
    const spread = Math.min(Math.PI / 2, children.length * 0.22);
    children.forEach((n, i) => {
      const a = base + (children.length === 1 ? 0 : -spread / 2 + (i / (children.length - 1)) * spread);
      pos.set(n.id, [cx + r2 * Math.cos(a), cy + r2 * Math.sin(a)]);
      placed.push(n);
    });
  }
  const edgeHtml = edges.filter((e) => pos.has(e.src_id) && pos.has(e.dst_id)).map((e) => {
    const [x1, y1] = pos.get(e.src_id), [x2, y2] = pos.get(e.dst_id);
    const labelIt = e.src_id === center || e.dst_id === center;
    return `<line class="edge" x1="${x1.toFixed(1)}" y1="${y1.toFixed(1)}" x2="${x2.toFixed(1)}" y2="${y2.toFixed(1)}"><title>${esc(e.rel)}</title></line>${labelIt ? `<text class="edge-label" x="${((x1 + x2) / 2).toFixed(1)}" y="${((y1 + y2) / 2 - 3).toFixed(1)}" text-anchor="middle">${esc(e.rel)}</text>` : ''}`;
  }).join('');
  const nodeHtml = nodes.filter((n) => pos.has(n.id)).map((n) => {
    const [x, y] = pos.get(n.id);
    const isCenter = n.id === center;
    const text = label(n).length > 26 ? `${label(n).slice(0, 25)}…` : label(n);
    return `<g class="node ${isCenter ? 'center' : ''} ${(n.exposure_score || 0) >= 50 ? 'exposed' : ''}" data-act="node" data-id="${esc(n.id)}" transform="translate(${x.toFixed(1)},${y.toFixed(1)})"><circle r="${isCenter ? 9 : 6}"><title>${esc(n.kind)} · ${esc(label(n))}${n.exposure_score ? ` · exposure ${n.exposure_score}` : ''}</title></circle><text y="${isCenter ? 22 : 18}" text-anchor="middle">${esc(text)}</text><text y="${isCenter ? 33 : 29}" text-anchor="middle" class="edge-label">${esc(n.kind)}</text></g>`;
  }).join('');
  return `<svg class="graph-svg" viewBox="0 0 ${width} ${height}" role="img" aria-label="Neighbourhood of ${esc(label(byId.get(center) || { id: center }))}">${edgeHtml}${nodeHtml}</svg>`;
}

async function renderNode({ root, params, query, navigate }) {
  const id = params[1];
  const depth = Number(query.depth) || 1;
  root.innerHTML = `<p><a href="#/graph" class="ghost-link">← Graph</a></p><div data-node></div>`;
  const view = section($('[data-node]', root), async () => {
    const [node, hood] = await Promise.all([get(`/graph/nodes/${id}`), get(`/graph/nodes/${id}/neighbors`, { depth, limit: 400 })]);
    return { node, hood };
  }, ({ node, hood }) => {
    const nodes = hood.nodes.some((n) => n.id === node.id) ? hood.nodes : [node, ...hood.nodes];
    const others = nodes.filter((n) => n.id !== node.id);
    return `${heading(node.kind, label(node), node.key, `${selectHtml('depth', [{ value: 1, label: 'Depth 1' }, { value: 2, label: 'Depth 2' }, { value: 3, label: 'Depth 3' }], depth, { allLabel: null, attrs: 'data-change="depth"' })}`)}
      <div class="graph-wrap"><div>${others.length ? radialSvg(node.id, nodes, hood.edges) : `<div class="panel">${empty('No neighbours', 'This node has no edges yet.')}</div>`}</div>
      <div>${panel({ title: 'Node', body: kv([['Kind', esc(node.kind)], ['Key', mono(node.key)], ['Source', esc(node.source)], ['Criticality', tag(node.criticality)], ['Exposure', esc(num(node.exposure_score))], ['Stale', node.is_stale ? 'yes' : 'no'], ['First seen', esc(fmt(node.first_seen_at))], ['Last seen', time(node.last_seen_at)]]) + `<h3 style="margin-top:14px">Properties</h3>${json(node.props)}` })}
      <div style="margin-top:16px">${panel({ title: `Neighbours (${others.length})`, sub: `${hood.edges.length} edges`, body: others.length ? `<div class="node-list">${others.slice(0, 80).map((n) => `<button class="node-row" data-act="node" data-id="${esc(n.id)}"><span>${esc(label(n))} <span class="subtle">${esc(n.kind)}</span></span><small>${esc(n.key)}</small></button>`).join('')}</div>` : empty('None') })}</div></div></div>`;
  });
  bind(root, { node: (el) => navigate(`graph/nodes/${el.dataset.id}`) }, { depth: (el) => { setQuery(navigate, 'graph', ['nodes', id], { depth: el.value }); view.reload(); } });
}

async function renderExplorer({ root, params, query, navigate }) {
  const tab = params[0] || 'nodes';
  const state = newPager();
  root.innerHTML = `${heading('Evidence graph', 'Graph', 'Entities and relations collected from cloud, identity, code and runtime sources, with materialized attack paths.',
    store.can('detections:run') ? '<button class="btn" data-act="recompute">Recompute attack paths</button>' : '')}
    <div data-stats></div>
    ${tabs([{ id: 'nodes', label: 'Nodes' }, { id: 'paths', label: 'Attack paths' }, { id: 'exposures', label: 'Exposures' }], tab)}
    <div data-tab-body></div>`;
  section($('[data-stats]', root), () => get('/graph/stats'), (s) => metrics([
    { label: 'Nodes', value: Object.values(s.nodes_by_kind || {}).reduce((a, b) => a + b, 0), caption: Object.entries(s.nodes_by_kind || {}).slice(0, 4).map(([k, v]) => `${k} ${v}`).join(' · ') || 'empty graph' },
    { label: 'Edges', value: Object.values(s.edges_by_rel || {}).reduce((a, b) => a + b, 0), caption: Object.entries(s.edges_by_rel || {}).slice(0, 4).map(([k, v]) => `${k} ${v}`).join(' · ') || '—' },
    { label: 'Open attack paths', value: s.attack_paths_open, caption: 'exposure → data store' },
    { label: 'Stale nodes', value: s.stale_nodes, caption: 'not seen by the latest collection' },
  ]));
  const bodyNode = $('[data-tab-body]', root);
  let list;
  if (tab === 'nodes') {
    bodyNode.innerHTML = `<div class="toolbar"><div class="tool-filters" data-filters><input class="field-input" name="search" placeholder="Search label or key" value="${esc(query.search || '')}" data-enter="apply"><input class="field-input" name="kind" placeholder="Kind (asset, identity, …)" value="${esc(query.kind || '')}" style="min-width:160px" data-enter="apply"><label class="check"><input type="checkbox" name="include_stale" ${query.include_stale ? 'checked' : ''} data-change="apply"> <span>Include stale</span></label></div></div><div class="panel" data-list></div>`;
    const filters = () => { const f = readFilters($('[data-filters]', bodyNode)); return { ...f, include_stale: Boolean(f.include_stale) }; };
    list = section($('[data-list]', bodyNode), () => get('/graph/nodes', { ...filters(), limit: 50, cursor: state.cursor }), (data) => {
      state.next_cursor = data.next_cursor;
      return table({ columns: [
        { label: 'Node', render: (n) => `<span class="cell-main">${esc(label(n))}</span><span class="cell-sub mono">${esc(n.key)}</span>` }, { label: 'Kind', render: (n) => esc(n.kind) }, { label: 'Criticality', render: (n) => tag(n.criticality) },
        { label: 'Exposure', render: (n) => esc(num(n.exposure_score)) }, { label: 'Source', render: (n) => esc(n.source) }, { label: 'Last seen', render: (n) => `${time(n.last_seen_at)}${n.is_stale ? ' ' + tag('stale') : ''}` }],
      rows: data.items, rowAttr: (n) => `data-act="node" data-id="${esc(n.id)}"`, empty: 'No nodes', emptySub: 'Run a collector to populate the graph.' }) + pager(state, data.items.length);
    });
    const apply = () => { pageReset(state); setQuery(navigate, 'graph', ['nodes'], readFilters($('[data-filters]', bodyNode))); list.reload(); };
    bind(bodyNode, {}, { apply });
    $('input[name=search]', bodyNode).addEventListener('input', debounce(apply, 350));
  } else if (tab === 'paths') {
    bodyNode.innerHTML = `<div class="toolbar"><div class="tool-filters" data-filters>${selectHtml('status', PATH_STATUSES, query.status, { allLabel: 'All statuses', attrs: 'data-change="apply"' })}<input class="field-input" type="number" name="min_score" placeholder="Min score" value="${esc(query.min_score || '')}" style="min-width:110px" data-enter="apply"></div></div><div class="panel" data-list></div>`;
    list = section($('[data-list]', bodyNode), () => get('/graph/attack-paths', { ...readFilters($('[data-filters]', bodyNode)), limit: 50, cursor: state.cursor }), (data) => {
      state.next_cursor = data.next_cursor;
      return table({ columns: [
        { label: 'Path', cls: 'wrap', render: (p) => `<span class="cell-main">${esc(p.summary || `${p.hops?.length || 0} hops`)}</span><div class="hops">${(p.hops || []).map((h, i) => `${i ? '<span class="arrow">→</span>' : ''}<span class="pill" title="${esc(h.rel || '')}">${esc(h.label || h.key || h.node_id?.slice(0, 8) || h.id?.slice(0, 8) || '')}</span>`).join('')}</div>` },
        { label: 'Score', render: (p) => esc(num(p.score)) }, { label: 'Status', render: (p) => tag(p.status) }, { label: 'Computed', render: (p) => time(p.computed_at) },
        { label: '', render: (p) => `<div class="inline-actions"><button class="btn small" data-act="path" data-id="${esc(p.id)}">Detail</button>${store.can('findings:write') ? PATH_STATUSES.filter((s) => s !== p.status).map((s) => `<button class="btn small" data-act="path-status" data-id="${esc(p.id)}" data-status="${s}">${esc(nice(s))}</button>`).join('') : ''}</div>` }],
      rows: data.items, empty: 'No attack paths', emptySub: 'Recompute after collectors have populated exposures and data stores.' }) + pager(state, data.items.length);
    });
    bind(bodyNode, {}, { apply: () => { pageReset(state); setQuery(navigate, 'graph', ['paths'], readFilters($('[data-filters]', bodyNode))); list.reload(); } });
  } else {
    bodyNode.innerHTML = `<div class="panel" data-list></div>`;
    list = section($('[data-list]', bodyNode), () => get('/graph/exposures', { limit: 50 }), (data) => table({ columns: [
      { label: 'Node', render: (n) => `<span class="cell-main">${esc(label(n))}</span><span class="cell-sub mono">${esc(n.key)}</span>` }, { label: 'Kind', render: (n) => esc(n.kind) }, { label: 'Criticality', render: (n) => tag(n.criticality) },
      { label: 'Exposure score', render: (n) => `<div style="min-width:140px">${esc(num(n.exposure_score))}<div class="meter"><span style="width:${Math.min(100, n.exposure_score || 0)}%"></span></div></div>` }, { label: 'Last seen', render: (n) => time(n.last_seen_at) }],
    rows: data.items, rowAttr: (n) => `data-act="node" data-id="${esc(n.id)}"`, empty: 'No exposure data', emptySub: 'Exposure scores are computed from graph relations by the graph package.' }));
  }
  bind(root, {
    node: (el) => navigate(`graph/nodes/${el.dataset.id}`),
    path: async (el) => { const p = await get(`/graph/attack-paths/${el.dataset.id}`); drawer('Attack path', `<div class="chip-row">${tag(p.status)}<span class="pill">score ${esc(num(p.score))}</span></div><p class="info-line">${esc(p.summary)}</p>${json(p.hops)}`); },
    'path-status': async (el) => {
      const result = await confirm(`Mark this attack path as ${nice(el.dataset.status)}?`, { label: 'Update', comment: 'Comment (optional)' });
      if (!result) return;
      await patch(`/graph/attack-paths/${el.dataset.id}`, { status: el.dataset.status, comment: result.comment || '' });
      toast('Attack path updated');
      list.reload(true);
    },
    recompute: async () => {
      const result = await post('/graph/recompute', {});
      trackJob(result.job_id, 'Attack path recompute').then(() => list.reload(true));
    },
    'page-next': () => { pageNext(state); list.reload(); },
    'page-prev': () => { pagePrev(state); list.reload(); },
  });
  root.querySelector('.tabs').addEventListener('click', (event) => { const t = event.target.closest('[data-tab]'); if (t) navigate(`graph/${t.dataset.tab}`); });
}

export default {
  render(ctx) { return ctx.params[0] === 'nodes' && ctx.params[1] ? renderNode(ctx) : renderExplorer(ctx); },
};
