// Pieces shared by several pages: reference-data lookups, job polling, generic list page scaffolding.
import { get, waitJob } from './api.js';
import { store } from './store.js';
import { $, bind, errorBox, loading, toast } from './ui.js';

/** Map asset id -> asset (cached 30s). */
export async function assetMap() {
  return store.memo('assets:map', async () => {
    const data = await get('/assets', { limit: 500 }, { silent: true });
    return new Map(data.items.map((a) => [a.id, a]));
  });
}
export const assetName = (map, id) => (id ? (map.get(id)?.name || id.slice(0, 8)) : '—');

/** Map user id -> member (admins only; others get an empty map). */
export async function userMap() {
  if (!store.can('admin:users')) return new Map();
  return store.memo('users:map', async () => {
    const data = await get('/admin/users', { limit: 500 }, { silent: true });
    return new Map(data.items.map((u) => [u.id, u]));
  });
}
export const userLabel = (map, id) => (id ? (map.get(id)?.email || map.get(id)?.display_name || id) : '—');

/** Announce a queued job and report its outcome when it finishes. */
export async function trackJob(jobId, label) {
  if (!jobId) return null;
  toast(`${label} queued`);
  const job = await waitJob(jobId).catch(() => null);
  if (!job) { toast(`${label}: still running in the background`); return null; }
  if (job.status === 'completed') toast(`${label} completed`);
  else toast(`${label} ${job.status}${job.error ? `: ${job.error}` : ''}`, 'error');
  return job;
}

/**
 * Mount a section that loads data and re-renders. `load()` returns data, `view(data)` returns HTML.
 * Returns {reload} and wires data-act="retry". Handles loading, error and (via view) empty states.
 */
export function section(node, load, view, { onRender } = {}) {
  let token = 0;
  async function reload(soft = false) {
    const mine = ++token;
    if (!soft) node.innerHTML = loading();
    else await settle();
    try {
      const data = await load();
      if (mine !== token) return;
      node.innerHTML = view(data);
      if (onRender) onRender(data, node);
    } catch (err) {
      if (mine !== token || err?.status === 401) return;
      node.innerHTML = errorBox(err);
    }
  }
  bind(node, { retry: () => reload() });
  reload();
  return { reload };
}

/** The API commits a request's transaction after its response is sent, so an immediate read can miss the write.
 * Soft reloads (after a mutation) wait briefly before fetching. */
export const settle = (ms = 300) => new Promise((resolve) => setTimeout(resolve, ms));

/** Read filter controls (inputs/selects with a name) inside a toolbar element into an object. */
export function readFilters(toolbar) {
  const out = {};
  for (const input of toolbar.querySelectorAll('[name]')) {
    if (input.type === 'checkbox') { if (input.checked) out[input.name] = true; } else if (input.value !== '') out[input.name] = input.value;
  }
  return out;
}

export function setQuery(navigate, page, params, query) {
  const text = new URLSearchParams(Object.entries(query).filter(([, v]) => v !== '' && v !== undefined && v !== null)).toString();
  navigate(`${[page, ...params].join('/')}${text ? `?${text}` : ''}`, { replace: true });
}

export const focusSearch = (root) => { const input = $('input[name=search]', root); if (input) input.focus(); };
