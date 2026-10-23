// Fetch helper for the v1 API: same-origin cookies, CSRF header on mutations, 401 -> login, {detail, code} -> toast.
import { store } from './store.js';
import { toast } from './ui.js';

export const BASE = '/api/v1';

export class ApiError extends Error {
  constructor(status, detail, code, body) {
    super(detail);
    this.status = status;
    this.code = code || 'error';
    this.body = body;
  }
}

function describe(status, data) {
  if (data && typeof data.detail === 'string') return data.detail;
  if (data && Array.isArray(data.detail)) {
    return data.detail.map((d) => `${(d.loc || []).filter((x) => x !== 'body').join('.')}: ${d.msg}`).join('; ') || 'Validation failed';
  }
  if (status === 0) return 'Network error';
  return `Request failed (${status})`;
}

export function qs(query) {
  if (!query) return '';
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === null || value === '' || value === false) continue;
    params.set(key, String(value));
  }
  const text = params.toString();
  return text ? `?${text}` : '';
}

/** api('/findings', {query}) | api('/findings/1', {method:'PATCH', body}) | api(path, {raw:true}) for blobs. */
export async function api(path, { method = 'GET', body, query, raw = false, silent = false, headers = {} } = {}) {
  const url = (path.startsWith('/api/') ? path : BASE + path) + qs(query);
  const init = { method, credentials: 'same-origin', headers: { Accept: raw ? '*/*' : 'application/json', ...headers } };
  if (body !== undefined) {
    init.headers['Content-Type'] = 'application/json';
    init.body = typeof body === 'string' ? body : JSON.stringify(body);
  }
  if (method !== 'GET' && method !== 'HEAD' && store.csrf) init.headers['X-CSRF-Token'] = store.csrf;
  let response;
  try {
    response = await fetch(url, init);
  } catch (err) {
    const error = new ApiError(0, 'Network error: the API is unreachable', 'network');
    if (!silent) toast(error.message, 'error');
    throw error;
  }
  if (response.status === 401 && !path.startsWith('/auth/login') && !path.startsWith('/auth/session') && !path.startsWith('/auth/totp')) {
    store.emit('unauthorized');
    throw new ApiError(401, 'Session expired, please sign in again', 'unauthorized');
  }
  if (raw) {
    if (!response.ok) {
      let data = null;
      try { data = await response.json(); } catch { /* not json */ }
      const error = new ApiError(response.status, describe(response.status, data), data?.code, data);
      if (!silent) toast(error.message, 'error');
      throw error;
    }
    return response;
  }
  let data = null;
  const text = await response.text();
  if (text) { try { data = JSON.parse(text); } catch { data = { detail: text.slice(0, 200) }; } }
  if (!response.ok) {
    const error = new ApiError(response.status, describe(response.status, data), data?.code, data);
    if (!silent && method !== 'GET') toast(error.message, 'error');
    throw error;
  }
  return data === null ? {} : data;
}

export const get = (path, query, opts = {}) => api(path, { query, ...opts });
export const post = (path, body = {}, opts = {}) => api(path, { method: 'POST', body, ...opts });
export const patch = (path, body = {}, opts = {}) => api(path, { method: 'PATCH', body, ...opts });
export const del = (path, opts = {}) => api(path, { method: 'DELETE', ...opts });

/** Poll a queue job until it is terminal (max ~20s). Returns the job or null on timeout. */
export async function waitJob(jobId, { timeoutMs = 20000, intervalMs = 400 } = {}) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const job = await get(`/ops/jobs/${encodeURIComponent(jobId)}`, null, { silent: true });
    if (['completed', 'failed', 'cancelled'].includes(job.status)) return job;
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
  return null;
}

/** Download a file through fetch so the session cookie and CSP are respected. */
export async function download(path, filename, query) {
  const response = await api(path, { query, raw: true });
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}
