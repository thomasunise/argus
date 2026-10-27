// Session state shared by every page. Mirrors app/core/rbac.py so write actions can be hidden client-side;
// the server remains the authority.
const VIEWER = ['assets:read', 'findings:read', 'events:read', 'graph:read', 'detections:read', 'collectors:read', 'agents:read', 'tests:read',
  'actions:read', 'integrations:read', 'audit:read', 'reports:read', 'investigations:read', 'approvals:read', 'canaries:read', 'scans:read', 'evals:read', 'autoresponse:read', 'ai:read', 'exploit:read'];
const ANALYST = [...VIEWER, 'findings:write', 'investigations:write', 'agents:run', 'detections:write', 'canaries:write', 'approvals:write', 'evals:run', 'ai_gateway:use', 'exploit:run'];
const OPERATOR = [...ANALYST, 'assets:write', 'assets:authorize', 'tests:run', 'tests:write', 'scans:run', 'collectors:run', 'actions:request',
  'actions:approve', 'actions:execute', 'actions:rollback', 'detections:run', 'exploit:approve'];
const ADMIN = [...OPERATOR, 'admin:users', 'admin:api_keys', 'admin:settings', 'collectors:write', 'integrations:write', 'actions:kill_switch', 'tests:scopes', 'autoresponse:write', 'ai:write'];
const OWNER = [...ADMIN, 'admin:tenant', 'actions:approve_critical'];
export const ROLE_PERMS = { viewer: new Set(VIEWER), analyst: new Set(ANALYST), operator: new Set(OPERATOR), admin: new Set(ADMIN), owner: new Set(OWNER) };
export const ROLES = ['viewer', 'analyst', 'operator', 'admin', 'owner'];

const listeners = new Map();

export const store = {
  session: null,
  csrf: null,
  killSwitch: null,
  cache: new Map(),
  get role() { return this.session?.role || ''; },
  get user() { return this.session?.user || null; },
  get tenant() { return this.session?.tenant || null; },
  get authenticated() { return Boolean(this.session?.authenticated); },
  can(perm) { return Boolean(ROLE_PERMS[this.role]?.has(perm)); },
  roleAtLeast(role) { return ROLES.indexOf(this.role) >= ROLES.indexOf(role); },
  setSession(session) {
    this.session = session && session.authenticated ? session : null;
    this.csrf = session?.csrf || null;
    this.cache.clear();
    this.emit('session', this.session);
  },
  on(event, fn) {
    if (!listeners.has(event)) listeners.set(event, new Set());
    listeners.get(event).add(fn);
    return () => listeners.get(event).delete(fn);
  },
  emit(event, data) { for (const fn of listeners.get(event) || []) fn(data); },
  // Short-lived memo for reference data (asset names, specs, catalog) reused across pages.
  async memo(key, loader, ttlMs = 30000) {
    const hit = this.cache.get(key);
    if (hit && Date.now() - hit.at < ttlMs) return hit.value;
    const value = await loader();
    this.cache.set(key, { at: Date.now(), value });
    return value;
  },
  forget(prefix) { for (const key of [...this.cache.keys()]) if (key.startsWith(prefix)) this.cache.delete(key); },
};

export function prefGet(key, fallback = null) {
  try { const raw = localStorage.getItem(`argus-${key}`); return raw === null ? fallback : JSON.parse(raw); } catch { return fallback; }
}
export function prefSet(key, value) {
  try { localStorage.setItem(`argus-${key}`, JSON.stringify(value)); } catch { /* storage unavailable */ }
}
