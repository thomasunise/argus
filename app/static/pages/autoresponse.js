import { get, post, patch, put, del } from '../api.js';
import { store } from '../store.js';
import { $, bind, confirm, closeDrawer, drawer, esc, fields, formActions, heading, json, kv, metrics, onSubmit,
         panel, readFields, table, tag, time, toast, num } from '../ui.js';

function playbookForm(afterSave, catalog) {
  const actions = catalog.items || [];
  if (!actions.length) { toast('No actions are registered', 'error'); return; }
  const defs = [
    { name: 'name', label: 'Playbook name', type: 'text', required: true, maxlength: 120 },
    { name: 'description', label: 'Purpose', type: 'textarea', rows: 2 },
    { name: 'action_type', label: 'Action', type: 'select', required: true, options: actions.map(a => ({ value: a.name, label: a.name + ' (' + a.risk + ')' })) },
    { name: 'mode', label: 'Mode', type: 'select', options: ['shadow', 'enforce'], value: 'shadow',
      hint: 'Shadow records decisions without making changes. Enforce performs the action only after all broker checks.' },
    { name: 'min_severity', label: 'Minimum severity', type: 'select', options: ['critical', 'high', 'medium', 'low', 'informational'], value: 'high' },
    { name: 'min_confidence', label: 'Minimum confidence', type: 'number', min: 0, max: 1, step: 0.05, value: 0.8 },
    { name: 'rule_ids', label: 'Rules (empty = any)', type: 'tags', value: [] },
    { name: 'params_template', label: 'Action parameters (JSON)', type: 'json', rows: 5, value: {} },
    { name: 'max_per_hour', label: 'Maximum actions per hour', type: 'number', min: 0, max: 500, value: 5 },
    { name: 'max_blast_radius', label: 'Maximum affected entities', type: 'number', min: 1, max: 100, value: 1 },
    { name: 'rollback_after_minutes', label: 'Automatic rollback delay (minutes, 0 disables)', type: 'number', min: 0, max: 43200, value: 60 },
  ];
  const body = drawer('Create response playbook', `<p class="info-line">A playbook starts in shadow mode by default. Enable enforcement only after review and a validated dry run.</p><form class="form-stack">${fields(defs)}${formActions('Create playbook')}</form>`, { wide: true });
  onSubmit($('form', body), async form => {
    const data = readFields(form, defs);
    if (data.mode === 'enforce') {
      const allowed = await confirm('Enforce mode can change external systems when the tenant and broker permit actions. Create it in enforce mode?', { label: 'Enable enforcement', danger: true });
      if (!allowed) return;
    }
    await post('/autoresponse/playbooks', data);
    closeDrawer();
    toast('Playbook created');
    await afterSave();
  });
}

export default {
  async render({ root }) {
    root.innerHTML = heading('Response operations', 'Autonomous response',
      'Review guarded response playbooks, execution outcomes, approvals and emergency recovery.') +
      '<div data-response-content></div>';
    const node = $('[data-response-content]', root);
    async function refresh() {
      const [status, playbooks, executions] = await Promise.all([
        get('/autoresponse/status'), get('/autoresponse/playbooks', { limit: 100 }),
        get('/autoresponse/executions', { limit: 100 }),
      ]);
      node.innerHTML = `
        ${metrics([
          { label: 'Tenant automation', value: status.tenant_enabled ? 'Enabled' : 'Off', caption: status.global_enabled ? 'Global service available' : 'Globally disabled by configuration' },
          { label: 'Playbooks', value: status.playbooks?.total ?? 0, caption: (status.playbooks?.enabled || 0) + ' enabled' },
          { label: 'Enforcement', value: status.playbooks?.enforcing || 0, caption: 'Enabled enforcing playbooks' },
          { label: 'Actions last hour', value: status.enforced_last_hour || 0, caption: 'Cap: ' + (status.max_per_hour ?? 0) },
        ])}
        ${panel({ title: 'Response controls',
          sub: 'Changes are audited. Engaging the action kill switch stops new actions, but authorized rollbacks remain available.',
          actions: store.can('autoresponse:write') ? `<button class="btn" data-act="response-toggle">${status.tenant_enabled ? 'Disable automation' : 'Enable automation'}</button>` : '',
          body: `<div class="chip-row">${tag(status.effective ? 'active' : 'disabled')}${tag(status.kill_switch?.effective ? 'kill switch engaged' : 'kill switch clear')}</div>` }) }
        ${panel({ title: 'Playbooks',
          actions: store.can('autoresponse:write') ? '<button class="btn primary" data-act="response-new">New playbook</button>' : '',
          flush: true,
          body: table({ columns: [
            { label: 'Playbook', render: p => `<span class="cell-main">${esc(p.name)}</span><span class="cell-sub">${esc(p.description || p.action_type || '')}</span>` },
            { label: 'Mode', render: p => tag(p.mode) },
            { label: 'State', render: p => tag(p.enabled ? 'enabled' : 'disabled') },
            { label: 'Rule match', render: p => esc((p.rule_ids || []).join(', ') || 'All rules') },
            { label: 'Action', render: p => esc(p.action_type) },
            { label: '', render: p => store.can('autoresponse:write') ?
              `<div class="inline-actions"><button class="btn small" data-act="response-toggle-playbook" data-id="${esc(p.id)}" data-enabled="${p.enabled ? '1' : ''}">${p.enabled ? 'Disable' : 'Enable'}</button><button class="btn small negative" data-act="response-delete" data-id="${esc(p.id)}">Delete</button></div>` : '' },
          ], rows: playbooks.items || [], empty: 'No playbooks configured' }),
        }) }
        ${panel({ title: 'Recent executions', flush: true,
          body: table({ columns: [
            { label: 'Decision', render: e => tag(e.outcome) },
            { label: 'Playbook', render: e => esc(e.playbook_id?.slice(0, 8) || '') },
            { label: 'Detection', render: e => esc(e.detection_id?.slice(0, 8) || '') },
            { label: 'Created', render: e => time(e.created_at) },
            { label: '', render: e => `<div class="inline-actions"><button class="btn small" data-act="response-detail" data-id="${esc(e.id)}">Details</button>${store.can('actions:approve') && e.outcome === 'enforced' ? `<button class="btn small" data-act="response-keep" data-id="${esc(e.id)}">Keep</button>` : ''}${store.can('actions:rollback') && e.action_run_id && e.outcome === 'enforced' ? `<button class="btn small negative" data-act="response-rollback" data-id="${esc(e.id)}">Rollback</button>` : ''}</div>` },
          ], rows: executions.items || [], empty: 'No autonomous response decisions recorded' }),
        }) }
      `;
    }
    await refresh();
    bind(root, {
      'response-toggle': async () => {
        const s = await get('/autoresponse/status');
        if (!s.tenant_enabled && !s.global_enabled) {
          toast('Automation is globally disabled. Set AUTORESPONSE_ENABLED before enabling a tenant.', 'error');
          return;
        }
        if (!s.tenant_enabled && !(await confirm('Allow automatic response evaluation for this tenant? Existing playbooks retain their own shadow/enforce mode.', { label: 'Enable', danger: true }))) return;
        await put('/autoresponse/settings', { enabled: !s.tenant_enabled });
        toast(s.tenant_enabled ? 'Automation disabled' : 'Automation enabled');
        await refresh();
      },
      'response-new': async () => playbookForm(refresh, await get('/actions/catalog')),
      'response-toggle-playbook': async el => {
        const enabling = !el.dataset.enabled;
        if (enabling && !(await confirm('Enable this response playbook? Review its mode and action permissions first.', { label: 'Enable' }))) return;
        await patch('/autoresponse/playbooks/' + encodeURIComponent(el.dataset.id), { enabled: enabling });
        toast(enabling ? 'Playbook enabled' : 'Playbook disabled'); await refresh();
      },
      'response-delete': async el => {
        if (!(await confirm('Delete this response playbook? Existing execution history is retained.', { label: 'Delete', danger: true }))) return;
        await del('/autoresponse/playbooks/' + encodeURIComponent(el.dataset.id));
        toast('Playbook deleted'); await refresh();
      },
      'response-detail': async el => {
        const entry = await get('/autoresponse/executions/' + encodeURIComponent(el.dataset.id));
        drawer('Response execution', json(entry));
      },
      'response-keep': async el => {
        if (!(await confirm('Keep this executed change and cancel its automatic rollback?', { label: 'Keep change', danger: true }))) return;
        await post('/autoresponse/executions/' + encodeURIComponent(el.dataset.id) + '/keep', {});
        toast('Change retained'); await refresh();
      },
      'response-rollback': async el => {
        if (!(await confirm('Request an emergency rollback of this executed change?', { label: 'Rollback', danger: true }))) return;
        await post('/autoresponse/executions/' + encodeURIComponent(el.dataset.id) + '/rollback', {});
        toast('Rollback requested'); await refresh();
      },
    });
  },
};
