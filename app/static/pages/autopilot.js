import { get, post } from '../api.js';
import { store } from '../store.js';
import { $, bind, closeDrawer, confirm, drawer, esc, fields, formActions, heading,
         json, kv, onSubmit, panel, readFields, table, tag, time, toast } from '../ui.js';

export default {
  async render({ root }) {
    root.innerHTML = heading('Offensive testing', 'Autopilot runs',
      'Authorized unattended testing only. Every action must remain within an active, explicitly autonomous scope.') +
      '<div data-autopilot-list></div>';
    const node = $('[data-autopilot-list]', root);

    async function reload() {
      const data = await get('/tests/autopilot', { limit: 100 });
      node.innerHTML = panel({
        title: 'Pentest automation history',
        sub: 'Global opt-in and per-tenant permissions apply. A stopped run may take time to cancel in-flight work.',
        actions: store.can('tests:run') ? '<button class="btn primary" data-act="autopilot-new">New autopilot run</button>' : '',
        flush: true,
        body: table({
          columns: [
            { label: 'Scope / Assets', render: r => `<span class="cell-main">${esc(r.scope_id?.slice(0, 8) || '')}</span><span class="cell-sub">${(r.asset_ids || []).length} assets · ${esc(r.max_tier)}</span>` },
            { label: 'Status', render: r => tag(r.status) },
            { label: 'Rounds', render: r => esc(r.rounds_completed + '/' + r.max_rounds) },
            { label: 'Test runs', render: r => esc(r.test_runs) },
            { label: 'New findings', render: r => esc(r.findings_new) },
            { label: 'Started', render: r => time(r.started_at || r.created_at) },
            { label: '', render: r => `<div class="inline-actions"><button class="btn small" data-act="autopilot-detail" data-id="${esc(r.id)}">Details</button>${store.can('tests:run') && ['queued', 'running'].includes(r.status) && !r.stop_requested ? `<button class="btn small negative" data-act="autopilot-stop" data-id="${esc(r.id)}">Stop</button>` : ''}</div>` },
          ],
          rows: data.items || [],
          empty: 'No autonomous testing runs yet',
        }),
      });
    }
    await reload();
    bind(root, {
      'autopilot-new': async () => {
        const scopes = await get('/tests/scopes', { limit: 100 });
        const available = (scopes.items || []).filter(s => s.autonomous && !s.revoked_at);
        if (!available.length) {
          toast('Create and authorize an autonomous test scope in Testing first.', 'error');
          return;
        }
        const defs = [
          { name: 'scope_id', label: 'Explicitly autonomous scope', type: 'select', required: true,
            options: available.map(s => ({ value: s.id, label: s.name })) },
          { name: 'max_tier', label: 'Maximum testing tier', type: 'select', options: ['passive', 'active', 'intrusive'], value: 'passive' },
          { name: 'max_rounds', label: 'Maximum rounds', type: 'number', min: 1, max: 20, value: 2 },
        ];
        const body = drawer('Launch authorized autopilot', `<p class="info-line">Autonomous testing remains off unless the global switch, tenant opt-in, asset authorizations, scope and timing all allow it. No implicit grants are made.</p><form class="form-stack">${fields(defs)}${formActions('Review and launch')}</form>`);
        onSubmit($('form', body), async form => {
          const data = readFields(form, defs);
          if (!(await confirm('Launch unattended testing within this signed scope? Confirm the scope, target network and maximum tier are authorized.', { label: 'Launch', danger: true }))) return;
          await post('/tests/autopilot', { ...data, asset_ids: [] });
          closeDrawer(); toast('Autopilot queued'); await reload();
        });
      },
      'autopilot-detail': async el => {
        const run = await get('/tests/autopilot/' + encodeURIComponent(el.dataset.id));
        drawer('Autopilot run ' + run.id.slice(0, 8), `<div class="chip-row">${tag(run.status)}<span class="pill">${esc(run.max_tier)}</span></div>${kv([['Scope', esc(run.scope_id)], ['Started', time(run.started_at)], ['Finished', time(run.finished_at)], ['Test runs', esc(run.test_runs)], ['New findings', esc(run.findings_new)], ['Error', esc(run.error || '')]])}<h3>Summary</h3>${json(run.summary)}<h3>Steps</h3>${json(run.steps)}`);
      },
      'autopilot-stop': async el => {
        if (!(await confirm('Request this autonomous testing run to stop? No further tests will be launched.', { label: 'Stop', danger: true }))) return;
        await post('/tests/autopilot/' + encodeURIComponent(el.dataset.id) + '/stop', {});
        toast('Stop requested'); await reload();
      },
    });
  },
};
