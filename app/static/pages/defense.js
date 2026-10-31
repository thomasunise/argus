import { get } from '../api.js';
import { store } from '../store.js';
import { $, bind, esc, heading, panel, metrics, table, tag, empty, link } from '../ui.js';

const pathDetail = (p) => '<span class="cell-main">' + esc((p.summary || 'Attack path').slice(0, 110)) + '</span>';

export default {
  async render({ root }) {
    root.innerHTML = heading('Defense intelligence', 'Continuous defense',
      'Correlated activity, behavioral identity risk, tool-call policy, and attack-path evidence. Heuristic findings are not exploit proof.') +
      '<div data-overview></div><div data-identity></div><div data-paths></div><div data-policy></div>';
    const sections = [
      store.can('detections:read') ? get('/detections', { limit: 100 }) : Promise.resolve(null),
      store.can('detections:read') ? get('/identity-risk/summary', { limit: 15 }) : Promise.resolve(null),
      store.can('graph:read') ? get('/graph/attack-paths', { limit: 15 }) : Promise.resolve(null),
      store.can('ai:read') ? get('/ai/tool-guard/policy') : Promise.resolve(null),
    ];
    const [detections, identities, paths, policy] = await Promise.all(sections.map(p => p.catch(() => null)));
    const correlated = (detections?.items || []).filter(x => x.rule_id === 'agentic.cross_source_attack_chain');
    $('[data-overview]', root).innerHTML = metrics([
      { label: 'Correlated attack chains', value: correlated.length, caption: 'Within loaded detections; not a global total' },
      { label: 'At-risk identities', value: identities?.items?.length ?? '—', caption: 'Behavioral heuristic only' },
      { label: 'Attack paths', value: paths?.items?.length ?? '—', caption: 'Graph reachability, not proof' },
      { label: 'Tool guard', value: policy?.mode || 'Unavailable', caption: 'Tenant policy mode' },
    ]);
    $('[data-identity]', root).innerHTML = panel({ title: 'Behavioral identity risk', sub: 'Recent failed logins and privilege actions',
      body: identities?.items?.length ? table({ columns: [
        { label: 'Identity', render: x => esc(x.actor) },
        { label: 'Risk score', render: x => esc(x.behavioral_risk_score) },
        { label: 'Privilege actions', render: x => esc(x.privilege_actions) },
        { label: 'Failed logins', render: x => esc(x.failed_logins) },
        { label: 'Sources', render: x => esc(x.sources.join(', ')) },
      ], rows: identities.items }) : empty('No behavioral signals available') });
    $('[data-paths]', root).innerHTML = panel({ title: 'Attack paths', sub: 'Use evidence validation to distinguish hypotheses from observations',
      body: paths?.items?.length ? table({ columns: [
        { label: 'Path', render: pathDetail },
        { label: 'Heuristic score', render: x => esc(x.score) },
        { label: 'Evidence', render: x => '<button class="btn small" data-act="validate" data-id="' + esc(x.id) + '">View evidence</button>' },
      ], rows: paths.items }) : empty('No materialized attack paths') });
    $('[data-policy]', root).innerHTML = panel({ title: 'Tool-call governance',
      sub: 'External MCP tools must call the policy endpoint through an enforcing proxy',
      body: policy ? '<div class="stat-list"><div class="stat-item"><span>Mode</span><strong>' + esc(policy.mode) +
        '</strong></div><div class="stat-item"><span>Denied tools</span><strong>' + esc((policy.deny_tools || []).join(', ') || 'none') +
        '</strong></div><div class="stat-item"><span>Denied risks</span><strong>' + esc((policy.deny_risks || []).join(', ') || 'none') +
        '</strong></div></div>' : empty('Tool-guard policy not accessible') });
    bind(root, { validate: async (el) => {
      const detail = await get('/graph/attack-paths/' + encodeURIComponent(el.dataset.id) + '/validation');
      const lines = detail.edges.map(x => esc(x.relation) + ': ' + esc(x.status)).join('; ');
      const info = document.createElement('div');
      info.className = 'callout';
      info.textContent = detail.validation_status + ': ' + detail.edges.map(x => x.relation + ' (' + x.status + ')').join(', ');
      const host = $('[data-paths]', root);
      host.prepend(info);
    } });
  },
};
