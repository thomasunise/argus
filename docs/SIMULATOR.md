# Agentic attack simulator

The simulator answers one question: if autonomous attacker agents hit this tenant today, which of
their moves would Argus detect? It replays synthetic agent-driven attacks against the detection engine
and reports, per scenario, which rules fired and which did not.

It generates data only. It sends no traffic, runs no tools and touches no real system.

## Scenarios

| Id | What the attacker agents do | ATT&CK | Rules expected to fire |
|---|---|---|---|
| `agent_swarm_credential_spray` | dozens of agent identities try passwords on the same privileged accounts within minutes | T1110.003 | `swarm.coordinated_identity_fanout` |
| `machine_speed_recon` | a stolen key driven by an LLM enumerates ~60 API actions across 20 services at sub-second pace | T1580, T1087.004, T1526 | `swarm.machine_speed_sequence`, `agentic.tool_abuse_pattern`, `swarm.novel_action_burst` |
| `autonomous_privilege_escalation` | assume an admin role, attach AdministratorAccess, read the production DB secret | T1078.004, T1098.003, T1555.006 | `identity.privilege_escalation_chain` |
| `lateral_fanout` | one service identity opens sessions to hosts, databases and buckets with sub-second gaps | T1021, T1530 | `swarm.synchronized_multi_asset_access` |
| `impossible_travel_agent` | a session token replayed from the other side of the world minutes later | T1550.004 | `identity.impossible_velocity` |
| `canary_grab` | an agent finds a planted LLM API key and uses it | T1552.001 | `canary.tripwire` |
| `exposure_and_secret_leak` | a bucket opened to the internet, and a coding agent commits a cloud key | T1537, T1552.004 | `cloud.public_exposure_change`, `code.secret_committed` |
| `rogue_k8s_agent` | an agent runner starts a privileged pod with host PID and host network | T1610, T1611 | `k8s.privileged_workload` |

Options:

- `intensity` (`low`, `normal`, `high`) scales the number of actors and actions.
- `evasion: true` replays the same attacks "slow and low": fewer identities, minutes or hours between
  steps, browser user agents, no agent headers. Expect gaps; they show which thresholds an attacker can
  tune their agents to slip under, so you can decide whether to tighten rule parameters.

## Isolation

Each tenant has one hidden sandbox tenant (`sim-<tenant id prefix>`, inactive, no members, no actions).
For each scenario the simulator:

1. empties the sandbox;
2. copies in the real tenant's detection rule settings (enabled flags and parameters) and baselines, so
   the result reflects how the real tenant is tuned;
3. writes the scenario's events (and canary hits) to the sandbox and runs the detection engine there;
4. records the outcome and empties the sandbox again.

The scenario runs in one transaction that is never committed with sandbox data, and off the event loop,
so no `detection.created` event is published: simulated detections cannot reach autonomous response,
outbound integrations, findings or posture. Detections are also tagged `simulation`, which autonomous
response skips in any case. Only the `SimulationRun` report is stored in the real tenant.

## Reading the report

Each scenario reports `outcome` (`detected`, `partial`, `missed`), `fired_rules`, `missed_rules`,
`extra_rules` (also fired), `disabled_rules` (expected rules the tenant has switched off) and the
detections produced. The run has an overall `coverage` (detected = 1, partial = 0.5) and a `gaps`
list.

## API

See "Attack simulator" in `docs/API.md`. Starting a run needs `detections:run` (operator and up).
