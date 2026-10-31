# Expanded defense capabilities (incremental implementation)

This branch adds working foundations, **not a claim that all production integrations are complete**.

## Implemented

- Tenant-scoped tool-call guard, with monitor/enforce modes, tool/risk/host policies.
  Argus internal AgentRuntime honors enforced decisions before invoking tools.
  External MCP and agent clients can call POST /api/v1/ai/tool-guard/evaluate, but
  **must send every call through their own enforcing proxy**. Calling this API
  without honoring the decision does not block third-party tools.
- Cross-source attack-chain detection rule (agentic.cross_source_attack_chain)
  tracks ordered authentication -> privilege -> data/egress stages by actor.
  Evidence contains event IDs and source names; no LLM classification is required.
- GET /api/v1/graph/attack-paths/{id}/validation distinguishes topological paths
  from routes whose edges reference completed tenant-owned test evidence.
  Even 'evidence_linked' **does not prove an exploit path is feasible**.
- POST /api/v1/verification/retest/{run_id} reruns a completed baseline through
  the existing scope, asset, tier, time-window and authorization checks.
  GET /api/v1/verification/compare compares two completed runs and reports
  rules no longer reproduced, still detected, or newly detected; it never
  asserts remediation from the absence of a single finding.
- POST /api/v1/verification/actions/{action_run_id}/retest finds the baseline
  for the completed action's linked finding, then queues an authorized scan.
- GET /api/v1/identity-risk/summary provides bounded behavioral scores for
  failure and privilege-action telemetry. It is not effective permission analysis.
- Zeek JSON and Suricata EVE ingestion: POST /api/v1/ingest/zeek and /suricata
  with existing scoped ingest API keys. No agents are installed on endpoints.
- 'Defense intelligence' navigation page surfaces correlated detections, identity
  behavioral risk, path evidence and tool-guard policy state.

## Still missing: deployment/coverage work

- An enforcing MCP reverse-proxy for arbitrary third-party agents, persistent
  agent-to-agent provenance, and cross-provider streaming content checks.
- Credential-effective AWS/Azure/GCP policy simulation and path precondition proof.
- Stronger vulnerability proof (actual sandboxed browser JS execution checks);
  scanner findings have been downgraded where proof is insufficient.
- Auto-remediation orchestration with health/rollback verification and operating
  thresholds. Remediation remains governed by the existing action broker.
- Native device/endpoint/OT sensor deployment and passive industrial protocol
  decoding. Zeek/Suricata ingestion requires a separately deployed sensor.
- Large adversarial eval datasets, benchmarked recall and false positives.
- PostgreSQL RLS, distributed token buckets, dedicated encryption keys,
  and full administrative UI for every new endpoint.

## Safety

These are monitoring, policy and *authorized retest* capabilities. No external
MCP tool is run by the policy endpoint. Any active scanning still passes the
existing scope checks; high-impact remediation is not automated by this branch.
