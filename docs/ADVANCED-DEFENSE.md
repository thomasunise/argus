# Advanced defense additions (incremental)

## MCP: enforce decisions in the tool transport

Launch a trusted MCP stdio server behind the ARGUS proxy:

\`\`\`bash
# 1. Create a scoped ARGUS API key that can call ai_gateway:use.
# 2. Configure the tenant tool guard mode to "enforce" and explicitly
#    deny unknown/write/execute risks or sensitive tools as needed.
export ARGUS_API_KEY=...
python -m app.ai.mcp_proxy --argus-url https://argus.example -- python -m trusted_mcp_server
\`\`\`

Point the MCP client at this command, **not** the original server. The
proxy intercepts \`tools/call\` and calls the ARGUS evaluation API before
forwarding the request. Network failures or monitor-only responses fail
closed. Other JSON-RPC messages are passed through. This protects only
the specific stdio connection and does not secure unproxied clients,
other MCP transports, or models' plain-language responses. The proxy
does not validate the child program. Only launch a trusted local server.

## AWS IAM analysis

\`POST /api/v1/cloud-permissions/aws/identity-policy/evaluate\` takes
\`{"policies":[{"Statement":{...}}],"action":"s3:GetObject","resource":"arn:aws:s3:::example/key"}\`.
It evaluates explicit identity policy statements and reports
\`potentially_allowed_in_supplied_documents\`, explicit deny,
indeterminate, or no allow in supplied documents. Effective permissions
and resource exploitation are **not** established: SCPs, boundaries,
session policies, resource policies, conditions and service-specific
semantics require additional context. No cloud credentials are used.

## Distributed rate limits

With \`REDIS_URL\` configured, API and ingest rate limiting uses a
Redis atomic increment/expiry window shared between API workers. Redis
outages fail closed (503) rather than silently dropping protection.
Without Redis, development runs keep the existing local limiter.
The load balancer should also enforce its own anonymous IP limits.

## Industrial observations

Suricata EVE's Modbus \`function_code\` metadata is ingested through
\`/api/v1/ingest/suricata\`. Write-function codes 5, 6, 15, 16 create
\`network.modbus.write\` events and an \`industrial.modbus_write_observed\`
detection. No probing, control command, or device reconfiguration is
performed. Attach an appropriately authorized passive sensor to the
network. A *request* does not prove the device executed the write.

## Opt-in remediation retesting

\`PUT /api/v1/verification/auto-settings\` with \`{"enabled":true}\`
enables checks **for that tenant only**. The linked test scope must
separately have \`autonomous=true\`. Only previously completed
passive/active baselines for a remediation-linked finding can be rerun;
ARGUS rechecks authorization and time windows at launch and execution.
The follow-up run stores \`stats.auto_verification\` with 'not reproduced',
'still detected', and 'newly detected' rules.

This is post-action verification, **not** an automatic certificate that
the finding is fixed or an autonomous rollback. A system owner should
review discrepancies and approve any additional actions.

## Security-eval coverage

\`tests/test_tool_guard_matrix.py\` runs a deterministic matrix for
policy matching and enforcement decisions, and the existing agent eval
suites test prompt injection, triage and hunt behaviors. This does not
replace empirical red-team exercises and production recall/FPR studies.
