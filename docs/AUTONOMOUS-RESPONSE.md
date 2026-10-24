# Autonomous response and Slack buttons

Two ways to act on a threat faster than "open Argus, find the request, approve, execute":

1. **Autonomous response**: playbooks that turn a detection into a broker action with no human in
   the loop, under strict guardrails, and undo it automatically unless someone keeps it.
2. **Slack buttons**: Approve, Deny and Roll back directly from the Slack message.

Both go through the action broker. Approvals, kill switches, deny-lists, dry runs and the
execute-time re-check apply exactly as for a request made in the web UI.

## Autonomous response

### Turning it on

It is off at two levels, and both must be on:

| Setting | Default | Meaning |
|---|---|---|
| `AUTORESPONSE_ENABLED` | `false` | global switch for the deployment |
| `PUT /api/v1/autoresponse/settings {"enabled": true}` | off | tenant opt-in (admin) |
| `AUTORESPONSE_MAX_PER_HOUR` | `20` | enforced autonomous actions per tenant per hour; a tenant may set a lower `max_per_hour` |
| `AUTORESPONSE_SWEEP_SECONDS` | `60` | how often expired actions are rolled back |

The tenant's actions must also be enabled (`POST /api/v1/actions/kill-switch {"enabled": false}`).
Engaging the kill switch stops autonomous actions immediately. It also blocks rollbacks while it is
engaged; pending automatic rollbacks are retried after it is released.

### Playbooks

```json
{
  "name": "Block sources that touch canaries",
  "mode": "shadow",
  "rule_ids": ["canary_tripwire"],
  "min_severity": "high",
  "min_confidence": 0.9,
  "entity_kind": "",
  "action_type": "cloudflare.waf.block_ip",
  "params_template": {"zone_id": "0123456789abcdef0123456789abcdef", "ip": "{{evidence.src_ip}}"},
  "max_per_hour": 5,
  "max_blast_radius": 1,
  "rollback_after_minutes": 60,
  "allow_high_risk": false
}
```

- **mode**: `shadow` (the default for new playbooks) runs the dry run and records what it would have
  done without changing anything. Switch to `enforce` once the shadow record looks right.
- **matching**: `rule_ids` (empty = any rule), minimum severity, minimum confidence, optional entity kind.
- **params_template**: string values may contain `{{field}}` placeholders taken from the detection:
  `id`, `rule_id`, `title`, `severity`, `entity`, `entity_kind`, `confidence`, `finding_id`,
  `evidence.<key>` (dotted paths, list indexes allowed). There is no expression language. A string
  that is exactly one placeholder keeps the value's type. A missing or non-scalar value skips the
  playbook for that detection.
- **rollback_after_minutes**: an enforced action is rolled back automatically after this long unless
  someone calls `POST /api/v1/autoresponse/executions/{id}/keep`. `0` means never roll back
  automatically.

### Guardrails

A playbook can only use an action that is **reversible** and **not critical**. High-risk actions,
such as host isolation, need `allow_high_risk: true` on the playbook. For every matching detection the engine:

1. Skips detections from the attack simulator: tag `simulation`, `evidence.simulation = true` or
   `evidence.source = "simulator"`.
2. Renders and validates the params against the action schema.
3. Applies the playbook hourly limit and, in enforce mode, the tenant hourly cap.
4. Creates the ActionRequest through the broker as the system principal with
   `policy.evaluate(autonomous=...)`. The policy auto-approves only if:
   - the dry run succeeded
   - the blast radius is within `max_blast_radius`
   - the risk is within the playbook limit (medium, or high with `allow_high_risk`)
   - no hard denial applies: global or tenant kill switch, deny-list, actions disabled

   Otherwise the request stays **pending** for humans (outcome `escalated`) or is refused (`denied`).
5. Queues execution. The worker re-checks policy, runs the dry run again, executes and stores the
   rollback payload.

Agent-originated requests are never auto-approved. The broker refuses the `autonomous` flag from
anyone but the system principal.

### Outcomes

`GET /api/v1/autoresponse/executions` has one row per (playbook, detection) that matched:

| Outcome | Meaning |
|---|---|
| `skipped` | a guardrail stopped it (simulation, template value missing, invalid params, hourly limit) |
| `shadow` | shadow mode; `reason` says whether it would have executed, escalated or been denied |
| `escalated` | enforce mode, but the policy wanted humans; see `action_request_id` |
| `enforced` | executed autonomously; `rollback_state` is `pending` until rolled back (`requested` → `done`) or `kept` |
| `denied` | hard policy denial |
| `failed` | unexpected error; see `reason` |

Every decision is audited as `autoresponse.decision`. Enforced actions also publish an
`action.autonomous` event, which outbound integrations, including Slack with a Roll back button,
can subscribe to.

## Slack buttons

### Slack app setup

1. Create a Slack app (api.slack.com/apps). Under **Interactivity & Shortcuts**, turn interactivity on
   and set the Request URL to `https://<argus>/api/v1/slack/interactions/<integration id>`. Create
   the integration first to get its id.
2. Copy the app's **Signing Secret** into a secret store and reference it from the integration.
3. Post messages with an incoming webhook or a bot token (`chat:write`). Add `users:read.email` only
   if you use `resolve_users_by_email`.

### Integration config

```json
{
  "name": "Slack #sec-actions",
  "kind": "slack",
  "topics": ["action.requested", "action.executed", "action.autonomous"],
  "config": {
    "mode": "webhook",
    "interactive": true,
    "user_map": {"U012ABCDEF": "alice@example.com"},
    "resolve_users_by_email": false,
    "allow_high_risk": false,
    "execute_on_approve": false,
    "team_id": "T0123456"
  },
  "secret_refs": {"webhook_url": "env:ARGUS_SECRET_SLACK_WEBHOOK", "signing_secret": "env:ARGUS_SECRET_SLACK_SIGNING"}
}
```

- `action.requested` messages for **pending** requests get **Approve** and **Deny** buttons.
- `action.executed` and `action.autonomous` messages for reversible actions get a **Roll back**
  button with a confirmation dialog.
- Every action message gets **Open in Argus**.
- `execute_on_approve`: when the click completes the approvals, queue execution as that user.
  This needs `actions:execute`.
- `team_id`: only accept clicks from that workspace.

### What a click does

1. **Signature**: Argus verifies the `X-Slack-Signature` v0 HMAC-SHA256 with the integration's
   signing secret, checks that `X-Slack-Request-Timestamp` is within 5 minutes, and rejects replays
   of the same signature. Any failure returns 401, with the same answer for an unknown integration,
   a disabled or non-interactive integration, or a bad signature.
2. **Identity**: the Slack user id is mapped through `user_map`. With `resolve_users_by_email`, Argus
   looks up the email with `users.info`. The result must be an active Argus user with a membership
   in the integration's tenant. The click then acts with that membership's role.
3. **Broker**: `approve`, `reject` or `rollback` run with that principal. Permissions, "a requester
   cannot approve their own request", distinct approvers, owner approval for critical, request
   expiry and kill switches all apply. A refusal is posted back to the user.
4. **Reply**: an ephemeral message goes to the click's `response_url`, and only when that is
   `https://hooks.slack.com/...`.
5. **Audit**: the click is audited as `slack.interaction` or `slack.interaction_refused`, with
   `via: slack` and the Slack user id. Approvals carry the comment `via Slack`.

### MFA trade-off

A Slack click is authenticated by Slack, not by an Argus login, so Argus MFA and session lifetime
do not apply. Anyone holding the linked Slack account can approve. For that reason:

- **High and critical actions cannot be decided or rolled back from Slack** unless the integration
  sets `allow_high_risk: true`. Those messages show only Open in Argus and a note to decide there.
- Separation of duty still holds: two Slack users mapped to the same Argus user count as one approver.
- Keep `user_map` small, require Slack SSO and 2FA in the workspace, and pin `team_id`.
