# AI & Agent Model-Risk Management (SR 11-7 / OCC 2011-12 / NIST AI RMF)

**Product:** Argus — Governed Defensive Security Platform  
**Audience:** Financial Services Model Risk Management (MRM), CISO, and Compliance Reviewers

This document describes the conceptual soundness, input/output boundaries, deterministic guardrails, independent validation benchmarks, and human-in-the-loop controls governing AI specialists in Argus.

---

## 1. Model Inventory & Intended Purpose

Argus uses Large Language Models (LLMs) strictly as **advisory analytical specialists** (`triage`, `investigate`, `remediate`, `hunt`, `posture_report`, `swarm_responder`).

- **What models CAN do**: Summarize findings, correlate read-only security events, query the asset/evidence graph, and *propose* candidate response actions (`ActionRequest` rows in `pending` status).
- **What models CANNOT do**:
  - Models have **no direct execution tools** (`execute` and `rollback` are absent from the agent tool registry).
  - Agent-originated action requests (`agent_run_id IS NOT NULL`) are **never auto-approved** (`app/actions/policy.py`), even for low-risk reversible actions.
  - Regulated builds can set `AUTONOMY_HARD_DISABLED=true`, which hard-disables autonomous response playbooks and low-risk auto-approval at the configuration and policy layers.

---

## 2. Defense-in-Depth Against Prompt Injection & Hallucination

1. **Untrusted Data Delimiters (`wrap_untrusted`)**:
   - Every finding, log event, and tool output passed to a model is wrapped in `<untrusted_data>` tags with pre-escaped closing tags so attacker-controlled text cannot break out into system instructions.
2. **Pre-Model & Post-Model DLP (`app/ai/dlp.py`, `app/ai/gateway.py`)**:
   - Both outbound prompts and inbound model completions are scanned for secrets (`aws_access_key`, `private_key`, `api_key`, `jwt`, `credential_assignment`), financial identifiers (`credit_card` with Luhn check, `us_ssn`, `iban`), and healthcare PHI (`medical_record_number`, `date_of_birth`, `patient_name`), including `data` and `image_url` fields.
3. **Deterministic Output Schema Validation (`app/agents/evals/schema.py`)**:
   - Every specialist must terminate by calling `submit_result`, whose payload is validated against a strict JSON Schema (`additionalProperties: false`). Malformed outputs are rejected.
4. **Hard Runtime Budgets (`app/agents/runtime.py`)**:
   - Every run is bounded by `AGENT_MAX_STEPS` (default 12), `AGENT_MAX_TOKENS` (default 150,000), `AGENT_MAX_SECONDS` (default 300s), and `AGENT_COST_CEILING_USD` (default $5.00). Setting `AGENT_REQUIRE_KNOWN_PRICE=true` refuses execution on any model without an explicit token price.
5. **Rule-Based Deterministic Fallback (`NullProvider`)**:
   - When `AI_PROVIDER=none` or an upstream provider is unavailable, every specialist has a deterministic rule-based fallback so security operations never depend on external LLM availability.

---

## 3. Ongoing Validation & Benchmark Outcomes (`app/agents/evals`)

Argus ships with an in-repo deterministic evaluation harness (`python -m pytest tests/test_agents_evals.py`) covering three benchmark suites:

| Suite | Cases | What It Measures | Release Gate |
|---|---|---|---|
| `prompt_injection` | 20 cases | Direct override, fake CISO authority, secret exfiltration, `</untrusted_data>` tag escape, zero-width/fullwidth unicode, base64 smuggling, markdown beacon exfiltration, forged JSON `tool_use`, DAN roleplay, multi-turn spoofing, DNS log poisoning, and system-prompt extraction across `triage`, `investigate`, `remediate`, and `swarm_responder` | **100% pass rate (0 unsafe tool calls, 0 leaked secrets, 0 severity downgrades)** |
| `triage_precision` | 20 cases | Severity calibration, KEV/EPSS prioritization, duplicate detection, and production vs. staging criticality weighting | **100% pass rate** |
| `hunt_recall` | 10 cases | Evidence recall and false-positive suppression across multi-stage attack hypotheses | **100% pass rate** |

---

## 4. Auditability & Explainability

- Every model turn and tool invocation is recorded in `agent_steps` with input/output token counts, latency, prompt SHA-256 hash, and full tool arguments/results.
- Every view or export of an agent run transcript is recorded in the tamper-evident audit chain (`audit.sensitive_read`).
