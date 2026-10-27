# Governed Strix engine

Argus can run [Strix](https://github.com/usestrix/strix) as an offensive engine without giving it
the run of your estate. Strix supplies the thing Argus does not have - autonomous discovery and
exploit development - and Argus supplies the thing Strix does not have: an authorization envelope,
a kill switch, pinned egress, an audit chain and evidence-bound findings.

Strix is Apache-2.0. The engine image is built from `sandbox/strix.Dockerfile`; it is not vendored.

## How a run works

```
Argus test run (tier exploit)
  -> StrixAdapter renders an engine envelope (image, argv, env, egress, limits)
  -> executor POST /v1/engine   (engine profile: digest-pinned allowlisted image, <=4 pinned /32 egress)
  -> Kubernetes Job (gVisor, non-root, read-only root, emptyDir workspace)
  -> sandbox/strix_runner.py runs `strix -n --target ... --max-budget ...`
  -> wrapper normalizes the newest report into ARGUS_FINDINGS lines
  -> adapter maps them to findings (PoC text kept as evidence)
```

The adapter is only reachable at tier `exploit`, so the same gates as PoC execution apply:
the scope must list `exploit`, the asset must carry an authorization with `allow_exploit`, staging
and lab are the default environments, and production additionally needs a signed scope document
reference.

## Configuration

```yaml
config:
  EXPLOIT_ENABLED: "true"
  EXPLOIT_EXECUTOR_URL: "http://argus-sandbox-executor:8080"
  EXPLOIT_SANDBOX_IMAGE: "ghcr.io/thomasunise/argus-sandbox@sha256:<digest>"
  STRIX_ENABLED: "true"
  STRIX_IMAGE: "ghcr.io/thomasunise/argus-strix@sha256:<digest>"   # must be digest-pinned
  STRIX_MODEL: "openrouter/z-ai/glm-5.3"
  STRIX_MAX_BUDGET_USD: "25"
  STRIX_MAX_WALL_SECONDS: "3600"
  STRIX_EGRESS_HOSTS: "api.anthropic.com,api.openai.com,openrouter.ai"
secrets:
  strixLlmApiKey: "<provider key>"
sandbox:
  enabled: true
  executor:
    token: "<32+ random chars>"
```

The executor must also allowlist the engine image, otherwise it refuses every engine job:

```
SANDBOX_ENGINE_IMAGES=ghcr.io/thomasunise/argus-strix@sha256:<digest>
SANDBOX_ENGINE_MAX_WALL_SECONDS=14400
```

## What the containment actually guarantees

- **Image allowlist.** The executor refuses any engine image that is not digest-pinned and listed in
  `SANDBOX_ENGINE_IMAGES`. An empty allowlist means no engine runs at all.
- **Egress is a short list of /32 destinations** (the asset plus the model provider), never a range;
  metadata, loopback and the unspecified address are rejected.
- **No host access.** gVisor runtime class, no host namespaces, no `hostPath`, all capabilities
  dropped, read-only root filesystem, writable scratch only in an `emptyDir`.
- **Budget and clock.** `STRIX_MAX_BUDGET_USD` is passed to Strix and `activeDeadlineSeconds`
  bounds the pod; the executor also caps the deadline.

## Known limitations (read before enabling)

1. **Nested sandbox.** Strix normally runs its own Docker sandbox. Inside the engine pod there is
   no Docker daemon, so the pod *is* the sandbox. If your Strix version needs flags for that mode,
   set `STRIX_EXTRA_ARGS`; otherwise the run fails loudly rather than silently degrading.
2. **Report format drift.** `sandbox/strix_runner.py` is the only file that knows Strix's on-disk
   layout; it tries `strix_runs/**/*.json` and the common `findings`/`vulnerabilities` shapes. A
   Strix release that changes its report will produce zero findings until the wrapper is updated -
   it will not produce wrong ones.
3. **Model cost.** A deep Strix run can spend real money. The budget is a cap, not an estimate.
4. **Attribution.** Findings arrive as `source=strix` with the PoC text in evidence. Argus marks
   them as findings; it does not re-verify them through the PoC verifier automatically. Pair a
   Strix run with `poc_author` when you want `validation_status=verified`.
