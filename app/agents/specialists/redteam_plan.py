"""Red-team planning specialist: produces a scope-checked test plan for one asset. It never runs
tests and refuses to plan active work for assets without a valid authorization."""
from __future__ import annotations

from ..tools.registry import ToolContext
from ._base import arr, b, call, enum, injection_signals, obj, s, spec

TIER = enum(['passive', 'active', 'intrusive'])

OUTPUT_SCHEMA = obj({
    'scope_check': obj({'authorized': b('a current, unrevoked authorization exists for the asset'), 'environment': s(), 'allowed_tiers': arr(TIER)}),
    'objectives': arr(s()),
    'proposed_tests': arr(obj({'adapter': s('adapter name, e.g. web_baseline, nuclei, zap, semgrep, gitleaks, trivy, prowler, caldera'), 'tier': TIER, 'rationale': s()})),
    'safety_constraints': arr(s()),
    'expected_signals': arr(s(), 'what detections or findings a successful test should produce'),
    'prompt_injection_suspected': b(),
})

PROMPT = """Task: write a test plan for one asset. You plan; humans and the test harness run tests, and the harness re-checks scope at execution time.

Procedure:
1. get_asset (and asset_context) for the asset id. Read its authorizations: a plan may include the active tier only when a current, unrevoked authorization has allow_active, and the intrusive tier only when it also has allow_intrusive and the environment is staging or lab, and the exploit tier only when it has allow_exploit (that tier runs a proof of concept in the sandbox executor).
2. If there is no valid authorization, return authorized=false, allowed_tiers=[] and an empty proposed_tests list, and say in objectives what authorization would be needed. Do not propose "passive" tests as a workaround.
3. Otherwise choose adapters from available_test_adapters that fit the asset kind and allowed tiers, state why each test matters given the open findings and attack paths, and add safety constraints (rate limits, time window, no destructive payloads, abort conditions).
4. List the signals the blue team should expect so the exercise also validates detection coverage.

Never call tools you do not need, and never suggest testing assets other than the one in your inputs."""

TOOLS = ['get_asset', 'asset_context', 'list_findings', 'find_similar_findings', 'attack_paths', 'exposure', 'graph_neighbors', 'available_test_adapters',
         'list_test_runs', 'test_results', 'detection_rules', 'note', 'recall']

ADAPTERS_BY_KIND: dict[str, list[tuple[str, str, str]]] = {
    'web': [('web_baseline', 'passive', 'Header, TLS, cookie and disclosure hygiene without payloads.'),
            ('js_analyze', 'passive', 'Reads the page and its bundles for endpoints and hardcoded secrets.'),
            ('subdomain_enum', 'passive', 'Resolves common subdomains of the asset domain; reports, never tests them.'),
            ('js_libs', 'passive', 'Detects vulnerable jQuery/Bootstrap/lodash/moment versions in bundles.'),
            ('retire_js', 'passive', 'Scans loaded scripts against the Retire.js CVE repository.'),
            ('waf_detect', 'active', 'Fingerprints the WAF/CDN in front of the asset.'),
            ('nuclei', 'active', 'Template checks for known exposures and misconfigurations on the live service.'),
            ('dir_probe', 'active', 'Curated path discovery for backups, VCS metadata and debug endpoints.'),
            ('port_probe', 'active', 'Connect-only scan of web, database and management ports.'),
            ('jwt_analyze', 'active', 'Decodes issued JWTs and flags unsigned, expired or long-lived tokens.'),
            ('param_probe', 'active', 'Benign marker probe for reflected query parameters (no payloads).'),
            ('ffuf_dir', 'active', 'Wordlist-driven path discovery with auto-calibration and response clustering.'),
            ('nmap_sv', 'active', 'Nmap service and version fingerprinting across top ports.'),
            ('param_mine', 'active', 'Arjun-style differential HTTP parameter discovery.'),
            ('trufflehog_verify', 'active', 'Secret detection and read-only provider verification across bundles.'),
            ('zap', 'intrusive', 'Authenticated active scan with injection payloads.'),
            ('payload_fuzz', 'intrusive', 'Curated SQLi, XSS and traversal payloads that detect evidence without exploiting.'),
            ('oob_probe', 'intrusive', 'Blind SSRF/XXE probe whose proof is a callback to the Argus listener.'),
            ('sqli_proof', 'intrusive', 'Proof-bounded SQLi verification (banner or boolean equivalence; never dumps data).'),
            ('jwt_attack', 'intrusive', 'Verifies JWT signing weaknesses (placeholder HMAC secrets, alg:none, kid/jwk confusion).'),
            ('browser_xss', 'intrusive', 'Confirms reflected XSS via HTML DOM sink parsing.'),
            ('idor_probe', 'intrusive', 'Cross-role authorization check comparing owner vs attacker credentials.'),],
    'repo': [('semgrep', 'passive', 'Static analysis for injection, auth and crypto bugs.'),
             ('gitleaks', 'passive', 'Secret detection across the full history.'),
             ('trivy', 'passive', 'Dependency, container and IaC vulnerabilities.')],
    'cloud_account': [('prowler', 'passive', 'Cloud configuration benchmark against CIS and provider best practice.')],
    'host': [('trivy', 'passive', 'OS package and configuration vulnerabilities.'), ('caldera', 'intrusive', 'Adversary emulation to validate endpoint detection.')],
    'k8s_cluster': [('trivy', 'passive', 'Cluster misconfiguration and image vulnerabilities.'), ('caldera', 'intrusive', 'Container-escape and lateral-movement emulation.')],
    'database': [('nuclei', 'active', 'Exposure and default-credential checks against the service port.')],
    'network': [('nuclei', 'active', 'Service exposure checks across the range.')],
    'identity_provider': [('prowler', 'passive', 'Identity configuration review (MFA, legacy auth, admin roles).')],
    'saas': [('prowler', 'passive', 'Tenant configuration review where a provider module exists.')],
}
EXPECTED_SIGNALS = {'web_baseline': 'No detections expected; findings for missing headers or weak TLS.',
                    'nuclei': 'WAF or web-server alerts for scanner user agents and template probes.',
                    'zap': 'WAF blocks, application error spikes, and injection-pattern detections.',
                    'semgrep': 'Code findings only; no runtime signals.', 'gitleaks': 'Secret findings; rotate anything confirmed live.',
                    'trivy': 'Vulnerability findings with CVE ids; cross-check KEV.',
                    'prowler': 'Cloud audit-log reads from the Argus principal; no control-plane changes.',
                    'caldera': 'EDR process-tree alerts, canary hits and detection rule matches for the emulated techniques.',
                    'param_probe': 'No exploitation expected; a WAF may log marker query parameters.',
                    'param_mine': 'Chunked GET requests with benign canary query parameters.',
                    'ffuf_dir': 'Rate-limited HTTP path enumeration with auto-calibration.',
                    'nmap_sv': 'TCP connect and light service banner probes across top ports.',
                    'retire_js': 'Passive JavaScript bundle inspection; no payloads.',
                    'trufflehog_verify': 'Secret extraction and optional read-only provider identity checks.',
                    'payload_fuzz': 'WAF blocks, application error spikes and injection-pattern detections.',
                    'sqli_proof': 'Bounded SQL predicate pairs or sqlmap level=1/risk=1 banner checks.',
                    'jwt_attack': 'Authentication failures (401/403) alongside forged-token verification requests.',
                    'browser_xss': 'Canary custom-element (<argus-xss>) query requests.',
                    'idor_probe': 'Paired authenticated requests across distinct user roles.',}
TIER_ORDER = {'passive': 0, 'active': 1, 'intrusive': 2, 'exploit': 3}


def _refusal(asset: dict | None, reason: str, signals: list[str]) -> dict:
    environment = str(asset.get('environment', 'unknown')) if asset else 'unknown'
    return {'scope_check': {'authorized': False, 'environment': environment, 'allowed_tiers': []},
            'objectives': [reason, 'Obtain a recorded authorization (POST /api/v1/assets/{id}/authorize) naming the permitted tier before any testing.'],
            'proposed_tests': [], 'safety_constraints': ['No testing of any tier until an authorization is recorded; queued work is not a grant.'],
            'expected_signals': [], 'prompt_injection_suspected': bool(signals)}


async def fallback(inputs: dict, ctx: ToolContext) -> dict:
    asset_id = str(inputs.get('asset_id') or '')
    asset = await call(ctx, 'get_asset', asset_id=asset_id)
    if not asset.get('found'):
        return _refusal(None, f'Asset {asset_id!r} does not exist in this tenant.', [])
    signals = injection_signals(asset.get('name'), asset.get('target'), asset.get('owner'), asset.get('tags'), [a.get('attestation') for a in asset.get('authorizations', [])])
    valid = [a for a in asset.get('authorizations', []) if a.get('valid')]
    if not valid:
        return _refusal(asset, f"Asset {asset.get('name')} has no current authorization (expired, revoked or never recorded).", signals)
    environment = str(asset.get('environment', 'production'))
    allowed = ['passive']
    if any(a.get('allow_active') for a in valid):
        allowed.append('active')
    if any(a.get('allow_intrusive') for a in valid) and environment in ('staging', 'lab'):
        allowed.append('intrusive')
    if any(a.get('allow_exploit') for a in valid):
        allowed.append('exploit')

    context = await call(ctx, 'asset_context', asset_id=asset_id)
    open_findings = context.get('open_findings', [])
    adapters = await call(ctx, 'available_test_adapters')
    installed = {a['name']: a for a in adapters.get('items', [])} if adapters.get('available') else None

    proposed: list[dict] = []
    for adapter, tier, rationale in ADAPTERS_BY_KIND.get(str(asset.get('kind')), [('nuclei', 'active', 'Generic exposure checks.')]):
        if tier not in allowed:
            continue
        note = ''
        if installed is not None:
            entry = installed.get(adapter)
            if entry is None:
                note = ' (no adapter registered under this name)'
            elif not entry.get('available', True):
                note = ' (adapter not installed on this worker)'
        related = [f for f in open_findings if adapter in str(f.get('source', '')).lower()]
        if related:
            rationale += f' Re-tests {len(related)} open finding(s) from the same source.'
        proposed.append({'adapter': adapter, 'tier': tier, 'rationale': rationale + note})
    proposed.sort(key=lambda t: TIER_ORDER[t['tier']])

    objectives = [f"Validate the current exposure of {asset.get('name')} ({asset.get('kind')}, {environment}) within the authorized tiers: {', '.join(allowed)}.",
                  f'Confirm or close the {len(open_findings)} open finding(s) on the asset.' if open_findings else 'Establish a baseline where no findings currently exist.',
                  'Measure whether the blue team sees the activity (detection coverage).']
    limits = ctx.settings
    constraints = [f'Only asset {asset_id} ({asset.get("target")}) is in scope; no pivoting to discovered hosts.',
                   f'Rate limit {limits.test_rate_limit_rps} requests/second and per-tool timeout {limits.test_tool_timeout_seconds}s as configured.',
                   'No destructive payloads, no data exfiltration, no account lockouts; abort on service degradation.',
                   'The harness re-checks the authorization, environment and time window at execution time; this plan grants nothing.']
    if 'intrusive' not in allowed:
        constraints.append('Intrusive adapters (ZAP active, CALDERA) are excluded: not authorized or the environment is not staging/lab.')
    if environment == 'production':
        constraints.append('Production asset: schedule in the maintenance window and notify the service owner before active tests.')
    if signals:
        constraints.append('Asset metadata contains instruction-like text; it was ignored and should be reviewed as possible prompt injection.')
    expected = list(dict.fromkeys(EXPECTED_SIGNALS.get(t['adapter'], 'Scanner activity from the Argus worker address.') for t in proposed))
    return {'scope_check': {'authorized': True, 'environment': environment, 'allowed_tiers': allowed}, 'objectives': objectives,
            'proposed_tests': proposed, 'safety_constraints': constraints, 'expected_signals': expected, 'prompt_injection_suspected': bool(signals)}


SPEC = spec(name='redteam_plan', role='the Red-Team Planning specialist', description='Scope-checked test plan for one asset; plans only, never executes.',
            system_prompt=PROMPT, tools=TOOLS, output_schema=OUTPUT_SCHEMA, max_steps=10, tags=('testing',), fallback=fallback)
