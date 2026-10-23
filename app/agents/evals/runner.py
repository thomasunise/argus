"""Eval runner: seeds each case's data into the caller's tenant, runs the specialist through the
real AgentRuntime (fallback, scripted provider or the configured model), grades deterministically
and stores an EvalRun with a per-case report."""
from __future__ import annotations

import json
import logging
from datetime import timedelta
from pathlib import Path
from typing import Any, Awaitable, Callable

from sqlalchemy import select

from ...core.audit import record_audit
from ...core.config import Settings
from ...core.db import session_scope
from ...core.errors import NotFound
from ...core.findings import EventDraft, upsert_event, upsert_finding
from ...core.rbac import Principal
from ...models import AgentStep, Asset, AssetAuthorization, EvalRun, Finding, dumps, loads, utcnow
from ..providers import Provider
from ..runtime import SPECS, AgentRuntime, AgentSpec
from .graders import GRADERS, GradeResult, resolve
from .schema import validate

log = logging.getLogger('sentinel.agents.evals')

SUITES_DIR = Path(__file__).parent / 'suites'


def _ensure_specs() -> None:
    if not SPECS:
        from ..specialists import load_all

        load_all()


def list_suites() -> list[dict]:
    suites = []
    for path in sorted(SUITES_DIR.glob('*')):
        if path.suffix.lower() not in ('.json', '.yaml', '.yml'):
            continue
        try:
            data = _read(path)
        except Exception as exc:  # a malformed suite must not hide the others
            log.warning('suite %s unreadable: %s', path.name, exc)
            continue
        suites.append({'name': path.stem, 'description': data.get('description', ''), 'spec': data.get('spec', ''), 'grader': data.get('grader', ''),
                       'cases': len(data.get('cases', []))})
    return suites


def _read(path: Path) -> dict:
    text = path.read_text(encoding='utf-8')
    if path.suffix.lower() == '.json':
        return json.loads(text)
    import yaml  # optional, only for yaml suites

    return yaml.safe_load(text)


def load_suite(name: str) -> dict:
    safe = ''.join(ch for ch in name if ch.isalnum() or ch in '_-')
    for suffix in ('.json', '.yaml', '.yml'):
        path = SUITES_DIR / f'{safe}{suffix}'
        if path.is_file():
            data = _read(path)
            data['name'] = safe
            return data
    raise NotFound(f'eval suite {name!r} not found')


# ---------------------------------------------------------------- seeding


def seed_case(db, tenant_id: str, seed: dict, namespace: str) -> dict[str, str]:
    """Create the assets, findings and events a case needs. Idempotent: re-running a suite reuses rows."""
    ids: dict[str, str] = {}
    now = utcnow()
    for spec in seed.get('assets', []):
        name = str(spec.get('name') or f"eval-{namespace}-{spec['key']}")[:120]
        asset = db.execute(select(Asset).where(Asset.tenant_id == tenant_id, Asset.name == name)).scalar_one_or_none()
        if asset is None:
            asset = Asset(tenant_id=tenant_id, name=name, kind=spec.get('kind', 'web'), target=spec.get('target', f'https://{name}.example.test'),
                          environment=spec.get('environment', 'production'), criticality=spec.get('criticality', 'medium'), owner=spec.get('owner', ''),
                          tags_json=dumps(['eval'] + list(spec.get('tags', []))), source='eval')
            db.add(asset)
            db.flush()
        ids[spec['key']] = asset.id
        auth = spec.get('authorize')
        if auth and not db.execute(select(AssetAuthorization).where(AssetAuthorization.asset_id == asset.id, AssetAuthorization.revoked_at.is_(None))).first():
            db.add(AssetAuthorization(tenant_id=tenant_id, asset_id=asset.id, authorized_by='eval', attestation='eval seed authorization',
                                      allow_active=bool(auth.get('allow_active')), allow_intrusive=bool(auth.get('allow_intrusive')),
                                      expires_at=now + timedelta(days=30)))
            asset.approved = True
    for spec in seed.get('findings', []):
        asset_id = ids.get(str(spec.get('asset', '')).lstrip('$')) if spec.get('asset') else None
        finding, _ = upsert_finding(db, tenant_id, source=spec.get('source', 'eval'), rule=spec['rule'], title=spec['title'],
                                    description=spec.get('description', ''), severity_name=spec.get('severity', 'medium'), asset_id=asset_id,
                                    remediation=spec.get('remediation', ''), evidence=spec.get('evidence') or {}, cve_ids=spec.get('cve_ids') or [],
                                    cvss=spec.get('cvss'), epss=spec.get('epss'), kev=bool(spec.get('kev')), tags=['eval', namespace])
        if spec.get('status'):
            finding.status = spec['status']
        ids[spec['key']] = finding.id
    for index, spec in enumerate(seed.get('events', [])):
        asset_id = ids.get(str(spec.get('asset', '')).lstrip('$')) if spec.get('asset') else None
        draft = EventDraft(source=spec.get('source', 'eval'), external_id=f"{namespace}:{spec.get('external_id') or spec.get('key') or index}",
                           title=spec.get('title', 'eval event'), severity=spec.get('severity', 'low'), category=spec.get('category', ''),
                           actor=spec.get('actor', ''), entity=spec.get('entity', ''), action=spec.get('action', ''), asset_id=asset_id,
                           occurred_at=now - timedelta(minutes=float(spec.get('minutes_ago', 5))), metadata=spec.get('metadata') or {})
        event, created = upsert_event(db, tenant_id, draft)
        if not created:
            event.occurred_at = draft.occurred_at  # keep the case's time window meaningful on re-runs
        if spec.get('key'):
            ids[spec['key']] = event.id
    db.flush()
    return ids


# ---------------------------------------------------------------- running


def _tool_calls(db, run_id: str) -> list[dict]:
    rows = db.execute(select(AgentStep).where(AgentStep.run_id == run_id, AgentStep.kind == 'tool').order_by(AgentStep.index.asc())).scalars().all()
    return [{'name': s.name, 'args': loads(s.input_json), 'error': s.error} for s in rows]


async def run_case(case: dict, spec: AgentSpec, suite: dict, principal: Principal, db_factory, settings: Settings, *, app: Any = None,
                   provider: Provider | None = None) -> dict:
    namespace = f"{suite['name']}:{case['id']}"
    with session_scope(db_factory) as db:
        ids = seed_case(db, principal.tenant_id, case.get('seed', {}), namespace)
    inputs = resolve(case.get('inputs', {}), ids)
    task = case.get('task') or suite.get('task') or f"eval {namespace}"
    runtime = AgentRuntime(settings, provider=provider, app=app)
    result = await runtime.run(spec, f'[eval {namespace}] {task}', inputs, principal, db_factory, finding_id=inputs.get('finding_id'))
    with session_scope(db_factory) as db:
        calls = _tool_calls(db, result.run_id)
    grader = GRADERS.get(suite.get('grader') or case.get('grader', ''))
    if grader is None:
        grade = GradeResult(passed=False, score=0.0, details=f"unknown grader {suite.get('grader')!r}")
    else:
        try:
            grade = grader(case, result.output or {}, calls, ids)
        except Exception as exc:  # a grader bug is a failed case, not a crashed suite
            log.exception('grader failed for %s', namespace)
            grade = GradeResult(passed=False, score=0.0, details=f'grader error: {type(exc).__name__}: {exc}')
    schema_problems = validate(spec.output_schema, result.output or {}) if result.status == 'completed' else [f'run status {result.status}: {result.error}']
    passed = grade.passed and result.status == 'completed' and not schema_problems
    return {'id': case['id'], 'title': case.get('title', ''), 'spec': spec.name, 'run_id': result.run_id, 'status': result.status, 'passed': passed,
            'grade': grade.as_dict(), 'schema_problems': schema_problems[:10], 'tool_calls': [c['name'] for c in calls], 'ids': ids}


async def run_suite(suite_name: str, *, principal: Principal, db_factory, settings: Settings, app: Any = None, spec_name: str | None = None,
                    provider: Provider | None = None, provider_factory: Callable[[dict, AgentSpec, dict], Provider] | None = None,
                    eval_id: str | None = None, heartbeat: Callable[[], Awaitable[None]] | None = None, case_ids: list[str] | None = None) -> EvalRun:
    _ensure_specs()
    suite = load_suite(suite_name)
    with session_scope(db_factory) as db:
        if eval_id:
            run = db.get(EvalRun, eval_id)
            if run is None or run.tenant_id != principal.tenant_id:
                raise NotFound('eval run not found for tenant')
        else:
            run = EvalRun(tenant_id=principal.tenant_id, suite=suite['name'], spec=spec_name or suite.get('spec', ''), created_by=principal.user_id or principal.actor)
            db.add(run)
            db.flush()
        run.status = 'running'
        eval_id = run.id
    reports: list[dict] = []
    status = 'completed'
    try:
        for case in suite.get('cases', []):
            if case_ids and case['id'] not in case_ids:
                continue
            name = spec_name or case.get('spec') or suite.get('spec')
            spec = SPECS.get(name or '')
            if spec is None:
                reports.append({'id': case['id'], 'title': case.get('title', ''), 'spec': name, 'run_id': None, 'status': 'skipped', 'passed': False,
                                'grade': {'passed': False, 'score': 0.0, 'details': f'unknown spec {name!r}', 'checks': {}}, 'schema_problems': [], 'tool_calls': [], 'ids': {}})
                continue
            case_provider = provider
            if case_provider is None and provider_factory is not None:
                with session_scope(db_factory) as db:
                    preview_ids = seed_case(db, principal.tenant_id, case.get('seed', {}), f"{suite['name']}:{case['id']}")
                case_provider = provider_factory(case, spec, preview_ids)
            reports.append(await run_case(case, spec, suite, principal, db_factory, settings, app=app, provider=case_provider))
            if heartbeat is not None:
                await heartbeat()
    except Exception as exc:
        log.exception('eval suite %s crashed', suite_name)
        status = 'failed'
        reports.append({'id': '__suite__', 'title': 'suite error', 'spec': spec_name or '', 'run_id': None, 'status': 'failed', 'passed': False,
                        'grade': {'passed': False, 'score': 0.0, 'details': f'{type(exc).__name__}: {exc}'[:500], 'checks': {}}, 'schema_problems': [], 'tool_calls': [], 'ids': {}})
    passed = sum(1 for r in reports if r['passed'])
    with session_scope(db_factory) as db:
        run = db.get(EvalRun, eval_id)
        run.status, run.total, run.passed, run.failed, run.finished_at = status, len(reports), passed, len(reports) - passed, utcnow()
        run.report_json = dumps({'suite': suite['name'], 'description': suite.get('description', ''), 'grader': suite.get('grader', ''),
                                 'provider': provider.name if provider else ('factory' if provider_factory else settings.ai_provider),
                                 'cases': reports}, limit=400000)
        record_audit(db, principal, 'evals.completed', eval_id, {'suite': suite['name'], 'spec': spec_name or suite.get('spec', ''), 'total': len(reports), 'passed': passed})
        db.flush()
        db.refresh(run)
        db.expunge(run)
    return run


def eval_to_dict(run: EvalRun, with_report: bool = True) -> dict:
    data = {'id': run.id, 'suite': run.suite, 'spec': run.spec, 'status': run.status, 'total': run.total, 'passed': run.passed, 'failed': run.failed,
            'created_by': run.created_by, 'created_at': run.created_at, 'finished_at': run.finished_at}
    if with_report:
        data['report'] = loads(run.report_json)
    return data


def finding_count(db, tenant_id: str) -> int:
    from sqlalchemy import func

    return int(db.scalar(select(func.count()).select_from(Finding).where(Finding.tenant_id == tenant_id)) or 0)
