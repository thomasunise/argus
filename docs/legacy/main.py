from __future__ import annotations

import asyncio
import csv
import io
import json
import secrets
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from .audit import record_audit, verify_audit_chain
from .config import Settings, assert_safe_config, get_settings
from .database import init_db, make_db, session_scope
from .findings import add_event, add_finding, correlate_event, import_trivy, normalize_falco, normalize_wazuh
from .intelligence import investigate
from .models import Approval, Asset, AuditEntry, Finding, Investigation, ScanRun, SecurityEvent, utcnow
from .policy import PolicyDenied, check_scan_permission, validate_repo_target, validate_web_target
from .scanners import trivy_repo_scan, web_baseline_scan

STATIC_DIR = Path(__file__).parent / 'static'


def as_dict(model, *fields):
    result = {}
    for field in fields:
        value = getattr(model, field)
        result[field] = value.isoformat() + ('Z' if value.tzinfo is None else '') if isinstance(value, datetime) else value
    return result


ASSET_FIELDS = ('id','name','kind','target','environment','approved','created_at','last_scan_at')
FINDING_FIELDS = ('id','asset_id','title','description','remediation','severity','status','source','occurrences','created_at','updated_at','evidence')
RUN_FIELDS = ('id','asset_id','scanner','status','result_count','error','created_at','completed_at')
EVENT_FIELDS = ('id','source','external_id','asset_id','title','severity','metadata_json','received_at')


class LoginBody(BaseModel):
    password: str


class AssetBody(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    kind: str = Field(pattern='^(web|repo|host|cloud|database)$')
    target: str = Field(min_length=2, max_length=512)
    environment: str = Field(default='production', pattern='^(production|staging|development)$')


class ApproveBody(BaseModel):
    attestation: bool


class ScanBody(BaseModel):
    asset_id: str
    scanner: str = 'web-baseline'


class ChangeStatus(BaseModel):
    status: str = Field(pattern='^(open|investigating|resolved|accepted)$')


class ApprovalRequest(BaseModel):
    finding_id: str
    action: str = Field(pattern='^(isolate_endpoint|revoke_credential|deploy_patch|change_firewall)$')
    rationale: str = Field(min_length=8, max_length=800)


class ApprovalDecision(BaseModel):
    decision: str = Field(pattern='^(approved|denied)$')


def create_app(settings: Settings | None = None) -> FastAPI:
    config = settings or get_settings()
    assert_safe_config(config)
    engine, factory = make_db(config.database_url)
    init_db(engine)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        worker = None
        if config.autoscan_enabled:
            worker = asyncio.create_task(periodic_scan_loop(app))
        yield
        if worker:
            worker.cancel()
            try:
                await worker
            except asyncio.CancelledError:
                pass
        for task in list(app.state.jobs.values()):
            task.cancel()
        engine.dispose()

    app = FastAPI(title='Sentinel Agentic Security', version='0.1.0', lifespan=lifespan)
    app.state.settings = config
    app.state.factory = factory
    app.state.jobs = {}
    app.state.login_attempts = {}
    app.add_middleware(SessionMiddleware, secret_key=config.session_secret, session_cookie='sentinel_session',
                       same_site='strict', https_only=config.cookie_secure, max_age=3600)

    def db_session():
        db = factory()
        try:
            yield db
        finally:
            db.close()

    def require_admin(request: Request):
        if request.session.get('authed') is not True:
            raise HTTPException(status_code=401, detail='Authentication required')
        if request.method not in {'GET', 'HEAD', 'OPTIONS'}:
            given = request.headers.get('x-csrf-token', '')
            expected = request.session.get('csrf', '')
            if not expected or not secrets.compare_digest(given, expected):
                raise HTTPException(status_code=403, detail='CSRF validation failed')
        return 'admin'

    def require_ingest(x_ingest_key: str = Header(default='')):
        if not secrets.compare_digest(x_ingest_key, config.ingest_api_key):
            raise HTTPException(status_code=401, detail='Invalid ingestion token')
        return 'sensor'

    @app.get('/')
    def index():
        return FileResponse(STATIC_DIR / 'index.html')

    @app.get('/static/{file_name}')
    def static(file_name: str):
        if file_name not in {'app.js', 'styles.css'}:
            raise HTTPException(404)
        return FileResponse(STATIC_DIR / file_name)

    @app.get('/health')
    def health():
        return {'status':'healthy','version':'0.1.0'}

    @app.get('/api/session')
    def session(request: Request):
        authorized = request.session.get('authed') is True
        return {'authenticated':authorized, 'csrf':request.session.get('csrf') if authorized else None}

    @app.post('/api/login')
    def login(body: LoginBody, request: Request):
        # In-process throttle. Terminate TLS and add edge-level throttling in production.
        client_id = request.client.host if request.client else 'unknown'
        now = time.monotonic()
        attempts = [x for x in app.state.login_attempts.get(client_id, []) if now - x < 300]
        if len(attempts) >= 8:
            raise HTTPException(status_code=429, detail='Too many attempts, try again later')
        if not secrets.compare_digest(body.password.encode(), config.admin_password.encode()):
            attempts.append(now)
            app.state.login_attempts[client_id] = attempts
            raise HTTPException(status_code=401, detail='Invalid credentials')
        app.state.login_attempts.pop(client_id, None)
        request.session.clear()
        request.session['authed'] = True
        request.session['csrf'] = secrets.token_urlsafe(32)
        return {'authenticated': True, 'csrf':request.session['csrf']}

    @app.post('/api/logout')
    def logout(request: Request, _=Depends(require_admin)):
        request.session.clear()
        return {'ok': True}

    @app.get('/api/settings')
    def public_settings(_=Depends(require_admin)):
        return {
            'ai_provider': config.ai_provider, 'ai_model': {'ollama':config.ollama_model, 'openai':config.openai_model,
                          'anthropic':config.anthropic_model}.get(config.ai_provider, 'rules-only'),
            'autoscan_enabled':config.autoscan_enabled, 'autoscan_minutes':config.autoscan_minutes,
            'trivy_enabled': config.enable_trivy, 'wazuh_configured':bool(config.wazuh_indexer_url),
            'private_targets_enabled':config.allow_private_targets,
        }

    @app.get('/api/dashboard')
    def dashboard(db: Session = Depends(db_session), _=Depends(require_admin)):
        assets = db.scalar(select(func.count()).select_from(Asset)) or 0
        approved = db.scalar(select(func.count()).select_from(Asset).where(Asset.approved.is_(True))) or 0
        open_findings = db.scalar(select(func.count()).select_from(Finding).where(Finding.status.in_(['open','investigating']))) or 0
        critical = db.scalar(select(func.count()).select_from(Finding).where(Finding.status.in_(['open','investigating']), Finding.severity=='critical')) or 0
        events = db.scalar(select(func.count()).select_from(SecurityEvent)) or 0
        last = db.execute(select(ScanRun).order_by(ScanRun.created_at.desc()).limit(1)).scalar_one_or_none()
        severities = {level: (db.scalar(select(func.count()).select_from(Finding).where(Finding.severity==level,
                   Finding.status.in_(['open','investigating']))) or 0) for level in ['critical','high','medium','low','informational']}
        recent = db.execute(select(SecurityEvent).order_by(SecurityEvent.received_at.desc()).limit(6)).scalars().all()
        return {'assets':assets, 'approved_assets':approved, 'open_findings':open_findings, 'critical':critical,
                'events':events, 'severity_counts':severities,
                'last_scan':as_dict(last, *RUN_FIELDS) if last else None,
                'recent_events':[as_dict(x, *EVENT_FIELDS) for x in recent]}

    @app.get('/api/assets')
    def assets(db: Session = Depends(db_session), _=Depends(require_admin)):
        return [as_dict(a, *ASSET_FIELDS) for a in db.execute(select(Asset).order_by(Asset.created_at.desc())).scalars()]

    @app.post('/api/assets', status_code=201)
    def create_asset(body: AssetBody, db: Session = Depends(db_session), _=Depends(require_admin)):
        if body.kind == 'web':
            try:
                validate_web_target(body.target, config, resolve=False)
            except PolicyDenied as exc:
                raise HTTPException(400, detail=str(exc)) from exc
        if body.kind == 'repo' and ('..' in Path(body.target).parts or Path(body.target).is_absolute()):
            raise HTTPException(400, detail='Use relative repository path below SCAN_ROOT')
        asset = Asset(name=body.name, kind=body.kind, target=body.target, environment=body.environment, approved=False)
        db.add(asset)
        db.flush()
        record_audit(db, 'admin', 'asset.created', asset.id, asset.name)
        db.commit()
        return as_dict(asset, *ASSET_FIELDS)

    @app.post('/api/assets/{asset_id}/approve')
    def approve_asset(asset_id: str, body: ApproveBody, db: Session = Depends(db_session), _=Depends(require_admin)):
        if not body.attestation:
            raise HTTPException(403, detail='Explicit authorization attestation required')
        asset = db.get(Asset, asset_id)
        if not asset:
            raise HTTPException(404, detail='Asset not found')
        try:
            if asset.kind == 'web':
                validate_web_target(asset.target, config)
            elif asset.kind == 'repo':
                validate_repo_target(asset.target, config)
        except PolicyDenied as exc:
            raise HTTPException(403, detail=str(exc)) from exc
        asset.approved = True
        record_audit(db, 'admin', 'asset.approved', asset.id, 'Administrator attested control of asset')
        db.commit()
        return as_dict(asset, *ASSET_FIELDS)

    @app.delete('/api/assets/{asset_id}')
    def delete_asset(asset_id: str, db: Session = Depends(db_session), _=Depends(require_admin)):
        asset = db.get(Asset, asset_id)
        if not asset:
            raise HTTPException(404, detail='Asset not found')
        # Keep evidence and history; detach records before deleting the inventory row.
        for model in (Finding, SecurityEvent):
            for row in db.execute(select(model).where(model.asset_id == asset_id)).scalars():
                row.asset_id = None
        if db.scalar(select(func.count()).select_from(ScanRun).where(ScanRun.asset_id==asset_id)):
            raise HTTPException(409, detail='This asset has scan history; preserve it for audit integrity')
        record_audit(db, 'admin', 'asset.deleted', asset.id, asset.name)
        db.delete(asset)
        db.commit()
        return {'ok':True}

    async def execute_scan(run_id: str):
        with session_scope(factory) as db:
            run = db.get(ScanRun, run_id)
            asset = db.get(Asset, run.asset_id)
            if not asset:
                run.status, run.error, run.completed_at = 'failed', 'Asset no longer exists', utcnow()
                return
            run.status = 'running'
            aid, target, scanner_name = asset.id, asset.target, run.scanner
        try:
            # Permission verified AGAIN at execution time; the queued scan is not a grant.
            with session_scope(factory) as db:
                asset = db.get(Asset, aid)
                check_scan_permission(asset, scanner_name, config)
            if scanner_name == 'web-baseline':
                items = await web_baseline_scan(target, config)
                with session_scope(factory) as db:
                    for item in items:
                        add_finding(db, asset_id=aid, source='web-baseline', **item)
            else:
                report = await trivy_repo_scan(target, config)
                with session_scope(factory) as db:
                    count = import_trivy(db, report, aid)
                items = [None] * count
            with session_scope(factory) as db:
                run = db.get(ScanRun, run_id)
                run.status, run.result_count, run.completed_at = 'completed', len(items), utcnow()
                asset = db.get(Asset, aid)
                if asset:
                    asset.last_scan_at = utcnow()
                record_audit(db, 'scanner', 'scan.completed', run.id, f'{scanner_name}: {len(items)} findings')
        except Exception as exc:
            with session_scope(factory) as db:
                run = db.get(ScanRun, run_id)
                run.status, run.completed_at = 'failed', utcnow()
                # Don't expose credentials, URLs or raw tool output in recorded errors.
                run.error = f'{type(exc).__name__}: scan failed; inspect restricted server logs' if not isinstance(exc, PolicyDenied) else str(exc)
                record_audit(db, 'scanner', 'scan.failed', run.id, type(exc).__name__)
        finally:
            app.state.jobs.pop(run_id, None)

    def queue_scan(asset_id: str, scanner_name: str) -> dict:
        with session_scope(factory) as db:
            asset = db.get(Asset, asset_id)
            if not asset:
                raise HTTPException(404, detail='Asset not found')
            try:
                check_scan_permission(asset, scanner_name, config)
            except PolicyDenied as exc:
                raise HTTPException(403, detail=str(exc)) from exc
            current = db.execute(select(ScanRun).where(ScanRun.asset_id==asset_id,
                              ScanRun.status.in_(['queued','running']))).scalar_one_or_none()
            if current:
                raise HTTPException(409, detail='A scan is already in progress for this asset')
            run = ScanRun(asset_id=asset_id, scanner=scanner_name, status='queued')
            db.add(run)
            db.flush()
            record_audit(db, 'admin', 'scan.queued', run.id, f'{asset_id}:{scanner_name}')
            out = as_dict(run, *RUN_FIELDS)
        task = asyncio.create_task(execute_scan(out['id']))
        app.state.jobs[out['id']] = task
        return out

    async def periodic_scan_loop(app: FastAPI):
        await asyncio.sleep(15)
        while True:
            try:
                with session_scope(factory) as db:
                    limit = utcnow() - timedelta(minutes=config.autoscan_minutes)
                    candidates = [a.id for a in db.execute(select(Asset).where(Asset.kind=='web', Asset.approved.is_(True))).scalars()
                                  if not a.last_scan_at or a.last_scan_at.replace(tzinfo=timezone.utc) < limit]
                for aid in candidates[:20]:
                    try:
                        queue_scan(aid, 'web-baseline')
                    except HTTPException:
                        pass
            except Exception:
                pass
            await asyncio.sleep(max(config.autoscan_minutes*60, 900))

    @app.post('/api/scans', status_code=202)
    async def launch_scan(body: ScanBody, _=Depends(require_admin)):
        return queue_scan(body.asset_id, body.scanner)

    @app.get('/api/scans')
    def scans(db: Session = Depends(db_session), _=Depends(require_admin)):
        return [as_dict(x, *RUN_FIELDS) for x in db.execute(select(ScanRun).order_by(ScanRun.created_at.desc()).limit(100)).scalars()]

    @app.get('/api/findings')
    def findings(status: str = '', db: Session = Depends(db_session), _=Depends(require_admin)):
        stmt = select(Finding).order_by(Finding.updated_at.desc()).limit(500)
        if status:
            stmt = stmt.where(Finding.status == status)
        return [as_dict(x, *FINDING_FIELDS) for x in db.execute(stmt).scalars()]

    @app.patch('/api/findings/{finding_id}')
    def change_finding(finding_id: str, body: ChangeStatus, db: Session = Depends(db_session), _=Depends(require_admin)):
        row = db.get(Finding, finding_id)
        if not row:
            raise HTTPException(404, detail='Finding not found')
        row.status, row.updated_at = body.status, utcnow()
        record_audit(db, 'admin', 'finding.status', row.id, body.status)
        db.commit()
        return as_dict(row, *FINDING_FIELDS)

    @app.get('/api/events')
    def events(db: Session = Depends(db_session), _=Depends(require_admin)):
        return [as_dict(x, *EVENT_FIELDS) for x in db.execute(select(SecurityEvent).order_by(SecurityEvent.received_at.desc()).limit(300)).scalars()]

    def process_events(source: str, payload, db: Session):
        data = payload if isinstance(payload, list) else [payload]
        if len(data) > 500:
            raise HTTPException(413, detail='Maximum 500 events per request')
        count = 0
        for item in data:
            if not isinstance(item, dict):
                raise HTTPException(400, detail='Each event must be a JSON object')
            info = normalize_wazuh(item) if source=='wazuh' else normalize_falco(item)
            event, created = add_event(db, **info)
            if created:
                correlate_event(db, event)
                count += 1
        record_audit(db, 'sensor', f'{source}.ingested', '', f'{count} events')
        db.commit()
        return {'ingested':count, 'received':len(data)}

    @app.post('/api/ingest/{source}')
    async def ingest(source: str, request: Request, db: Session = Depends(db_session), _=Depends(require_ingest)):
        if source not in {'wazuh','falco','trivy'}:
            raise HTTPException(404)
        if int(request.headers.get('content-length', 0) or 0) > 4_000_000:
            raise HTTPException(413)
        content = await request.body()
        if len(content) > 4_000_000:
            raise HTTPException(413)
        try:
            payload = json.loads(content)
        except ValueError as exc:
            raise HTTPException(400, detail='Invalid JSON') from exc
        if source == 'trivy':
            if not isinstance(payload, dict):
                raise HTTPException(400, detail='Trivy payload must be an object')
            asset_id = request.headers.get('x-asset-id') or None
            if asset_id and not db.get(Asset, asset_id):
                raise HTTPException(404, detail='Asset not found')
            imported = import_trivy(db, payload, asset_id)
            record_audit(db, 'sensor', 'trivy.ingested', asset_id or '', f'{imported} findings')
            db.commit()
            return {'imported': imported}
        return process_events(source, payload, db)

    @app.post('/api/integrations/wazuh/sync')
    async def wazuh_sync(db: Session = Depends(db_session), _=Depends(require_admin)):
        if not config.wazuh_indexer_url.startswith('https://'):
            raise HTTPException(400, detail='Configure HTTPS WAZUH_INDEXER_URL first')
        try:
            async with httpx.AsyncClient(timeout=20, verify=config.wazuh_ca_bundle or True, trust_env=False) as client:
                response = await client.post(config.wazuh_indexer_url + '/wazuh-alerts-*/_search',
                    auth=(config.wazuh_indexer_user, config.wazuh_indexer_password), json={
                    'size': 200,
                    'sort':[{'timestamp': {'order': 'desc'}}],
                    'query': {'range': {'timestamp': {'gte': 'now-30m'}}},
                    '_source':['id','rule','agent','timestamp']})
                response.raise_for_status()
                hits = response.json().get('hits', {}).get('hits', [])
                return process_events('wazuh', [h.get('_source',{}) for h in hits], db)
        except (httpx.HTTPError, ValueError):
            raise HTTPException(502, detail='Wazuh indexer sync failed; verify URL, trust chain and read-only permissions')

    @app.post('/api/findings/{finding_id}/investigate')
    async def investigate_finding(finding_id: str, db: Session = Depends(db_session), _=Depends(require_admin)):
        row = db.get(Finding, finding_id)
        if not row:
            raise HTTPException(404, detail='Finding not found')
        asset = db.get(Asset, row.asset_id) if row.asset_id else None
        try:
            model, result = await investigate(row, asset, config)
        except (httpx.HTTPError, RuntimeError, KeyError, IndexError, TypeError, ValueError) as exc:
            raise HTTPException(502, detail=f'Investigation unavailable: {type(exc).__name__}. Check configured provider.') from exc
        record = Investigation(finding_id=row.id, model=model, summary=result['summary'],
                               recommended_steps=json.dumps({'confidence':result['confidence'],
                                     'next_steps':result['next_steps'], 'limitations':result['limitations']}))
        db.add(record)
        record_audit(db, 'ai' if model != 'rules-only' else 'rules', 'finding.investigated', row.id, model)
        db.commit()
        return {'id':record.id, 'model':model, **result}

    @app.get('/api/investigations')
    def investigations(db: Session = Depends(db_session), _=Depends(require_admin)):
        rows = db.execute(select(Investigation).order_by(Investigation.created_at.desc()).limit(100)).scalars()
        return [{'id':r.id, 'finding_id':r.finding_id, 'model':r.model, 'summary':r.summary,
                 'details':json.loads(r.recommended_steps), 'created_at':r.created_at.isoformat()} for r in rows]

    @app.post('/api/approvals', status_code=201)
    def create_approval(body: ApprovalRequest, db: Session = Depends(db_session), _=Depends(require_admin)):
        if not db.get(Finding, body.finding_id):
            raise HTTPException(404, detail='Finding not found')
        approval = Approval(finding_id=body.finding_id, action=body.action, rationale=body.rationale)
        db.add(approval)
        db.flush()
        record_audit(db, 'admin', 'approval.requested', approval.id, body.action)
        db.commit()
        return {'id':approval.id,'status':approval.status,'execution':'not_implemented'}

    @app.get('/api/approvals')
    def approvals(db: Session = Depends(db_session), _=Depends(require_admin)):
        rows = db.execute(select(Approval).order_by(Approval.created_at.desc()).limit(100)).scalars()
        return [as_dict(x,'id','finding_id','action','rationale','status','created_at','decided_at') for x in rows]

    @app.post('/api/approvals/{approval_id}/decide')
    def decide_approval(approval_id: str, body: ApprovalDecision, db: Session = Depends(db_session), _=Depends(require_admin)):
        approval = db.get(Approval, approval_id)
        if not approval:
            raise HTTPException(404, detail='Approval not found')
        if approval.status != 'pending':
            raise HTTPException(409, detail='Decision already recorded')
        approval.status, approval.decided_at = body.decision, utcnow()
        record_audit(db, 'admin', 'approval.decided', approval.id, body.decision)
        db.commit()
        return {'id':approval.id,'status':approval.status,'execution':'not_implemented'}

    @app.get('/api/audit')
    def audits(db: Session = Depends(db_session), _=Depends(require_admin)):
        rows = db.execute(select(AuditEntry).order_by(AuditEntry.id.desc()).limit(150)).scalars()
        return [as_dict(x,'id','actor','action','subject','detail','entry_hash','created_at') for x in rows]

    @app.get('/api/audit/verify')
    def verify_audit(db: Session = Depends(db_session), _=Depends(require_admin)):
        return {'valid':verify_audit_chain(db), 'note':'Local hash chaining is tamper-evident only if hashes are anchored externally.'}

    @app.get('/api/reports/summary')
    def summary_report(db: Session = Depends(db_session), _=Depends(require_admin)):
        records = db.execute(select(Finding).order_by(Finding.updated_at.desc())).scalars().all()
        return {'generated_at':utcnow().isoformat(), 'report_type':'evidence-based-findings',
                'totals': {'assets':db.scalar(select(func.count()).select_from(Asset)), 'findings':len(records),
                           'unresolved':sum(x.status in {'open','investigating'} for x in records)},
                'findings':[as_dict(x,*FINDING_FIELDS) for x in records],
                'limitations':['Not a compliance certification or guarantee of security.',
                    'Covers connected telemetry and explicitly authorized scans only.']}

    @app.get('/api/reports/findings.csv')
    def csv_report(db: Session = Depends(db_session), _=Depends(require_admin)):
        f = io.StringIO()
        writer = csv.writer(f)
        writer.writerow(['id','severity','status','asset_id','title','source','occurrences','created_at','remediation'])
        for x in db.execute(select(Finding).order_by(Finding.updated_at.desc())).scalars():
            writer.writerow([x.id,x.severity,x.status,x.asset_id,x.title,x.source,x.occurrences,x.created_at.isoformat(),x.remediation])
        return Response(content=f.getvalue(),media_type='text/csv',headers={'Content-Disposition':'attachment; filename="sentinel-findings.csv"'})

    return app


app = create_app()
