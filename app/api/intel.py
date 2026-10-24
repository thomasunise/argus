"""Threat-intel API: feed status, KEV refresh, finding backfill and single-CVE lookup from the cache."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..core.audit import record_audit
from ..core.config import Settings
from ..core.errors import ArgusError
from ..core.rbac import Principal
from ..intel import feeds
from .deps import get_db, get_settings, require

router = APIRouter(prefix='/api/v1/intel', tags=['intel'])


class InvalidCve(ArgusError):
    status = 422
    code = 'invalid_cve'


class EnrichBody(BaseModel):
    finding_ids: list[str] = Field(default_factory=list, max_length=2000)
    include_closed: bool = False


@router.get('/status')
def intel_status(settings: Settings = Depends(get_settings), principal: Principal = Depends(require('findings:read'))):
    return feeds.status(settings)


@router.post('/refresh', status_code=202)
async def refresh(request: Request, db: Session = Depends(get_db), principal: Principal = Depends(require('admin:settings'))):
    record_audit(db, principal, 'intel.refresh_requested', '', {})
    job = await request.app.state.queue.enqueue('intel.refresh', {'force': True}, tenant_id=principal.tenant_id,
                                                idempotency_key=f'intel.refresh:{principal.tenant_id}', priority=6)
    return {'job_id': job.id}


@router.post('/enrich', status_code=202)
async def enrich_findings(body: EnrichBody, request: Request, db: Session = Depends(get_db), principal: Principal = Depends(require('findings:write'))):
    """Backfill: enrich the listed findings, or every open finding with a CVE when the list is empty."""
    record_audit(db, principal, 'intel.enrich_requested', '', {'finding_ids': len(body.finding_ids), 'include_closed': body.include_closed})
    job = await request.app.state.queue.enqueue('intel.enrich', {'tenant_id': principal.tenant_id, 'finding_ids': body.finding_ids,
                                                                 'include_closed': body.include_closed},
                                                tenant_id=principal.tenant_id, priority=6)
    return {'job_id': job.id}


@router.get('/cve/{cve_id}')
async def cve(cve_id: str, settings: Settings = Depends(get_settings), principal: Principal = Depends(require('findings:read'))):
    ids = feeds.normalize_cves([cve_id])
    if not ids:
        raise InvalidCve('expected a CVE id such as CVE-2024-3094')
    kev = await feeds.kev_lookup(settings, ids)
    epss = await feeds.epss_lookup(settings, ids)
    entry = kev.get(ids[0])
    return {'cve_id': ids[0], 'kev': bool(entry), 'kev_entry': entry, 'epss': epss.get(ids[0]), 'catalog': feeds.status(settings)['kev']}
