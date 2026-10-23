"""Operational endpoints: queue visibility and cancellation."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from ..core.errors import NotFound
from ..core.queue import iso
from ..core.rbac import Principal
from .deps import require

router = APIRouter(prefix='/api/v1/ops', tags=['ops'])


def _job_dict(job) -> dict:
    return {'id': job.id, 'kind': job.kind, 'status': job.status, 'attempts': job.attempts, 'max_attempts': job.max_attempts,
            'error': job.error, 'priority': job.priority, 'created_at': iso(job.created_at), 'started_at': iso(job.started_at),
            'finished_at': iso(job.finished_at), 'result': job.result}


@router.get('/jobs')
async def list_jobs(request: Request, status: str | None = None, limit: int = 100, principal: Principal = Depends(require('audit:read'))):
    jobs = await request.app.state.queue.list(principal.tenant_id, min(500, limit), status)
    return {'items': [_job_dict(j) for j in jobs], 'kinds': request.app.state.queue.kinds}


@router.get('/jobs/{job_id}')
async def get_job(job_id: str, request: Request, principal: Principal = Depends(require('audit:read'))):
    job = await request.app.state.queue.status(job_id)
    if not job or job.tenant_id != principal.tenant_id:
        raise NotFound('Job not found')
    return _job_dict(job)


@router.post('/jobs/{job_id}/cancel')
async def cancel_job(job_id: str, request: Request, principal: Principal = Depends(require('admin:settings'))):
    job = await request.app.state.queue.status(job_id)
    if not job or job.tenant_id != principal.tenant_id:
        raise NotFound('Job not found')
    return {'ok': await request.app.state.queue.cancel(job_id)}
