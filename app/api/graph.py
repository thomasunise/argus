"""Evidence graph API: nodes, neighborhoods, attack paths, exposures and statistics."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.audit import record_audit
from ..core.db import get_scoped, scoped
from ..core.errors import NotFound
from ..core.rbac import Principal
from ..graph import service
from ..models import utcnow
from ..models.graph import ATTACK_PATH_STATUSES, AttackPath, GraphNode
from .deps import Page, get_db, require, write_off_loop

router = APIRouter(prefix='/api/v1/graph', tags=['graph'])


class PathPatch(BaseModel):
    status: str
    comment: str = ''


class RecomputeBody(BaseModel):
    from_kind: str = 'exposure'
    to_kind: str = 'data_store'
    max_hops: int = 6
    limit: int = 50


@router.get('/nodes')
def list_nodes(kind: str | None = None, key: str | None = None, search: str | None = Query(default=None, max_length=200),
               include_stale: bool = True, page: Page = Depends(), db: Session = Depends(get_db),
               principal: Principal = Depends(require('graph:read'))):
    rows = service.query(db, principal.tenant_id, kind=kind, key=key, search=search, limit=page.limit + 1, offset=page.offset,
                         include_stale=include_stale)
    return page.wrap(rows, service.node_to_dict)


@router.get('/stats')
def graph_stats(db: Session = Depends(get_db), principal: Principal = Depends(require('graph:read'))):
    return service.stats(db, principal.tenant_id)


@router.get('/exposures')
def list_exposures(limit: int = Query(default=20, ge=1, le=200), kind: str | None = None, db: Session = Depends(get_db),
                   principal: Principal = Depends(require('graph:read'))):
    stmt = scoped(GraphNode, principal).where(GraphNode.is_stale.is_(False))
    if kind:
        stmt = stmt.where(GraphNode.kind == kind)
    rows = db.execute(stmt.order_by(GraphNode.exposure_score.desc(), GraphNode.last_seen_at.desc()).limit(limit)).scalars().all()
    return {'items': [service.node_to_dict(n) for n in rows]}


@router.get('/attack-paths')
def list_attack_paths(status: str | None = None, min_score: float | None = None, page: Page = Depends(), db: Session = Depends(get_db),
                      principal: Principal = Depends(require('graph:read'))):
    stmt = scoped(AttackPath, principal)
    if status:
        stmt = stmt.where(AttackPath.status == status)
    if min_score is not None:
        stmt = stmt.where(AttackPath.score >= min_score)
    rows = db.execute(page.apply(stmt.order_by(AttackPath.score.desc(), AttackPath.computed_at.desc()))).scalars().all()
    return page.wrap(rows, service.path_to_dict)


@router.get('/attack-paths/{path_id}')
def get_attack_path(path_id: str, db: Session = Depends(get_db), principal: Principal = Depends(require('graph:read'))):
    path = get_scoped(db, AttackPath, principal, path_id)
    if not path:
        raise NotFound('Attack path not found')
    return service.path_to_dict(path)


@router.patch('/attack-paths/{path_id}')
def patch_attack_path(path_id: str, body: PathPatch, db: Session = Depends(get_db),
                      principal: Principal = Depends(require('graph:read', 'findings:write'))):
    path = get_scoped(db, AttackPath, principal, path_id)
    if not path:
        raise NotFound('Attack path not found')
    if body.status not in ATTACK_PATH_STATUSES:
        from ..core.errors import ArgusError

        raise ArgusError(f'status must be one of {", ".join(ATTACK_PATH_STATUSES)}', code='invalid_status')
    previous = path.status
    path.status = body.status
    path.computed_at = path.computed_at or utcnow()
    record_audit(db, principal, 'graph.attack_path_status', path.id, {'from': previous, 'to': body.status, 'comment': body.comment[:500]})
    return service.path_to_dict(path)


@router.post('/recompute', status_code=202)
async def recompute(request: Request, body: RecomputeBody | None = None, db: Session = Depends(get_db),
                    principal: Principal = Depends(require('graph:read', 'detections:run'))):
    body = body or RecomputeBody()
    payload = {'tenant_id': principal.tenant_id, 'from_kind': body.from_kind[:24], 'to_kind': body.to_kind[:24],
               'max_hops': max(1, min(body.max_hops, 10)), 'limit': max(1, min(body.limit, 500))}
    job = await request.app.state.queue.enqueue('graph.recompute', payload, tenant_id=principal.tenant_id)
    await write_off_loop(db, lambda: record_audit(db, principal, 'graph.recompute', job.id,
                                                  {'from_kind': payload['from_kind'], 'to_kind': payload['to_kind']}))
    return {'job_id': job.id, 'status': job.status}


@router.get('/nodes/{node_id}')
def get_node(node_id: str, db: Session = Depends(get_db), principal: Principal = Depends(require('graph:read'))):
    node = get_scoped(db, GraphNode, principal, node_id)
    if not node:
        raise NotFound('Node not found')
    return service.node_to_dict(node)


@router.get('/nodes/{node_id}/neighbors')
def node_neighbors(node_id: str, depth: int = Query(default=1, ge=1, le=4), rels: str | None = None,
                   direction: str = Query(default='both', pattern='^(both|in|out)$'), limit: int = Query(default=500, ge=1, le=2000),
                   db: Session = Depends(get_db), principal: Principal = Depends(require('graph:read'))):
    node = db.execute(select(GraphNode.id).where(GraphNode.id == node_id, GraphNode.tenant_id == principal.tenant_id)).scalar_one_or_none()
    if not node:
        raise NotFound('Node not found')
    rel_list = [r.strip() for r in rels.split(',') if r.strip()] if rels else None
    return service.neighbors(db, principal.tenant_id, node_id, rels=rel_list, depth=depth, direction=direction, limit=limit)
