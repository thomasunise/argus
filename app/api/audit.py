"""Audit chain: tenant-scoped listing, chain verification and JSONL export."""
from __future__ import annotations

import json
from typing import Iterator

from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..core.audit import record_audit, verify_chain
from ..core.errors import Forbidden
from ..core.rbac import Principal, Role, role_at_least
from ..models import AuditEntry, loads
from ._common import aware, like, parse_since
from .deps import Page, get_db, require

router = APIRouter(prefix='/api/v1/audit', tags=['audit'])

EXPORT_BATCH = 500


def entry_to_dict(e: AuditEntry) -> dict:
    return {'id': e.id, 'actor': e.actor, 'actor_kind': e.actor_kind, 'action': e.action, 'subject': e.subject, 'detail': loads(e.detail),
            'request_id': e.request_id, 'previous_hash': e.previous_hash, 'entry_hash': e.entry_hash, 'signed': bool(e.signature),
            'created_at': e.created_at}


def _filtered(principal: Principal, actor: str | None, action: str | None, subject: str | None, since: str | None, until: str | None):
    stmt = select(AuditEntry).where(AuditEntry.tenant_id == principal.tenant_id)
    if actor:
        stmt = stmt.where(AuditEntry.actor == actor)
    if action:
        stmt = stmt.where(AuditEntry.action.like(action.replace('%', '\\%').replace('_', '\\_') + '%', escape='\\'))
    if subject:
        stmt = stmt.where(AuditEntry.subject == subject)
    since_at = parse_since(since)
    if since_at:
        stmt = stmt.where(AuditEntry.created_at >= since_at)
    until_at = parse_since(until, field='until')
    if until_at:
        stmt = stmt.where(AuditEntry.created_at <= until_at)
    return stmt


@router.get('')
def list_audit(actor: str | None = None, action: str | None = None, subject: str | None = None, since: str | None = None,
               until: str | None = None, search: str | None = None, page: Page = Depends(Page), db: Session = Depends(get_db),
               principal: Principal = Depends(require('audit:read'))):
    stmt = _filtered(principal, actor, action, subject, since, until)
    if search:
        stmt = stmt.where(AuditEntry.detail.ilike(like(search.strip()), escape='\\'))
    rows = db.execute(page.apply(stmt.order_by(AuditEntry.id.desc()))).scalars().all()
    return page.wrap(rows, entry_to_dict)


@router.get('/verify')
def verify(db: Session = Depends(get_db), principal: Principal = Depends(require('audit:read'))):
    result = verify_chain(db, principal.tenant_id)
    result['note'] = 'Hash chaining is tamper-evident; anchor the chain externally (jsonl/S3 Object Lock/Azure immutable blob) for tamper-proof retention.'
    return result


@router.get('/actions')
def list_actions(db: Session = Depends(get_db), principal: Principal = Depends(require('audit:read'))):
    rows = db.execute(select(AuditEntry.action, func.count()).where(AuditEntry.tenant_id == principal.tenant_id)
                      .group_by(AuditEntry.action).order_by(AuditEntry.action)).all()
    return {'items': [{'action': a, 'count': int(n)} for a, n in rows]}


@router.get('/export.jsonl')
def export_jsonl(actor: str | None = None, action: str | None = None, subject: str | None = None, since: str | None = None,
                 until: str | None = None, db: Session = Depends(get_db), principal: Principal = Depends(require('audit:read'))):
    """Full-fidelity export (hashes and signatures included) so the chain can be re-verified offline.
    Restricted to admins and owners because the detail field can contain operational context."""
    if not role_at_least(principal.role, Role.admin):
        raise Forbidden('Audit export requires the admin or owner role')
    stmt = _filtered(principal, actor, action, subject, since, until)
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    record_audit(db, principal, 'audit.exported', '', {'format': 'jsonl', 'rows': int(total),
                                                        'filters': {k: v for k, v in {'actor': actor, 'action': action, 'subject': subject,
                                                                                      'since': since, 'until': until}.items() if v}})
    db.commit()
    rows = db.execute(stmt.order_by(AuditEntry.id.asc())).scalars().all()

    def generate() -> Iterator[str]:
        for e in rows:
            record = {'id': e.id, 'tenant_id': e.tenant_id, 'actor': e.actor, 'actor_kind': e.actor_kind, 'action': e.action, 'subject': e.subject,
                      'detail': e.detail, 'request_id': e.request_id, 'previous_hash': e.previous_hash, 'entry_hash': e.entry_hash,
                      'signature': e.signature, 'created_at': aware(e.created_at).isoformat()}
            yield json.dumps(record, sort_keys=True, default=str) + '\n'

    return StreamingResponse(generate(), media_type='application/x-ndjson',
                             headers={'Content-Disposition': 'attachment; filename="sentinel-audit.jsonl"', 'X-Row-Count': str(int(total))})
