"""Legacy record-only approvals. These document a human decision about a finding; nothing is
executed. Executable, policy-checked requests live in the action broker at /api/v1/actions."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..core.audit import record_audit
from ..core.db import get_scoped, scoped
from ..core.errors import Conflict, Forbidden, NotFound
from ..core.rbac import Principal
from ..models import Approval, Finding, utcnow
from .deps import Page, get_db, require

router = APIRouter(prefix='/api/v1/approvals', tags=['approvals'])

ACTIONS_HINT = {'executes': False, 'note': 'Record-only approval. For executable, policy-checked requests use /api/v1/actions.'}
DECISIONS = ('approved', 'denied')


class ApprovalBody(BaseModel):
    finding_id: str = Field(min_length=1, max_length=36)
    action: str = Field(min_length=2, max_length=64, pattern=r'^[a-z0-9_\-\.]+$')
    rationale: str = Field(min_length=8, max_length=800)


class DecisionBody(BaseModel):
    decision: str = Field(pattern='^(approved|denied)$')
    comment: str = Field(default='', max_length=800)


def approval_to_dict(a: Approval) -> dict:
    return {'id': a.id, 'finding_id': a.finding_id, 'action': a.action, 'rationale': a.rationale, 'status': a.status,
            'requested_by': a.requested_by, 'decided_by': a.decided_by, 'created_at': a.created_at, 'decided_at': a.decided_at, **ACTIONS_HINT}


@router.get('')
def list_approvals(status: str | None = None, finding_id: str | None = None, page: Page = Depends(Page), db: Session = Depends(get_db),
                   principal: Principal = Depends(require('approvals:read'))):
    stmt = scoped(Approval, principal)
    if status:
        stmt = stmt.where(Approval.status == status)
    if finding_id:
        stmt = stmt.where(Approval.finding_id == finding_id)
    rows = db.execute(page.apply(stmt.order_by(Approval.created_at.desc(), Approval.id))).scalars().all()
    return page.wrap(rows, approval_to_dict)


@router.post('', status_code=201)
def create_approval(body: ApprovalBody, db: Session = Depends(get_db), principal: Principal = Depends(require('approvals:write'))):
    if get_scoped(db, Finding, principal, body.finding_id) is None:
        raise NotFound('Finding not found')
    approval = Approval(tenant_id=principal.tenant_id, finding_id=body.finding_id, action=body.action, rationale=body.rationale,
                        requested_by=principal.user_id or principal.actor)
    db.add(approval)
    db.flush()
    record_audit(db, principal, 'approvals.requested', approval.id, {'finding_id': body.finding_id, 'action': body.action, 'rationale': body.rationale})
    return approval_to_dict(approval)


@router.get('/{approval_id}')
def get_approval(approval_id: str, db: Session = Depends(get_db), principal: Principal = Depends(require('approvals:read'))):
    approval = get_scoped(db, Approval, principal, approval_id)
    if approval is None:
        raise NotFound('Approval not found')
    return approval_to_dict(approval)


@router.post('/{approval_id}/decide')
def decide_approval(approval_id: str, body: DecisionBody, db: Session = Depends(get_db), principal: Principal = Depends(require('approvals:write'))):
    approval = get_scoped(db, Approval, principal, approval_id)
    if approval is None:
        raise NotFound('Approval not found')
    if approval.status != 'pending':
        raise Conflict('Decision already recorded')
    decider = principal.user_id or principal.actor
    if approval.requested_by and approval.requested_by == decider:
        raise Forbidden('The requester cannot decide their own approval', code='self_approval')
    approval.status, approval.decided_by, approval.decided_at = body.decision, decider, utcnow()
    record_audit(db, principal, 'approvals.decided', approval.id, {'decision': body.decision, 'finding_id': approval.finding_id,
                                                                   'action': approval.action, 'comment': body.comment})
    return approval_to_dict(approval)
