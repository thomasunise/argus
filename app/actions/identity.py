"""Actor identity, separation-of-duty helpers, and serializers for the action broker."""
from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from ..core.db import scoped
from ..core.rbac import Principal
from ..core.security import redact
from ..models import ApiKey, loads
from ..models.actions import ActionApproval, ActionRequest, ActionRun
from . import policy


def actor_id(principal: Principal) -> str:
    if principal.auth == 'api_key':
        return f'api_key:{principal.api_key_id}'
    if principal.auth == 'system' and not principal.user_id:
        return 'system'
    return principal.user_id or principal.email or 'unknown'


def identity_of(db: Session | None, actor: str) -> str:
    """Canonical human identity behind an actor id. An API key acts on behalf of the user who minted it, so a
    request made through a key and an approval made by that user (or another of their keys) are the SAME actor
    for separation-of-duty purposes. Unknown keys and 'system' stay as they are."""
    actor = actor or ''
    if actor.startswith('api_key:') and db is not None:
        key = db.get(ApiKey, actor[len('api_key:'):])
        if key is not None and key.created_by:
            return f'user:{key.created_by}'
        return actor
    if not actor or actor == 'system':
        return actor
    return f'user:{actor}'


def same_identity(db: Session | None, a: str, b: str) -> bool:
    return bool(a) and bool(b) and (policy.same_actor(a, b) or identity_of(db, a) == identity_of(db, b))


def _redacted(value: Any, depth: int = 0) -> Any:
    if depth > 12:
        return '[truncated]'
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {str(k): _redacted(v, depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redacted(v, depth + 1) for v in value]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return redact(str(value))


def _approvals(db: Session, req: ActionRequest) -> list[ActionApproval]:
    stmt = scoped(ActionApproval, req.tenant_id).where(ActionApproval.request_id == req.id).order_by(ActionApproval.created_at.asc())
    return list(db.execute(stmt).scalars().all())


def _runs(db: Session, req: ActionRequest) -> list[ActionRun]:
    stmt = scoped(ActionRun, req.tenant_id).where(ActionRun.request_id == req.id).order_by(ActionRun.created_at.asc())
    return list(db.execute(stmt).scalars().all())


def approvals_satisfied(req: ActionRequest, approvals: list[ActionApproval], db: Session | None = None) -> bool:
    if req.status == 'auto_approved':
        return True
    requester = identity_of(db, req.requested_by)
    approving = [a for a in approvals if a.decision == 'approve' and a.approver_id != req.requested_by
                 and identity_of(db, a.approver_id) != requester]
    distinct = {identity_of(db, a.approver_id) for a in approving}
    owner_ok = (not req.owner_approval_required) or any(a.can_approve_critical for a in approving)
    return len(distinct) >= req.required_approvals and owner_ok


def approval_to_dict(a: ActionApproval) -> dict:
    return {'id': a.id, 'request_id': a.request_id, 'approver_id': a.approver_id, 'approver_role': a.approver_role,
            'can_approve_critical': bool(a.can_approve_critical), 'decision': a.decision, 'comment': a.comment, 'created_at': a.created_at}


def run_to_dict(r: ActionRun, *, include_rollback_payload: bool = False) -> dict:
    data = {'id': r.id, 'request_id': r.request_id, 'status': r.status, 'dry_run': bool(r.dry_run), 'result': loads(r.result_json, {}),
            'error': r.error, 'executed_by': r.executed_by, 'job_id': r.job_id, 'rollback_job_id': r.rollback_job_id,
            'has_rollback_payload': r.rollback_payload_json not in ('', '{}', 'null'), 'started_at': r.started_at,
            'finished_at': r.finished_at, 'rolled_back_at': r.rolled_back_at, 'rolled_back_by': r.rolled_back_by, 'created_at': r.created_at}
    if include_rollback_payload:
        data['rollback_payload'] = _redacted(loads(r.rollback_payload_json, {}))
    return data


def request_to_dict(r: ActionRequest, approvals: list[ActionApproval] | None = None, runs: list[ActionRun] | None = None) -> dict:
    data = {'id': r.id, 'action_type': r.action_type, 'params': loads(r.params_json, {}), 'reason': r.reason, 'risk': r.risk,
            'status': r.status, 'requested_by': r.requested_by, 'requested_by_role': r.requested_by_role, 'agent_run_id': r.agent_run_id,
            'agent_originated': bool(r.agent_run_id), 'finding_id': r.finding_id, 'detection_id': r.detection_id,
            'dry_run': loads(r.dry_run_json, {}), 'policy': loads(r.policy_json, {}), 'required_approvals': r.required_approvals,
            'owner_approval_required': bool(r.owner_approval_required), 'created_at': r.created_at, 'decided_at': r.decided_at,
            'expires_at': r.expires_at}
    if approvals is not None:
        data['approvals'] = [approval_to_dict(a) for a in approvals]
        data['approval_count'] = len({a.approver_id for a in approvals if a.decision == 'approve'})
    if runs is not None:
        data['runs'] = [run_to_dict(x) for x in runs]
    return data


def request_detail(db: Session, req: ActionRequest) -> dict:
    return request_to_dict(req, _approvals(db, req), _runs(db, req))
