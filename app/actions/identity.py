"""Actor identity, separation-of-duty helpers, and serializers for the action broker."""
from __future__ import annotations

from datetime import UTC, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.db import scoped
from ..core.rbac import Principal
from ..core.security import redact
from ..models import ApiKey, Membership, OidcIdentity, User, loads, utcnow
from ..models.actions import ActionApproval, ActionRequest, ActionRun
from . import policy


def actor_id(principal: Principal) -> str:
    if principal.auth == 'api_key':
        return f'api_key:{principal.api_key_id}'
    if principal.auth == 'system' and not principal.user_id:
        return 'system'
    return principal.user_id or principal.email or 'unknown'


def identity_of(db: Session | None, actor: str | Principal) -> str:
    """Canonical human identity behind an actor id. An API key acts on behalf of the user who minted it, so a
    request made through a key and an approval made by that user (or another of their keys) are the SAME actor
    for separation-of-duty purposes. Keys with no creator return '' so they cannot approve requests."""
    if isinstance(actor, Principal):
        actor = actor_id(actor)
    actor = actor or ''
    if actor.startswith('api_key:'):
        if db is None:
            return ''
        key = db.get(ApiKey, actor[len('api_key:'):])
        if key is not None and key.created_by:
            return f'user:{key.created_by}'
        return ''
    if not actor or actor == 'system':
        return actor
    return f'user:{actor}'


def same_identity(db: Session | None, a: str | Principal, b: str | Principal) -> bool:
    a_id = actor_id(a) if isinstance(a, Principal) else (a or '')
    b_id = actor_id(b) if isinstance(b, Principal) else (b or '')
    if not a_id or not b_id:
        return False
    if policy.same_actor(a_id, b_id):
        return True
    ia, ib = identity_of(db, a_id), identity_of(db, b_id)
    return bool(ia) and bool(ib) and ia == ib


def cooling_off_reason(db: Session | None, approver_actor: str, requester_actor: str, tenant_id: str) -> str:
    """Cooling-off and creator-separation rule: an account or key created by the requester,
    or created in the last 24 hours, cannot approve that requester's actions."""
    if db is None or not approver_actor:
        return ''
    req_ident = identity_of(db, requester_actor)
    req_uid = req_ident[len('user:'):] if req_ident.startswith('user:') else ''
    app_ident = identity_of(db, approver_actor)
    app_uid = app_ident[len('user:'):] if app_ident.startswith('user:') else ''
    now = utcnow()
    if approver_actor.startswith('api_key:'):
        key = db.get(ApiKey, approver_actor[len('api_key:'):])
        if key is not None and req_uid and key.created_by == req_uid:
            return 'an API key created by the requester cannot approve their actions'
    if app_uid:
        user = db.get(User, app_uid)
        membership = db.execute(select(Membership).where(Membership.user_id == app_uid,
                                                         Membership.tenant_id == tenant_id)).scalar_one_or_none()
        creator = (membership.created_by if membership else '') or (user.created_by if user else '')
        if req_uid and creator and creator == req_uid:
            return 'an account created by the requester cannot approve their actions'
        if req_uid:
            req_user = db.get(User, req_uid)
            req_membership = db.execute(select(Membership).where(Membership.user_id == req_uid,
                                                                 Membership.tenant_id == tenant_id)).scalar_one_or_none()
            req_creator = (req_membership.created_by if req_membership else '') or (req_user.created_by if req_user else '')
            if req_creator and req_creator == app_uid:
                return 'you created the requesting account, so you cannot approve its actions'
        if creator:
            created_at = (membership.created_at if membership and membership.created_by else None) or (user.created_at if user else None)
            if created_at is not None:
                aware_ts = created_at if created_at.tzinfo else created_at.replace(tzinfo=UTC)
                if now - aware_ts < timedelta(hours=24):
                    return 'cooling-off rule: accounts created in the last 24 hours cannot approve actions'
    return ''


def federation_reason(db: Session | None, approver_actor: str, required: bool) -> str:
    """When federated approvers are required, an approval only counts from a person the identity provider vouches for.

    Local password accounts and keys minted by them can be created by any administrator, so two-person approval built
    on them is only as strong as one administrator's honesty. An IdP-linked account cannot be fabricated from inside
    Argus."""
    if not required or db is None:
        return ''
    ident = identity_of(db, approver_actor)
    uid = ident[len('user:'):] if ident.startswith('user:') else ''
    if not uid:
        return 'approvals require an account linked to the identity provider'
    linked = db.execute(select(OidcIdentity.id).where(OidcIdentity.user_id == uid).limit(1)).first()
    if linked is None:
        return 'approvals require an account linked to the identity provider; sign in through SSO first'
    return ''


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
                 and (ident := identity_of(db, a.approver_id)) and (not requester or ident != requester)]
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
