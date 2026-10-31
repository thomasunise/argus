"""AI/MCP tool-call policy. Evaluation is advisory for external callers, enforced in AgentRuntime."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..ai.tool_guard import evaluate, policy_for, validate_policy
from ..core.audit import record_audit
from ..core.errors import ArgusError
from ..core.rbac import Principal
from ..models import Tenant, dumps, loads
from .deps import get_db, require

router = APIRouter(prefix='/api/v1/ai/tool-guard', tags=['ai'])


class CheckBody(BaseModel):
    tool: str = Field(min_length=1, max_length=200)
    risk: str = Field(default='unknown', max_length=40)
    arguments: dict = Field(default_factory=dict)


class PolicyBody(BaseModel):
    mode: str = 'monitor'
    allow_tools: list[str] = Field(default_factory=list)
    deny_tools: list[str] = Field(default_factory=list)
    deny_risks: list[str] = Field(default_factory=list)
    allow_hosts: list[str] = Field(default_factory=list)
    deny_hosts: list[str] = Field(default_factory=list)


@router.get('/policy')
def get_policy(db: Session = Depends(get_db), principal: Principal = Depends(require('ai:read'))):
    return validate_policy(policy_for(db, principal.tenant_id))


@router.put('/policy')
def put_policy(body: PolicyBody, db: Session = Depends(get_db), principal: Principal = Depends(require('ai:write'))):
    try:
        new_policy = validate_policy(body.model_dump())
    except ValueError as exc:
        raise ArgusError(str(exc), status=400, code='invalid_tool_guard_policy') from exc
    tenant = db.get(Tenant, principal.tenant_id)
    settings = loads(tenant.settings_json, {})
    settings = settings if isinstance(settings, dict) else {}
    settings['tool_guard'] = new_policy
    tenant.settings_json = dumps(settings)
    record_audit(db, principal, 'ai.tool_guard_policy_updated', '', {'mode': new_policy['mode']})
    return new_policy


@router.post('/evaluate')
def check_tool(body: CheckBody, db: Session = Depends(get_db), principal: Principal = Depends(require('ai_gateway:use'))):
    try:
        decision = evaluate(body.tool, body.risk, body.arguments, policy_for(db, principal.tenant_id))
    except ValueError as exc:
        raise ArgusError(str(exc), status=400, code='invalid_tool_guard_policy') from exc
    if decision.would_block:
        record_audit(db, principal, 'ai.tool_guard_decision', body.tool[:120],
                     {'allowed': decision.allowed, 'reasons': list(decision.reasons)})
    return {**decision.as_dict(), 'enforcement': 'caller_must_enforce_for_external_tools'}
