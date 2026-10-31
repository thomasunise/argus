"""No-credential offline IAM policy checks, scoped to authenticated ARGUS users."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from ..ai.iam_policy import evaluate_identity_policies
from ..core.errors import ArgusError
from ..core.rbac import Principal
from .deps import require

router = APIRouter(prefix='/api/v1/cloud-permissions', tags=['cloud'])


class IAMBody(BaseModel):
    policies: list[dict] = Field(min_length=1, max_length=20)
    action: str = Field(min_length=1, max_length=200)
    resource: str = Field(min_length=1, max_length=1024)


@router.post('/aws/identity-policy/evaluate')
def evaluate_iam(body: IAMBody, principal: Principal = Depends(require('graph:read'))):
    try:
        return evaluate_identity_policies(body.policies, body.action, body.resource)
    except ValueError as exc:
        raise ArgusError(str(exc), status=400, code='invalid_iam_document') from exc
