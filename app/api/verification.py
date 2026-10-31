"""Authorized repeat-scanning and side-by-side validation evidence.

A non-reproduced finding is not claimed fixed until independently verified.
Both runs must be completed, same asset and same adapter to be comparable.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.db import get_scoped, scoped
from ..core.errors import ArgusError, NotFound
from ..core.rbac import Principal
from ..models import loads
from ..models.testing import TestRun, TestResult
from ..testing.service import launch_scan
from .deps import get_db, require

router = APIRouter(prefix='/api/v1/verification', tags=['testing'])


def compare_rules(before: list[str], after: list[str]) -> dict:
    old, new = set(before), set(after)
    return {'no_longer_reproduced': sorted(old - new),
            'still_detected': sorted(old & new),
            'newly_detected': sorted(new - old)}


@router.post('/retest/{run_id}', status_code=202)
async def retest(run_id: str, request: Request, db: Session = Depends(get_db),
                 principal: Principal = Depends(require('tests:run'))):
    previous = get_scoped(db, TestRun, principal, run_id)
    if previous is None:
        raise NotFound('Test run not found')
    if previous.status != 'completed':
        raise ArgusError('Only a completed test can be used as a retest baseline', status=409, code='invalid_baseline')
    if not previous.scope_id:
        raise ArgusError('Baseline test has no active scope reference', status=409, code='invalid_baseline')
    # launch_scan performs a fresh authorization, environment, tier, rate and time-window check.
    return await launch_scan(request.app, principal, asset_id=previous.asset_id, adapter_name=previous.adapter,
                             scope_id=previous.scope_id, requested_tier=previous.tier,
                             triggered_by=f'retest:{run_id[:36]}', params=loads(previous.params_json, {}))


@router.get('/compare')
def compare(baseline: str, followup: str, db: Session = Depends(get_db),
            principal: Principal = Depends(require('tests:read'))):
    a = get_scoped(db, TestRun, principal, baseline)
    b = get_scoped(db, TestRun, principal, followup)
    if a is None or b is None:
        raise NotFound('Test run not found')
    if a.asset_id != b.asset_id or a.adapter != b.adapter:
        raise ArgusError('Comparable runs must use the same asset and adapter', status=400, code='incompatible_runs')
    if a.status != 'completed' or b.status != 'completed':
        return {'status': 'inconclusive', 'baseline_status': a.status, 'followup_status': b.status}
    old = db.execute(select(TestResult.rule).where(TestResult.tenant_id == principal.tenant_id,
                       TestResult.run_id == a.id)).scalars().all()
    new = db.execute(select(TestResult.rule).where(TestResult.tenant_id == principal.tenant_id,
                       TestResult.run_id == b.id)).scalars().all()
    return {'status': 'comparable', 'asset_id': a.asset_id, 'adapter': a.adapter,
            'baseline_run_id': a.id, 'followup_run_id': b.id, 'remediation_confirmed': False,
            'note': 'A missing finding in one follow-up scan is not sufficient proof of remediation.',
            **compare_rules(old, new)}
