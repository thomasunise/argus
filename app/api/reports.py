"""Reports: dashboard summary, posture score, compliance evidence mapping and daily trends."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..core.audit import record_audit
from ..core.config import Settings
from ..core.errors import NotFound
from ..core.rbac import Principal
from ..reports import FRAMEWORKS, compliance, onboarding, posture, summary, trends
from ..reports.controls import catalog
from .deps import get_db, get_settings, require

router = APIRouter(prefix='/api/v1/reports', tags=['reports'])


@router.get('/summary')
def get_summary(db: Session = Depends(get_db), settings: Settings = Depends(get_settings), principal: Principal = Depends(require('reports:read'))):
    return summary(db, principal.tenant_id, settings)


@router.get('/onboarding')
def get_onboarding(db: Session = Depends(get_db), principal: Principal = Depends(require('reports:read'))):
    return onboarding(db, principal.tenant_id)


@router.get('/posture')
def get_posture(db: Session = Depends(get_db), settings: Settings = Depends(get_settings), principal: Principal = Depends(require('reports:read'))):
    return posture(db, principal.tenant_id, settings)


@router.get('/compliance')
def list_frameworks(principal: Principal = Depends(require('reports:read'))):
    return {'items': [{'framework': key, 'name': value['name'], 'controls': len(value['controls'])} for key, value in FRAMEWORKS.items()],
            'catalog': catalog()}


@router.get('/compliance/{framework}')
def get_compliance(framework: str, db: Session = Depends(get_db), settings: Settings = Depends(get_settings),
                   principal: Principal = Depends(require('reports:read'))):
    key = framework.lower()
    if key not in FRAMEWORKS:
        raise NotFound(f'Unknown framework {framework!r}; one of {sorted(FRAMEWORKS)}')
    report = compliance(db, principal.tenant_id, key, settings)
    record_audit(db, principal, 'reports.compliance_generated', key, {'totals': report['totals']})
    return report


@router.get('/trends')
def get_trends(days: int = 30, db: Session = Depends(get_db), principal: Principal = Depends(require('reports:read'))):
    return trends(db, principal.tenant_id, days)
