"""Security posture score (0..100). A weighted average of component scores; components that
cannot be computed on this deployment are dropped and the remaining weights renormalized, so a
partial install never reports a falsely low or high score."""
from __future__ import annotations

from datetime import timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..core.config import Settings
from ..models import Asset, Finding
from .evidence import CRITICAL_SLA_DAYS, HIGH_SLA_DAYS, MTTR_TARGET_DAYS, OPEN_STATES, aware, run_check, utcnow

WEIGHTS = {'authorization': 20, 'open_critical_high': 30, 'coverage': 15, 'detection_trend': 10, 'exposure': 15, 'mttr': 10}


def _clamp(value: float) -> float:
    return max(0.0, min(100.0, value))


def _grade(score: float) -> str:
    for threshold, letter in ((90, 'A'), (80, 'B'), (70, 'C'), (60, 'D')):
        if score >= threshold:
            return letter
    return 'F'


def _authorization(db: Session, tenant_id: str) -> tuple[float | None, dict]:
    total = int(db.scalar(select(func.count()).select_from(Asset).where(Asset.tenant_id == tenant_id)) or 0)
    if total == 0:
        return None, {'assets': 0, 'authorized': 0, 'note': 'no assets inventoried'}
    approved = int(db.scalar(select(func.count()).select_from(Asset).where(Asset.tenant_id == tenant_id, Asset.approved.is_(True))) or 0)
    return _clamp(100.0 * approved / total), {'assets': total, 'authorized': approved, 'percent': round(100.0 * approved / total, 1)}


def _open_critical_high(db: Session, tenant_id: str) -> tuple[float, dict]:
    """Each open critical costs 8 points (16 once past SLA), each open high 3 (6 past SLA)."""
    now = utcnow()
    rows = db.execute(select(Finding.severity, Finding.created_at).where(Finding.tenant_id == tenant_id, Finding.status.in_(OPEN_STATES),
                                                                         Finding.severity.in_(['critical', 'high']))).all()
    penalty = 0.0
    counts = {'critical': 0, 'high': 0, 'critical_past_sla': 0, 'high_past_sla': 0}
    for severity, created in rows:
        age = (now - aware(created)).days
        counts[severity] += 1
        if severity == 'critical':
            late = age > CRITICAL_SLA_DAYS
            penalty += 16 if late else 8
        else:
            late = age > HIGH_SLA_DAYS
            penalty += 6 if late else 3
        if late:
            counts[f'{severity}_past_sla'] += 1
    return _clamp(100.0 - penalty), {**counts, 'penalty': round(min(100.0, penalty), 1)}


def _mttr(db: Session, tenant_id: str) -> tuple[float | None, dict]:
    since = utcnow() - timedelta(days=90)
    rows = db.execute(select(Finding.created_at, Finding.updated_at).where(Finding.tenant_id == tenant_id, Finding.status == 'resolved',
                                                                           Finding.updated_at >= since).limit(5000)).all()
    if not rows:
        return None, {'sample': 0, 'note': 'no findings resolved in the last 90 days'}
    mean_days = sum((aware(u) - aware(c)).total_seconds() for c, u in rows) / len(rows) / 86400
    # 1 day or less = 100, target (30 days) = 50, 2x target = 0.
    if mean_days <= 1:
        score = 100.0
    elif mean_days <= MTTR_TARGET_DAYS:
        score = 100.0 - 50.0 * (mean_days - 1) / (MTTR_TARGET_DAYS - 1)
    else:
        score = 50.0 - 50.0 * min(1.0, (mean_days - MTTR_TARGET_DAYS) / MTTR_TARGET_DAYS)
    return _clamp(score), {'mean_days': round(mean_days, 2), 'sample': len(rows), 'target_days': MTTR_TARGET_DAYS}


def posture(db: Session, tenant_id: str, settings: Settings) -> dict[str, Any]:
    components: dict[str, dict[str, Any]] = {}

    score, detail = _authorization(db, tenant_id)
    components['authorization'] = {'score': score, 'detail': detail, 'description': 'share of inventoried assets with a current testing authorization'}

    score, detail = _open_critical_high(db, tenant_id)
    components['open_critical_high'] = {'score': score, 'detail': detail, 'description': 'open critical/high findings weighted by age against SLA'}

    cov = run_check('coverage', db, tenant_id, settings)
    cov_score = None if cov.ok is None else _clamp(100.0 * float((cov.value or {}).get('ratio', 1.0 if cov.ok else 0.0)))
    components['coverage'] = {'score': cov_score, 'detail': cov.to_dict(), 'description': 'collector kinds configured for the asset kinds present'}

    trend = run_check('detection_volume_trend', db, tenant_id, settings)
    if trend.ok is None:
        trend_score = None
    else:
        ratio = float((trend.value or {}).get('ratio', 1.0))
        trend_score = 100.0 if ratio <= 1.0 else _clamp(100.0 - 50.0 * min(1.0, ratio - 1.0))  # doubling = 50
        open_now = int((trend.value or {}).get('open', 0))
        trend_score = _clamp(trend_score - min(30.0, 2.0 * open_now))
    components['detection_trend'] = {'score': trend_score, 'detail': trend.to_dict(), 'description': 'week-over-week detection volume and open detections'}

    exp = run_check('exposure', db, tenant_id, settings)
    if exp.ok is None:
        exp_score = None
    else:
        value = exp.value or {}
        exp_score = _clamp(100.0 - float(value.get('top_exposure_mean', 0)) - 5.0 * int(value.get('attack_paths_open', 0)))
    components['exposure'] = {'score': exp_score, 'detail': exp.to_dict(), 'description': 'graph exposure of the most exposed nodes and open attack paths'}

    score, detail = _mttr(db, tenant_id)
    components['mttr'] = {'score': score, 'detail': detail, 'description': 'mean time to resolve findings over the last 90 days'}

    available = {name: c for name, c in components.items() if c['score'] is not None}
    total_weight = sum(WEIGHTS[name] for name in available) or 1
    overall = sum(WEIGHTS[name] * c['score'] for name, c in available.items()) / total_weight
    for name, component in components.items():
        component['weight'] = WEIGHTS[name]
        component['included'] = component['score'] is not None
        if component['score'] is not None:
            component['score'] = round(component['score'], 1)
    return {'generated_at': utcnow(), 'score': round(overall, 1), 'grade': _grade(overall), 'components': components,
            'weights_used': {name: WEIGHTS[name] for name in available},
            'note': 'Heuristic score derived from inventory, findings, detections and graph state. It is a trend indicator, not a risk quantification.'}
