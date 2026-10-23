"""Read-only finding tools: lookup, listing, similarity and history."""
from __future__ import annotations

from sqlalchemy import or_, select

from ...core.db import scoped
from ...models import AgentRun, AuditEntry, Finding
from ._common import OPEN_STATUSES, SEVERITY_RANK, clamp_limit, compact_finding, full_finding, like, load_finding, severity_sorted
from .registry import ToolContext, registry

_ID = {'type': 'string', 'description': 'Finding id (UUID)'}


@registry.tool('get_finding', 'Fetch one finding with its description, evidence, exploitability fields (cvss/epss/kev), status and asset.',
               {'properties': {'finding_id': _ID}, 'required': ['finding_id']}, tags=('findings',))
def get_finding(args: dict, ctx: ToolContext) -> dict:
    finding = load_finding(ctx, args['finding_id'])
    if finding is None:
        return {'found': False, 'finding_id': args['finding_id']}
    return {'found': True, **full_finding(finding)}


@registry.tool('list_findings', 'List findings for this tenant, optionally filtered by status, severity or asset. Sorted by severity then recency.',
               {'properties': {'status': {'type': 'string', 'description': 'open, investigating, resolved, accepted, false_positive'},
                               'severity': {'type': 'string', 'description': 'critical, high, medium, low, informational'},
                               'asset_id': {'type': 'string'}, 'limit': {'type': 'integer', 'description': 'max 200, default 50'}},
                'required': []}, tags=('findings',))
def list_findings(args: dict, ctx: ToolContext) -> dict:
    stmt = scoped(Finding, ctx.principal)
    if args.get('status'):
        stmt = stmt.where(Finding.status == args['status'])
    if args.get('severity'):
        stmt = stmt.where(Finding.severity == args['severity'])
    if args.get('asset_id'):
        stmt = stmt.where(Finding.asset_id == args['asset_id'])
    limit = clamp_limit(args.get('limit'))
    rows = ctx.db.execute(stmt.order_by(Finding.updated_at.desc()).limit(limit * 4)).scalars().all()
    rows = severity_sorted(list(rows))[:limit]
    return {'count': len(rows), 'items': [compact_finding(f) for f in rows]}


@registry.tool('find_similar_findings', 'Find findings related to a given one: same rule on other assets (likely duplicates) and other findings on the same asset.',
               {'properties': {'finding_id': _ID, 'limit': {'type': 'integer'}}, 'required': ['finding_id']}, tags=('findings',))
def find_similar_findings(args: dict, ctx: ToolContext) -> dict:
    finding = load_finding(ctx, args['finding_id'])
    if finding is None:
        return {'found': False, 'finding_id': args['finding_id'], 'same_rule': [], 'same_asset': []}
    limit = clamp_limit(args.get('limit'), default=25, maximum=100)
    base = scoped(Finding, ctx.principal).where(Finding.id != finding.id)
    same_rule = ctx.db.execute(base.where(Finding.rule == finding.rule, Finding.source == finding.source)
                               .order_by(Finding.updated_at.desc()).limit(limit)).scalars().all()
    same_asset: list[Finding] = []
    if finding.asset_id:
        same_asset = ctx.db.execute(base.where(Finding.asset_id == finding.asset_id).order_by(Finding.updated_at.desc()).limit(limit)).scalars().all()
    same_rule_ids = {f.id for f in same_rule}
    return {'found': True, 'finding_id': finding.id, 'rule': finding.rule, 'asset_id': finding.asset_id,
            'same_rule': [compact_finding(f) for f in same_rule],
            'same_asset': [compact_finding(f) for f in same_asset if f.id not in same_rule_ids],
            'open_same_rule_count': sum(1 for f in same_rule if f.status in OPEN_STATUSES)}


@registry.tool('get_finding_history', 'Audit trail for a finding: status changes, investigations, approvals and agent runs that referenced it.',
               {'properties': {'finding_id': _ID, 'limit': {'type': 'integer'}}, 'required': ['finding_id']}, tags=('findings', 'audit'))
def get_finding_history(args: dict, ctx: ToolContext) -> dict:
    finding = load_finding(ctx, args['finding_id'])
    if finding is None:
        return {'found': False, 'finding_id': args['finding_id'], 'audit': [], 'agent_runs': []}
    limit = clamp_limit(args.get('limit'), default=100, maximum=500)
    audit_stmt = (select(AuditEntry).where(AuditEntry.tenant_id == ctx.principal.tenant_id,
                                            or_(AuditEntry.subject == finding.id, AuditEntry.detail.like(like(finding.id), escape='\\')))
                  .order_by(AuditEntry.id.asc()).limit(limit))
    audit = ctx.db.execute(audit_stmt).scalars().all()
    runs = ctx.db.execute(scoped(AgentRun, ctx.principal).where(AgentRun.finding_id == finding.id, AgentRun.id != ctx.run_id)
                          .order_by(AgentRun.created_at.desc()).limit(20)).scalars().all()
    return {'found': True, 'finding_id': finding.id, 'status': finding.status, 'created_at': finding.created_at, 'updated_at': finding.updated_at,
            'occurrences': finding.occurrences,
            'audit': [{'id': a.id, 'actor': a.actor, 'actor_kind': a.actor_kind, 'action': a.action, 'subject': a.subject,
                       'detail': a.detail[:1000], 'created_at': a.created_at} for a in audit],
            'agent_runs': [{'id': r.id, 'spec': r.spec, 'status': r.status, 'created_at': r.created_at, 'finished_at': r.finished_at} for r in runs]}


def severity_rank(name: str) -> int:
    return SEVERITY_RANK.get(name, len(SEVERITY_RANK))
