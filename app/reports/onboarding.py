"""Get-started checklist for a new tenant. Each step is marked done from the tenant's own rows, so
progress reflects what has really been set up rather than what the user has clicked through."""
from __future__ import annotations

from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import AgentRun, Membership, SecurityEvent
from ..models.collectors import CollectorConfig
from ..models.detections import Detection
from ..models.integrations import IntegrationConfig


def _any(db: Session, column, *where) -> bool:
    return db.scalar(select(column).where(*where).limit(1)) is not None


def onboarding(db: Session, tenant_id: str) -> dict[str, Any]:
    members = int(db.scalar(select(func.count()).select_from(Membership).where(Membership.tenant_id == tenant_id)) or 0)
    source = (_any(db, CollectorConfig.id, CollectorConfig.tenant_id == tenant_id)
              or _any(db, IntegrationConfig.id, IntegrationConfig.tenant_id == tenant_id))
    # `perm` is what the user needs to act on the step; the console uses it to decide whether to link.
    steps = [
        {'id': 'source', 'title': 'Connect a data source', 'perm': 'collectors:write', 'href': '#/collectors/types',
         'description': 'Add a collector for your cloud, identity or code platform, or an integration for an existing tool.',
         'done': source},
        {'id': 'events', 'title': 'Receive your first events', 'perm': 'integrations:read', 'href': '#/integrations/ingest',
         'description': 'Run a collector or send alerts to an ingest endpoint. Events feed the detection rules.',
         'done': _any(db, SecurityEvent.id, SecurityEvent.tenant_id == tenant_id)},
        {'id': 'triage', 'title': 'Triage a detection', 'perm': 'detections:write', 'href': '#/detections',
         'description': 'Open a detection and move it to investigating, resolved or false positive.',
         'done': _any(db, Detection.id, Detection.tenant_id == tenant_id, Detection.status != 'open')},
        {'id': 'agent', 'title': 'Run an agent investigation', 'perm': 'agents:run', 'href': '#/agents',
         'description': 'Let a specialist agent gather evidence on a finding or detection and report back.',
         'done': _any(db, AgentRun.id, AgentRun.tenant_id == tenant_id)},
        {'id': 'team', 'title': 'Invite a teammate', 'perm': 'admin:users', 'href': '#/admin/users',
         'description': 'Add the people who will review detections and approve response actions.',
         'done': members > 1},
    ]
    return {'steps': steps, 'completed': sum(1 for s in steps if s['done']), 'total': len(steps)}
