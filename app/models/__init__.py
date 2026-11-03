"""Import every model module so Base.metadata is complete before create_all / Alembic."""
from __future__ import annotations

from .actions import ActionApproval, ActionRequest, ActionRun  # noqa: F401
from .agents import AgentRun, AgentStep, EvalRun  # noqa: F401
from .ai import AIDiscoveryState, AIGatewayRequest, AIService  # noqa: F401
from .audit import AuditEntry, AuditSinkDelivery  # noqa: F401
from .autoresponse import AutoresponseExecution, ResponsePlaybook  # noqa: F401
from .base import Base, TenantMixin, dumps, loads, uid, utcnow  # noqa: F401
from .collectors import CollectorConfig, CollectorRun  # noqa: F401
from .detections import Baseline, Canary, CanaryHit, Detection, DetectionRuleState, DetectionRun  # noqa: F401
from .discovery import Discovery, DiscoveryRun, RequestCapture  # noqa: F401
from .exploit import PocArtifact, PocRequest  # noqa: F401
from .findings import Approval, Finding, Investigation, ScanRun, SecurityEvent  # noqa: F401
from .graph import AttackPath, GraphEdge, GraphNode  # noqa: F401
from .identity import ApiKey, Membership, OidcIdentity, Tenant, User  # noqa: F401
from .integrations import IngestBatch, IntegrationConfig, WebhookDelivery  # noqa: F401
from .inventory import Asset, AssetAuthorization, AssetCredential  # noqa: F401
from .oob import OobToken  # noqa: F401
from .ops import BackupRecord  # noqa: F401
from .simulation import AutopilotRun, SimulationRun  # noqa: F401
from .testing import PentestHypothesis, PentestRun, TestPlan, TestResult, TestRun, TestScope  # noqa: F401
