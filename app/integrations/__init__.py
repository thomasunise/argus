"""Integrations: inbound parsers + ingest pipeline, outbound channels + event-bus deliveries, and
the legacy Wazuh indexer pull job.

Public interface for other packages:
  from app.integrations import inbound_registry, outbound_registry, ingest, IngestResult
  from app.integrations.inbound import Parser, ParseContext, FindingDraft
  from app.integrations.outbound import OutboundEvent, DeliveryResult, Channel
  from app.integrations.delivery import build_event, send_delivery, create_deliveries

setup(app) registers the queue handlers `integrations.fanout`, `integrations.deliver` and
`integrations.wazuh_sync`, subscribes to the event bus ('*', filtered to finding/detection/action/testing/agent
topics) and adds the Wazuh pull scheduler startup hook.
"""
from __future__ import annotations

import logging

from .inbound import registry as inbound_registry  # noqa: F401
from .ingest import IngestResult, ingest  # noqa: F401
from .outbound import registry as outbound_registry  # noqa: F401

log = logging.getLogger('argus.integrations')


def setup(app) -> None:
    inbound_registry.load_builtin()
    outbound_registry.load_builtin()
    from . import delivery, wazuh_sync

    delivery.install(app)
    wazuh_sync.install(app)


__all__ = ['setup', 'inbound_registry', 'outbound_registry', 'ingest', 'IngestResult']
