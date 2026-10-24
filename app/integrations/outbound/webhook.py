"""Generic JSON webhook with an HMAC-SHA256 signature (`X-Argus-Signature: sha256=<hex>` over the
raw body) and in-call retries with exponential backoff for transient failures."""
from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any

from . import Channel, DeliveryResult, OutboundEvent, egress_error, registry, request_with_retry, result_from_response

SIGNATURE_HEADER = 'X-Argus-Signature'


def sign(secret: str, body: bytes) -> str:
    return 'sha256=' + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def build_body(event: OutboundEvent, delivery_id: str, sent_at: float | None = None) -> bytes:
    document: dict[str, Any] = {'id': delivery_id or event.delivery_id, 'topic': event.topic, 'tenant_id': event.tenant_id,
                                'sent_at': int(sent_at or time.time()), 'event': event.as_dict()}
    return json.dumps(document, sort_keys=True, separators=(',', ':'), default=str).encode()


class WebhookChannel(Channel):
    kind = 'webhook'
    description = 'HTTPS JSON POST signed with HMAC-SHA256 (X-Argus-Signature).'
    config_schema = {
        'type': 'object', 'additionalProperties': False, 'required': ['url'],
        'properties': {
            'url': {'type': 'string', 'format': 'uri', 'pattern': '^https?://', 'description': 'Destination URL (https recommended)'},
            'headers': {'type': 'object', 'description': 'Extra non-secret headers', 'additionalProperties': {'type': 'string'}},
            'timeout_seconds': {'type': 'number', 'minimum': 1, 'maximum': 60, 'default': 15},
            'retry_attempts': {'type': 'integer', 'minimum': 1, 'maximum': 5, 'default': 3},
            'retry_backoff_seconds': {'type': 'number', 'minimum': 0, 'maximum': 30, 'default': 0.5},
        },
    }
    secret_fields = ['signing_secret']
    default_topics = ['finding.*', 'detection.*', 'action.*']

    async def send(self, event: OutboundEvent, config: dict[str, Any], secrets: dict[str, str]) -> DeliveryResult:
        url = str(config.get('url') or '')
        if not url.startswith(('http://', 'https://')):
            return DeliveryResult(ok=False, error='webhook url missing or not http(s)')
        denied = egress_error(url)
        if denied:
            return DeliveryResult(ok=False, error=f'webhook url refused: {denied}')
        body = build_body(event, event.delivery_id)
        headers = {'Content-Type': 'application/json', 'User-Agent': 'Argus-Webhook/1.0', 'X-Argus-Topic': event.topic,
                   'X-Argus-Delivery': event.delivery_id, 'X-Argus-Timestamp': str(int(time.time()))}
        extra = config.get('headers') if isinstance(config.get('headers'), dict) else {}
        for key, value in extra.items():
            if str(key).lower() not in {'authorization', 'cookie', 'host', 'content-length'}:
                headers[str(key)] = str(value)
        secret = secrets.get('signing_secret') or ''
        if secret:
            headers[SIGNATURE_HEADER] = sign(secret, body)
        response, error = await request_with_retry(lambda client: client.post(url, content=body, headers=headers),
                                                   attempts=int(config.get('retry_attempts') or 3), backoff=float(config.get('retry_backoff_seconds', 0.5)),
                                                   timeout=float(config.get('timeout_seconds') or 15))
        return result_from_response(response, error)


registry.register(WebhookChannel())
