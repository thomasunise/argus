"""Email via SMTP (smtplib, STARTTLS) executed in a worker thread."""
from __future__ import annotations

import asyncio
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from html import escape
from typing import Any

from . import Channel, DeliveryResult, OutboundEvent, registry, severity_label


def build_message(event: OutboundEvent, config: dict[str, Any]) -> EmailMessage:
    prefix = str(config.get('subject_prefix') or '[Sentinel]')
    message = EmailMessage()
    message['Subject'] = f'{prefix} {severity_label(event.severity)}: {event.title}'[:200]
    message['From'] = str(config.get('from') or 'sentinel@localhost')
    message['To'] = ', '.join(str(x) for x in (config.get('to') or []))
    message['Date'] = formatdate(localtime=False)
    message['Message-ID'] = make_msgid(domain=str(config.get('message_id_domain') or 'sentinel.local'))
    message['X-Sentinel-Topic'] = event.topic
    message['X-Sentinel-Delivery'] = event.delivery_id
    lines = [f'Topic: {event.topic}', f'Severity: {severity_label(event.severity)}', f'Subject: {event.subject_kind} {event.subject_id}']
    if event.status:
        lines.append(f'Status: {event.status}')
    if event.summary:
        lines += ['', event.summary]
    if event.url:
        lines += ['', f'Open in Sentinel: {event.url}']
    message.set_content('\n'.join(lines))
    rows = ''.join(f'<tr><th align="left">{escape(k)}</th><td>{escape(str(v))}</td></tr>' for k, v in
                   (('Topic', event.topic), ('Severity', severity_label(event.severity)), ('Subject', f'{event.subject_kind} {event.subject_id}'), ('Status', event.status or '-')))
    link = f'<p><a href="{escape(event.url)}">Open in Sentinel</a></p>' if event.url else ''
    message.add_alternative(f'<html><body><h2>{escape(event.title)}</h2><table>{rows}</table><p>{escape(event.summary)}</p>{link}</body></html>', subtype='html')
    return message


def _send_sync(message: EmailMessage, config: dict[str, Any], secrets: dict[str, str]) -> None:
    host = str(config.get('host') or 'localhost')
    port = int(config.get('port') or 587)
    timeout = float(config.get('timeout_seconds') or 20)
    use_tls = bool(config.get('use_ssl'))
    starttls = config.get('use_starttls', True) is not False
    context = ssl.create_default_context()
    smtp_cls = smtplib.SMTP_SSL if use_tls else smtplib.SMTP
    with (smtp_cls(host, port, timeout=timeout, context=context) if use_tls else smtp_cls(host, port, timeout=timeout)) as smtp:
        smtp.ehlo()
        if starttls and not use_tls:
            smtp.starttls(context=context)
            smtp.ehlo()
        username, password = secrets.get('username') or '', secrets.get('password') or ''
        if username:
            smtp.login(username, password)
        smtp.send_message(message)


class EmailChannel(Channel):
    kind = 'email'
    description = 'Email notification via SMTP with STARTTLS.'
    config_schema = {
        'type': 'object', 'additionalProperties': False, 'required': ['host', 'from', 'to'],
        'properties': {
            'host': {'type': 'string'}, 'port': {'type': 'integer', 'minimum': 1, 'maximum': 65535, 'default': 587},
            'from': {'type': 'string', 'format': 'email'}, 'to': {'type': 'array', 'items': {'type': 'string'}, 'minItems': 1},
            'use_starttls': {'type': 'boolean', 'default': True}, 'use_ssl': {'type': 'boolean', 'default': False},
            'subject_prefix': {'type': 'string', 'default': '[Sentinel]'}, 'timeout_seconds': {'type': 'number', 'minimum': 1, 'maximum': 120, 'default': 20},
            'message_id_domain': {'type': 'string'},
        },
    }
    secret_fields = ['username', 'password']
    default_topics = ['finding.created']

    async def send(self, event: OutboundEvent, config: dict[str, Any], secrets: dict[str, str]) -> DeliveryResult:
        recipients = [str(x) for x in (config.get('to') or []) if x]
        if not recipients or not config.get('host'):
            return DeliveryResult(ok=False, error='email needs host and at least one recipient')
        message = build_message(event, config)
        try:
            await asyncio.to_thread(_send_sync, message, config, secrets)
        except (smtplib.SMTPException, OSError) as exc:
            retryable = not isinstance(exc, (smtplib.SMTPAuthenticationError, smtplib.SMTPRecipientsRefused, smtplib.SMTPSenderRefused))
            return DeliveryResult(ok=False, error=f'{type(exc).__name__}: {str(exc)[:200]}', retryable=retryable)
        return DeliveryResult(ok=True, status_code=250, external_ref=str(message['Message-ID']), detail={'recipients': recipients})


registry.register(EmailChannel())
