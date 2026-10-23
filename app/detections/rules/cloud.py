"""Cloud control-plane rules."""
from __future__ import annotations

import re

from ...models import dumps
from ..engine import DetectionDraft, DetectionRule, RuleContext, registry
from ..util import event_time, iso, meta, source_ip, user_agent, window_bucket

_WILDCARD_PRINCIPAL = re.compile(r'"(Principal|AWS|principal|members?)":\s*(\[\s*)?"\*"')


class PublicExposureChange(DetectionRule):
    id = 'cloud.public_exposure_change'
    name = 'Public exposure change'
    severity = 'high'
    category = 'cloud'
    description = ('A bucket policy, ACL, security group or IAM binding was changed to allow the whole internet (0.0.0.0/0, ::/0, '
                   'allUsers or a wildcard principal).')
    remediation = 'Revert the policy or rule, confirm nothing was read while it was open, and add a guardrail (SCP, org policy, Azure policy) against public grants.'
    default_params = {
        'actions': ['s3.put_bucket_policy', 's3.put_bucket_acl', 's3.put_object_acl', 's3.delete_public_access_block', 'ec2.authorize_security_group_ingress',
                    'ec2.modify_security_group_rules', 'storage.set_iam_policy', 'storage.buckets.set_iam_policy', 'compute.firewalls.insert',
                    'compute.firewalls.patch', 'az.network.nsg.rule.write', 'az.storage.account.write', 'az.storage.container.write',
                    'microsoft.network/networksecuritygroups/securityrules/write', 'putbucketpolicy', 'putbucketacl', 'authorizesecuritygroupingress',
                    'setiampolicy'],
        'markers': ['0.0.0.0/0', '::/0', 'allUsers', 'allAuthenticatedUsers', 'public-read', 'public-read-write', 'authenticated-read', 'Internet',
                    '"Any"', '"public":true', '"publicAccess":"blob"', '"publicAccess":"container"', '"allowBlobPublicAccess":true'],
        'bucket_minutes': 60,
    }

    def evaluate(self, ctx: RuleContext) -> list[DetectionDraft]:
        wanted = {a.lower() for a in ctx.param('actions', [])}
        markers = list(ctx.param('markers', []))
        bucket_minutes = int(ctx.param('bucket_minutes', 60))
        drafts: list[DetectionDraft] = []
        for event in ctx.events(actions=sorted({*wanted, *(a for a in self.default_params['actions'])})):
            if (event.action or '').lower() not in wanted:
                continue
            data = meta(event)
            text = dumps(data)
            matched = [m for m in markers if m in text]
            if _WILDCARD_PRINCIPAL.search(text):
                matched.append('Principal:*')
            if data.get('public') is True and '"public":true' not in matched:
                matched.append('public')
            if not matched:
                continue
            when = event_time(event)
            drafts.append(DetectionDraft(
                rule_id=self.id, severity=self.severity, confidence=0.9,
                title=f'{event.entity or "resource"} opened to the internet via {event.action}',
                description=(f'`{event.actor or "unknown actor"}` executed `{event.action}` on {event.entity or "a resource"} at {iso(when)} with '
                             f'public indicators {", ".join(sorted(set(matched)))}.'),
                entity=event.entity or event.action, entity_kind='asset', asset_id=event.asset_id, fingerprint_parts=[event.entity or '', event.action],
                window_bucket=window_bucket(when, bucket_minutes), first_seen_at=when, last_seen_at=when,
                evidence={'action': event.action, 'entity': event.entity, 'actor': event.actor, 'markers': sorted(set(matched)), 'source': event.source,
                          'source_ip': source_ip(event), 'user_agent': user_agent(event), 'region': data.get('region') or data.get('awsRegion') or '',
                          'account': data.get('account') or data.get('account_id') or data.get('project') or data.get('subscription') or '',
                          'event_ids': [event.id]}))
        return drafts


registry.register(PublicExposureChange())
