"""Source-code rules. Evidence is whitelisted so a detected secret never reaches the database."""
from __future__ import annotations

from ..engine import DetectionDraft, DetectionRule, RuleContext, registry
from ..util import event_time, first_present, iso, meta, window_bucket

_HIGH_VALUE = {'aws', 'aws_access_key', 'aws-access-token', 'private_key', 'private-key', 'rsa', 'gcp', 'gcp_service_account', 'github', 'github_pat',
               'slack_token', 'stripe', 'azure', 'db_password', 'database'}


class SecretCommitted(DetectionRule):
    id = 'code.secret_committed'
    name = 'Secret committed to source'
    severity = 'high'
    category = 'code'
    description = 'A secret scanner reported a credential committed to a repository. Committed secrets must be treated as leaked.'
    remediation = 'Rotate the credential first, then purge it from history and add a pre-commit secret scan to the repository.'
    default_params = {'actions': ['secret_detected', 'gitleaks.secret', 'secret.committed', 'trufflehog.verified'], 'bucket_minutes': 1440}

    def evaluate(self, ctx: RuleContext) -> list[DetectionDraft]:
        wanted = {a.lower() for a in ctx.param('actions', [])}
        bucket_minutes = int(ctx.param('bucket_minutes', 1440))
        drafts: list[DetectionDraft] = []
        for event in ctx.events(category='code'):
            if (event.action or '').lower() not in wanted:
                continue
            data = meta(event)
            secret_type = str(first_present(data, 'secret_type', 'rule_id', 'rule', 'detector', 'type', default='secret'))[:80]
            path = str(first_present(data, 'file', 'path', 'file_path', default=''))[:300]
            commit = str(first_present(data, 'commit', 'sha', 'commit_sha', default=''))[:64]
            when = event_time(event)
            repo = event.entity or str(data.get('repo') or data.get('repository') or 'repository')
            severity = 'critical' if any(tag in secret_type.lower() for tag in _HIGH_VALUE) or data.get('verified') is True else self.severity
            drafts.append(DetectionDraft(
                rule_id=self.id, severity=severity, confidence=0.95 if data.get('verified') is True else 0.85,
                title=f'{secret_type} committed to {repo}' + (f' ({path})' if path else ''),
                description=f'A {secret_type} was detected in {repo}{" at " + path if path else ""}{" in commit " + commit[:12] if commit else ""} at {iso(when)}.',
                entity=repo, entity_kind='asset', asset_id=event.asset_id, fingerprint_parts=[repo, path, secret_type],
                window_bucket=window_bucket(when, bucket_minutes), first_seen_at=when, last_seen_at=when,
                # Whitelisted evidence only: the matched secret value never leaves the scanner event.
                evidence={'repository': repo, 'secret_type': secret_type, 'file': path, 'commit': commit, 'line': data.get('line') or data.get('line_number'),
                          'branch': str(data.get('branch') or '')[:120], 'author': str(data.get('author') or event.actor or '')[:120],
                          'verified': bool(data.get('verified')), 'scanner': event.source, 'event_ids': [event.id]}))
        return drafts


registry.register(SecretCommitted())
