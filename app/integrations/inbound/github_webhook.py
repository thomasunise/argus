"""GitHub webhooks: secret_scanning_alert, code_scanning_alert, dependabot_alert, repository
(publicized), member / organization (admin grants), branch_protection_rule deletions. The
event kind comes from X-GitHub-Event when the header is present, otherwise from the body shape.
Signature verification implements X-Hub-Signature-256 (HMAC-SHA256 of the raw body)."""
from __future__ import annotations

import hashlib
import hmac
from typing import Any

from ...core.findings import EventDraft
from . import registry
from ._common import FindingDraft, ParseContext, Parser, dig, event, first, hash_item, snake

_ADMIN_ROLES = {'admin', 'maintain', 'owner'}
_FINDING_ACTIONS = {'created', 'reopened', 'reintroduced', 'appeared_in_branch'}
_RESOLVED_ACTIONS = {'resolved', 'fixed', 'dismissed', 'closed_by_user', 'auto_dismissed'}


def _event_kind(item: dict, header: str) -> str:
    if header:
        return header.strip().lower()
    alert = item.get('alert') if isinstance(item.get('alert'), dict) else None
    if alert is not None:
        if 'secret_type' in alert:
            return 'secret_scanning_alert'
        if 'security_advisory' in alert or 'dependency' in alert:
            return 'dependabot_alert'
        if 'rule' in alert or 'tool' in alert:
            return 'code_scanning_alert'
    if 'member' in item and 'repository' in item:
        return 'member'
    if 'membership' in item and 'organization' in item and 'repository' not in item:
        return 'organization'
    if 'rule' in item and item.get('action') in {'created', 'edited', 'deleted'} and 'repository' in item:
        return 'branch_protection_rule'
    if 'repository' in item and item.get('action') in {'publicized', 'privatized', 'created', 'deleted', 'archived', 'transferred', 'renamed'}:
        return 'repository'
    return str(item.get('event') or 'unknown')


class GitHubWebhookParser(Parser):
    name = 'github_webhook'
    aliases = ('github',)
    source = 'github'
    description = 'GitHub webhooks: secret scanning, code scanning, Dependabot, repository visibility and admin grants.'
    kind = 'both'
    example = 'tests/fixtures/integrations/github_webhook/secret_scanning_alert.json'
    supports_verify = True
    secret_fields = ['webhook_secret']

    def parse_item(self, item: dict, ctx: ParseContext) -> list[EventDraft]:
        kind = _event_kind(item, ctx.header('X-GitHub-Event'))
        action_name = str(item.get('action') or '')
        repo = item.get('repository') if isinstance(item.get('repository'), dict) else {}
        org = item.get('organization') if isinstance(item.get('organization'), dict) else {}
        sender = item.get('sender') if isinstance(item.get('sender'), dict) else {}
        repo_name = str(repo.get('full_name') or org.get('login') or '')
        actor = str(sender.get('login') or '')
        delivery = ctx.header('X-GitHub-Delivery')
        alert = item.get('alert') if isinstance(item.get('alert'), dict) else {}
        number = alert.get('number')
        base: dict[str, Any] = {'repo': repo_name, 'repository': repo_name, 'github_event': kind, 'github_action': action_name, 'service': 'github',
                                'private': repo.get('private'), 'default_branch': repo.get('default_branch') or '', 'org': org.get('login') or dig(repo, 'owner', 'login') or '',
                                'delivery': delivery, 'ip': '', 'user_agent': ctx.header('User-Agent')}
        ext = delivery or hash_item({'k': kind, 'r': repo_name, 'n': number, 'a': action_name, 'u': alert.get('updated_at') or item.get('updated_at')})
        if kind == 'secret_scanning_alert':
            secret_type = str(alert.get('secret_type_display_name') or alert.get('secret_type') or 'secret')
            verified = str(alert.get('validity') or '').lower() == 'active' or alert.get('push_protection_bypassed') is True
            meta = {**base, 'secret_type': str(alert.get('secret_type') or secret_type), 'validity': alert.get('validity') or '', 'verified': verified,
                    'alert_number': number, 'url': alert.get('html_url') or '', 'state': alert.get('state') or '', 'resolution': alert.get('resolution') or '',
                    'push_protection_bypassed': alert.get('push_protection_bypassed'), 'publicly_leaked': alert.get('publicly_leaked'),
                    'multi_repo': alert.get('multi_repo'), 'author': dig(alert, 'resolved_by', 'login') or actor}
            if action_name in _FINDING_ACTIONS or action_name == 'validated':
                severity = 'critical' if verified or alert.get('publicly_leaked') else 'high'
                return [event(self.source, ext, f'{secret_type} committed to {repo_name}', severity=severity, category='code', actor=actor, entity=repo_name,
                              action='secret_detected', occurred_at=first(alert, 'created_at', 'updated_at'), metadata=meta)]
            return [event(self.source, ext, f'Secret scanning alert #{number} {action_name} in {repo_name}', severity='low', category='code', actor=actor,
                          entity=repo_name, action=f'github.secret_scanning_alert.{snake(action_name)}', occurred_at=first(alert, 'resolved_at', 'updated_at'), metadata=meta)]
        if kind == 'code_scanning_alert':
            rule = alert.get('rule') if isinstance(alert.get('rule'), dict) else {}
            tool = alert.get('tool') if isinstance(alert.get('tool'), dict) else {}
            loc = dig(alert, 'most_recent_instance', 'location') or {}
            sev = str(rule.get('security_severity_level') or rule.get('severity') or 'medium')
            meta = {**base, 'rule_id': rule.get('id') or '', 'rule_name': rule.get('name') or '', 'tool': tool.get('name') or '', 'alert_number': number,
                    'url': alert.get('html_url') or '', 'state': alert.get('state') or '', 'file': loc.get('path') or '', 'line': loc.get('start_line'),
                    'ref': dig(alert, 'most_recent_instance', 'ref') or item.get('ref') or '', 'commit': item.get('commit_oid') or ''}
            severity = sev if action_name in _FINDING_ACTIONS else 'informational'
            return [event(self.source, ext, f'Code scanning: {rule.get("description") or rule.get("id") or "alert"} ({action_name})', severity=severity, category='code',
                          actor=actor, entity=repo_name, action=f'github.code_scanning_alert.{snake(action_name)}', occurred_at=first(alert, 'created_at', 'updated_at'), metadata=meta)]
        if kind == 'dependabot_alert':
            adv = alert.get('security_advisory') if isinstance(alert.get('security_advisory'), dict) else {}
            dep = alert.get('dependency') if isinstance(alert.get('dependency'), dict) else {}
            pkg = dep.get('package') if isinstance(dep.get('package'), dict) else {}
            sev = str(adv.get('severity') or dig(alert, 'security_vulnerability', 'severity') or 'medium')
            meta = {**base, 'ghsa_id': adv.get('ghsa_id') or '', 'cve_id': adv.get('cve_id') or '', 'package': pkg.get('name') or '', 'ecosystem': pkg.get('ecosystem') or '',
                    'manifest': dep.get('manifest_path') or '', 'scope': dep.get('scope') or '', 'alert_number': number, 'url': alert.get('html_url') or '',
                    'state': alert.get('state') or '', 'fixed_in': dig(alert, 'security_vulnerability', 'first_patched_version', 'identifier') or '',
                    'vulnerable_range': dig(alert, 'security_vulnerability', 'vulnerable_version_range') or '', 'cvss': dig(adv, 'cvss', 'score')}
            severity = sev if action_name in _FINDING_ACTIONS else 'informational'
            return [event(self.source, ext, f'Dependabot: {adv.get("summary") or adv.get("ghsa_id") or "alert"} in {pkg.get("name") or "dependency"} ({action_name})',
                          severity=severity, category='code', actor=actor, entity=repo_name, action=f'github.dependabot_alert.{snake(action_name)}',
                          occurred_at=first(alert, 'created_at', 'updated_at'), metadata=meta)]
        if kind == 'repository':
            severity = 'high' if action_name == 'publicized' else 'medium' if action_name in {'deleted', 'transferred'} else 'low'
            meta = {**base, 'visibility': repo.get('visibility') or ('public' if repo.get('private') is False else ''), 'url': repo.get('html_url') or '',
                    'public': action_name == 'publicized' or repo.get('private') is False, 'markers': ['public'] if action_name == 'publicized' else []}
            return [event(self.source, ext, f'Repository {repo_name} {action_name}', severity=severity, category='code', actor=actor, entity=repo_name,
                          action=f'github.repository.{snake(action_name)}', occurred_at=repo.get('updated_at') or item.get('updated_at'), metadata=meta)]
        if kind == 'member':
            member = item.get('member') if isinstance(item.get('member'), dict) else {}
            permission = str(dig(item, 'changes', 'permission', 'to') or dig(item, 'changes', 'role_name', 'to') or item.get('permission') or '').lower()
            target = str(member.get('login') or '')
            if action_name in {'added', 'edited'} and permission in _ADMIN_ROLES:
                meta = {**base, 'member': target, 'permission': permission, 'role': permission, 'url': member.get('html_url') or ''}
                return [event(self.source, ext, f'{target} granted {permission} on {repo_name}', severity='high', category='identity', actor=actor,
                              entity=f'{repo_name}:{target}', action='permission_added', occurred_at=item.get('updated_at'), metadata=meta)]
            meta = {**base, 'member': target, 'permission': permission}
            return [event(self.source, ext, f'Member {target} {action_name} on {repo_name}', severity='low', category='identity', actor=actor,
                          entity=f'{repo_name}:{target}', action=f'github.member.{snake(action_name)}', metadata=meta)]
        if kind == 'organization':
            membership = item.get('membership') if isinstance(item.get('membership'), dict) else {}
            target = str(dig(membership, 'user', 'login') or '')
            role = str(membership.get('role') or dig(item, 'changes', 'role', 'to') or '').lower()
            if action_name in {'member_added', 'member_edited'} and role in _ADMIN_ROLES:
                meta = {**base, 'member': target, 'role': role, 'permission': role}
                return [event(self.source, ext, f'{target} granted {role} in organization {repo_name}', severity='high', category='identity', actor=actor,
                              entity=f'{repo_name}:{target}', action='permission_added', metadata=meta)]
            return [event(self.source, ext, f'Organization {repo_name}: {action_name} {target}'.strip(), severity='low', category='identity', actor=actor,
                          entity=f'{repo_name}:{target}', action=f'github.organization.{snake(action_name)}', metadata={**base, 'member': target, 'role': role})]
        if kind == 'branch_protection_rule':
            rule = item.get('rule') if isinstance(item.get('rule'), dict) else {}
            severity = 'high' if action_name == 'deleted' else 'low'
            return [event(self.source, ext, f'Branch protection {action_name} on {repo_name}:{rule.get("name") or ""}', severity=severity, category='code', actor=actor,
                          entity=repo_name, action=f'github.branch_protection_rule.{snake(action_name)}', metadata={**base, 'branch_pattern': rule.get('name') or ''})]
        if kind in {'ping', 'unknown'} and 'zen' in item:
            return []
        return [event(self.source, ext, f'GitHub {kind} {action_name}'.strip(), severity='informational', category='code', actor=actor, entity=repo_name,
                      action=f'github.{snake(kind)}.{snake(action_name)}'.rstrip('.'), metadata=base)]

    def findings_for_item(self, item: dict, ctx: ParseContext) -> list[FindingDraft]:
        kind = _event_kind(item, ctx.header('X-GitHub-Event'))
        action_name = str(item.get('action') or '')
        if kind not in {'dependabot_alert', 'code_scanning_alert'} or action_name not in _FINDING_ACTIONS:
            return []
        alert = item.get('alert') if isinstance(item.get('alert'), dict) else {}
        repo = dig(item, 'repository', 'full_name') or ''
        if kind == 'dependabot_alert':
            adv = alert.get('security_advisory') if isinstance(alert.get('security_advisory'), dict) else {}
            dep = alert.get('dependency') if isinstance(alert.get('dependency'), dict) else {}
            pkg = dig(dep, 'package', 'name') or 'dependency'
            ident = adv.get('ghsa_id') or adv.get('cve_id') or f'alert-{alert.get("number")}'
            cve = adv.get('cve_id')
            return [FindingDraft(source=self.source, rule=f'dependabot:{repo}:{dep.get("manifest_path") or ""}:{ident}', title=f'{ident}: {str(adv.get("summary") or pkg)[:200]}',
                                 description=f'Dependabot alert #{alert.get("number")} in {repo}: {pkg} ({dig(dep, "package", "ecosystem") or ""}) is affected by {ident}. '
                                             f'{str(adv.get("description") or "")[:800]}',
                                 remediation=f'Upgrade {pkg} to {dig(alert, "security_vulnerability", "first_patched_version", "identifier") or "a patched version"}.',
                                 severity=str(adv.get('severity') or 'medium'), cve_ids=[cve] if cve else [], cvss=dig(adv, 'cvss', 'score'),
                                 evidence={'repository': repo, 'package': pkg, 'manifest': dep.get('manifest_path'), 'ghsa_id': adv.get('ghsa_id'), 'url': alert.get('html_url'),
                                           'vulnerable_range': dig(alert, 'security_vulnerability', 'vulnerable_version_range')},
                                 tags=['github', 'dependabot'])]
        rule = alert.get('rule') if isinstance(alert.get('rule'), dict) else {}
        loc = dig(alert, 'most_recent_instance', 'location') or {}
        rule_id = str(rule.get('id') or 'rule')
        return [FindingDraft(source=self.source, rule=f'code_scanning:{repo}:{loc.get("path") or ""}:{rule_id}', title=f'{rule.get("description") or rule_id} in {repo}',
                             description=f'Code scanning alert #{alert.get("number")} ({dig(alert, "tool", "name") or "scanner"}) at {loc.get("path") or "unknown path"}'
                                         f':{loc.get("start_line") or "?"}. {str(rule.get("full_description") or "")[:600]}',
                             remediation=str(rule.get('help') or 'Review the flagged code path and apply the scanner recommendation.')[:600],
                             severity=str(rule.get('security_severity_level') or rule.get('severity') or 'medium'),
                             evidence={'repository': repo, 'rule_id': rule_id, 'tool': dig(alert, 'tool', 'name'), 'file': loc.get('path'), 'line': loc.get('start_line'),
                                       'url': alert.get('html_url'), 'ref': dig(alert, 'most_recent_instance', 'ref')},
                             tags=['github', 'code_scanning'])]

    def verify(self, ctx: ParseContext, body: bytes, secret: str) -> bool:
        given = ctx.header('X-Hub-Signature-256')
        if not given or not secret or not given.startswith('sha256='):
            return False
        expected = 'sha256=' + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        return hmac.compare_digest(given.strip(), expected)


registry.register(GitHubWebhookParser())
