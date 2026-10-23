"""GitHub collector (httpx against the REST API, read-only). Inventories an organization's
repositories, branch protection, Dependabot / secret-scanning / code-scanning alerts and admin
collaborators. Secret values are never requested (the secret-scanning alert endpoint returns
the matched secret; the normalizer drops it before anything is persisted).

API calls made (GET, paginated via the Link header, per_page=100):
  GET /orgs/{org}
  GET /orgs/{org}/repos?type=all
  GET /repos/{org}/{repo}/branches/{default_branch}/protection
  GET /repos/{org}/{repo}/dependabot/alerts?state=open
  GET /repos/{org}/{repo}/secret-scanning/alerts?state=open
  GET /repos/{org}/{repo}/code-scanning/alerts?state=open
  GET /repos/{org}/{repo}/collaborators?affiliation=all
Token: fine-grained PAT or GitHub App token with read-only Metadata, Administration (for branch
protection and collaborators), Dependabot alerts, Secret scanning alerts and Code scanning alerts.
"""
from __future__ import annotations

import logging
import re
from typing import Any

import httpx

from .base import Collector, CollectorContext, CollectorResult, parse_time, registry

log = logging.getLogger('sentinel.collectors.github')

API_VERSION = '2022-11-28'
SEVERITY_MAP = {'critical': 'critical', 'high': 'high', 'medium': 'medium', 'moderate': 'medium', 'low': 'low', 'error': 'high', 'warning': 'medium', 'note': 'low'}


class GithubCollector(Collector):
    name = 'github'
    kind = 'code'
    description = 'GitHub organization inventory: repositories, default-branch protection, Dependabot, secret-scanning and code-scanning alerts, admin collaborators, public repos.'
    sdk_modules = ('httpx',)
    secret_fields = ['token']
    default_schedule_minutes = 120
    config_schema = {
        'type': 'object', 'additionalProperties': False, 'required': ['org'],
        'properties': {
            'org': {'type': 'string', 'pattern': r'^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$'},
            'api_url': {'type': 'string', 'pattern': r'^https://', 'description': 'GitHub Enterprise Server API base; default https://api.github.com'},
            'include_archived': {'type': 'boolean'},
            'max_repos': {'type': 'integer', 'minimum': 1, 'maximum': 5000},
        },
    }

    async def collect(self, ctx: CollectorContext) -> CollectorResult:
        raw = await _fetch(ctx)
        return self._normalize(raw)

    def _normalize(self, raw: dict[str, Any]) -> CollectorResult:
        r = CollectorResult()
        source = self.source
        org = raw.get('org') or {}
        login = org.get('login') or raw.get('org_login') or ''
        counts = {'repos': 0, 'public_repos': 0, 'unprotected_default_branches': 0, 'dependabot_alerts': 0, 'secret_scanning_alerts': 0, 'code_scanning_alerts': 0,
                  'admin_collaborators': 0}
        for warning in raw.get('warnings', []) or []:
            r.warn(str(warning))
        onode = r.node('asset', f'github:org:{login}', {'provider': 'github', 'type': 'organization', 'login': login, 'two_factor_requirement_enabled': org.get('two_factor_requirement_enabled'),
                                                        'members_can_create_public_repositories': org.get('members_can_create_public_repositories'),
                                                        'plan': (org.get('plan') or {}).get('name')}, label=f'GitHub org {login}', criticality='high')
        if org.get('two_factor_requirement_enabled') is False:
            r.event(source, f'github:{login}:2fa-not-required', f'GitHub organization {login} does not require two-factor authentication', 'high', 'code',
                    entity=onode.key, action='org_2fa_not_required', metadata={'org': login})
        for repo in raw.get('repos', []) or []:
            full = repo.get('full_name') or f"{login}/{repo.get('name')}"
            default_branch = repo.get('default_branch') or 'main'
            protection = repo.get('branch_protection')
            prot_known = protection is not None and protection != 'unknown'
            protected = bool(protection) and prot_known
            reviews = (protection or {}).get('required_pull_request_reviews') if prot_known else None
            public = repo.get('visibility', 'private' if repo.get('private', True) else 'public') == 'public'
            counts['repos'] += 1
            counts['public_repos'] += int(public)
            node = r.node('asset', f'github:repo:{full}', {'provider': 'github', 'type': 'repository', 'full_name': full, 'default_branch': default_branch,
                                                           'visibility': 'public' if public else repo.get('visibility', 'private'), 'archived': bool(repo.get('archived')),
                                                           'language': repo.get('language'), 'pushed_at': repo.get('pushed_at'),
                                                           'branch_protected': protected if prot_known else None,
                                                           'required_reviews': (reviews or {}).get('required_approving_review_count') if reviews else 0,
                                                           'enforce_admins': bool(((protection or {}).get('enforce_admins') or {}).get('enabled')) if prot_known else None,
                                                           'allow_force_pushes': bool(((protection or {}).get('allow_force_pushes') or {}).get('enabled')) if prot_known else None,
                                                           'secret_scanning': ((repo.get('security_and_analysis') or {}).get('secret_scanning') or {}).get('status'),
                                                           'open_alerts': {'dependabot': len(repo.get('dependabot_alerts') or []), 'secret_scanning': len(repo.get('secret_scanning_alerts') or []),
                                                                           'code_scanning': len(repo.get('code_scanning_alerts') or [])}},
                          label=full, criticality='high' if public else 'medium')
            r.edge(onode, node, 'owns')
            if public:
                exposure = r.node('exposure', f'github:exposure:public-repo:{full}', {'type': 'public_repository'}, label=f'Public repo {full}', criticality='medium')
                r.edge(node, exposure, 'exposes')
            if prot_known and not protected and not repo.get('archived'):
                counts['unprotected_default_branches'] += 1
                r.event(source, f'github:{full}:unprotected:{default_branch}', f'{full} default branch {default_branch} has no branch protection', 'medium', 'code',
                        entity=node.key, action='branch_unprotected', metadata={'repo': full, 'branch': default_branch, 'public': public})
            for alert in repo.get('dependabot_alerts') or []:
                counts['dependabot_alerts'] += 1
                adv = alert.get('security_advisory') or {}
                vuln = alert.get('security_vulnerability') or {}
                pkg = (vuln.get('package') or {}).get('name') or (alert.get('dependency') or {}).get('package', {}).get('name', '')
                eco = (vuln.get('package') or {}).get('ecosystem', '')
                sev = SEVERITY_MAP.get(str(vuln.get('severity') or adv.get('severity') or 'medium').lower(), 'medium')
                cves = [i.get('value') for i in adv.get('identifiers') or [] if i.get('type') == 'CVE']
                ghsa = adv.get('ghsa_id', '')
                vnode = r.node('vuln', f"github:vuln:{ghsa or cves[0] if (ghsa or cves) else alert.get('number')}:{eco}:{pkg}",
                               {'provider': 'github', 'type': 'dependency', 'ghsa_id': ghsa, 'cve_ids': cves, 'package': pkg, 'ecosystem': eco, 'severity': sev,
                                'vulnerable_range': vuln.get('vulnerable_version_range'), 'patched_version': (vuln.get('first_patched_version') or {}).get('identifier'),
                                'summary': adv.get('summary', '')[:200], 'cvss': (adv.get('cvss') or {}).get('score')},
                               label=f"{ghsa or (cves[0] if cves else 'vuln')} {pkg}", criticality=sev if sev in ('critical', 'high') else 'medium')
                r.edge(node, vnode, 'affected_by', {'manifest': (alert.get('dependency') or {}).get('manifest_path'), 'alert_number': alert.get('number')})
                r.event(source, f"github:{full}:dependabot:{alert.get('number')}", f"{full}: {pkg} vulnerable ({ghsa or (cves[0] if cves else 'advisory')})", sev, 'code',
                        entity=node.key, action='dependency_vulnerable', occurred_at=parse_time(alert.get('created_at')),
                        metadata={'repo': full, 'package': pkg, 'ecosystem': eco, 'ghsa_id': ghsa, 'cve_ids': cves, 'manifest': (alert.get('dependency') or {}).get('manifest_path'),
                                  'url': alert.get('html_url')})
            for alert in repo.get('secret_scanning_alerts') or []:
                counts['secret_scanning_alerts'] += 1
                stype = alert.get('secret_type_display_name') or alert.get('secret_type', 'secret')
                snode = r.node('secret', f"github:secret:{full}:{alert.get('number')}", {'provider': 'github', 'type': alert.get('secret_type'), 'display_name': stype,
                                                                                        'validity': alert.get('validity'), 'push_protection_bypassed': bool(alert.get('push_protection_bypassed')),
                                                                                        'state': alert.get('state')}, label=f"{stype} in {full}",
                               criticality='critical' if alert.get('validity') == 'active' else 'high')
                r.edge(node, snode, 'affected_by', {'alert_number': alert.get('number')})
                r.event(source, f"github:{full}:secret:{alert.get('number')}", f'{stype} committed to {full}', 'critical' if alert.get('validity') == 'active' else 'high', 'code',
                        actor=(alert.get('push_protection_bypassed_by') or {}).get('login', ''), entity=node.key, action='secret_detected',
                        occurred_at=parse_time(alert.get('created_at')),
                        metadata={'repo': full, 'secret_type': alert.get('secret_type'), 'validity': alert.get('validity'), 'url': alert.get('html_url'),
                                  'push_protection_bypassed': bool(alert.get('push_protection_bypassed'))})  # the `secret` field is intentionally never copied
            for alert in repo.get('code_scanning_alerts') or []:
                counts['code_scanning_alerts'] += 1
                rule = alert.get('rule') or {}
                sev = SEVERITY_MAP.get(str(rule.get('security_severity_level') or rule.get('severity') or 'medium').lower(), 'medium')
                loc = ((alert.get('most_recent_instance') or {}).get('location') or {})
                vnode = r.node('vuln', f"github:code:{full}:{rule.get('id')}", {'provider': 'github', 'type': 'code_scanning', 'rule': rule.get('id'), 'tool': (alert.get('tool') or {}).get('name'),
                                                                               'severity': sev, 'description': (rule.get('description') or '')[:200]},
                               label=f"{rule.get('id')} in {full}", criticality=sev if sev in ('critical', 'high') else 'medium')
                r.edge(node, vnode, 'affected_by', {'alert_number': alert.get('number'), 'path': loc.get('path')})
                r.event(source, f"github:{full}:code-scanning:{alert.get('number')}", f"{full}: {rule.get('id')} at {loc.get('path', '?')}:{loc.get('start_line', '?')}", sev, 'code',
                        entity=node.key, action='code_scanning_alert', occurred_at=parse_time(alert.get('created_at')),
                        metadata={'repo': full, 'rule': rule.get('id'), 'tool': (alert.get('tool') or {}).get('name'), 'path': loc.get('path'), 'line': loc.get('start_line'), 'url': alert.get('html_url')})
            for collab in repo.get('collaborators') or []:
                perms = collab.get('permissions') or {}
                if not (perms.get('admin') or collab.get('role_name') == 'admin'):
                    continue
                counts['admin_collaborators'] += 1
                ident = r.node('identity', f"github:user:{collab.get('login')}", {'provider': 'github', 'type': 'user', 'login': collab.get('login'), 'site_admin': collab.get('site_admin')},
                               label=collab.get('login', ''), criticality='high')
                perm = r.node('permission', f'github:perm:admin:{full}', {'provider': 'github', 'role': 'admin', 'repo': full, 'admin': True, 'wildcard': True}, label=f'admin on {full}',
                              criticality='high')
                r.edge(ident, perm, 'has_permission')
        r.stats.update(counts)
        r.stats['org'] = login
        return r.finalize()


# ---------------------------------------------------------------- fetch


def _next_link(response: httpx.Response) -> str | None:
    link = response.headers.get('link', '')
    match = re.search(r'<([^>]+)>;\s*rel="next"', link)
    return match.group(1) if match else None


async def _get_all(client: httpx.AsyncClient, url: str, params: dict[str, Any] | None, warnings: list[str], label: str, max_pages: int = 50) -> list[Any] | None:
    """Follow Link pagination. Returns None when the endpoint is unavailable (403/404) so callers can tell 'none' from 'unknown'."""
    items: list[Any] = []
    pages = 0
    next_url: str | None = url
    next_params = dict(params or {})
    while next_url and pages < max_pages:
        response = await client.get(next_url, params=next_params or None)
        next_params = {}
        if response.status_code in (403, 404, 451):
            if pages == 0:
                warnings.append(f'{label}: HTTP {response.status_code}')
                return None
            break
        response.raise_for_status()
        data = response.json()
        items.extend(data if isinstance(data, list) else [data])
        next_url = _next_link(response)
        pages += 1
    return items


async def _fetch(ctx: CollectorContext) -> dict[str, Any]:
    config = ctx.config
    org = config['org']
    base = (config.get('api_url') or 'https://api.github.com').rstrip('/')
    headers = {'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': API_VERSION, 'User-Agent': 'sentinel-collector'}
    if config.get('token'):
        headers['Authorization'] = f"Bearer {config['token']}"
    warnings: list[str] = []
    raw: dict[str, Any] = {'org_login': org, 'org': {}, 'repos': [], 'warnings': warnings}
    async with httpx.AsyncClient(headers=headers, timeout=httpx.Timeout(30.0)) as client:
        response = await client.get(f'{base}/orgs/{org}')
        response.raise_for_status()
        raw['org'] = response.json()
        repos = await _get_all(client, f'{base}/orgs/{org}/repos', {'type': 'all', 'per_page': 100}, warnings, 'repos') or []
        max_repos = int(config.get('max_repos') or 1000)
        for repo in repos[:max_repos]:
            if repo.get('archived') and not config.get('include_archived'):
                continue
            name = repo['name']
            prefix = f'{base}/repos/{org}/{name}'
            branch = repo.get('default_branch') or 'main'
            prot = await client.get(f'{prefix}/branches/{branch}/protection')
            if prot.status_code == 200:
                repo['branch_protection'] = prot.json()
            elif prot.status_code == 404:
                repo['branch_protection'] = {}  # explicitly unprotected
            else:
                repo['branch_protection'] = 'unknown'
                warnings.append(f'{name}: branch protection HTTP {prot.status_code}')
            repo['dependabot_alerts'] = await _get_all(client, f'{prefix}/dependabot/alerts', {'state': 'open', 'per_page': 100}, warnings, f'{name} dependabot') or []
            secrets = await _get_all(client, f'{prefix}/secret-scanning/alerts', {'state': 'open', 'per_page': 100}, warnings, f'{name} secret-scanning') or []
            for alert in secrets:
                alert.pop('secret', None)  # never keep the matched secret value
            repo['secret_scanning_alerts'] = secrets
            repo['code_scanning_alerts'] = await _get_all(client, f'{prefix}/code-scanning/alerts', {'state': 'open', 'per_page': 100}, warnings, f'{name} code-scanning') or []
            repo['collaborators'] = await _get_all(client, f'{prefix}/collaborators', {'affiliation': 'all', 'per_page': 100}, warnings, f'{name} collaborators') or []
            raw['repos'].append(repo)
            await ctx.heartbeat()
    return raw


registry.register(GithubCollector())
