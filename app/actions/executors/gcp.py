"""Google Cloud executors over REST (httpx). Credentials: ACTIONS_GCP_ACCESS_TOKEN (short-lived
token, e.g. from Workload Identity) or ACTIONS_GCP_CREDENTIALS_FILE (service-account JSON,
exchanged through google-auth, imported lazily)."""
from __future__ import annotations

import asyncio
from typing import Any

from ..catalog import ActionError, ActionType, DryRunResult, ExecContext, ExecResult, entities, register
from ._common import body, http

COMPUTE = 'https://compute.googleapis.com/compute/v1'
STORAGE = 'https://storage.googleapis.com/storage/v1'
CRM = 'https://cloudresourcemanager.googleapis.com/v1'
SCOPE = 'https://www.googleapis.com/auth/cloud-platform'
PUBLIC_MEMBERS = ('allUsers', 'allAuthenticatedUsers')

_PROJECT = {'type': 'string', 'minLength': 6, 'maxLength': 30, 'pattern': r'^[a-z][a-z0-9-]*[a-z0-9]$'}
_NAME = {'type': 'string', 'minLength': 1, 'maxLength': 63, 'pattern': r'^[a-z]([-a-z0-9]*[a-z0-9])?$'}
_BUCKET = {'type': 'string', 'minLength': 3, 'maxLength': 222, 'pattern': r'^[a-z0-9][a-z0-9._-]+[a-z0-9]$'}
_ROLE = {'type': 'string', 'minLength': 6, 'maxLength': 300, 'pattern': r'^(roles/|projects/[^/]+/roles/|organizations/[^/]+/roles/)[\w.]+$'}
_MEMBER = {'type': 'string', 'minLength': 4, 'maxLength': 300,
           'pattern': r'^(user|serviceAccount|group|domain|principal|principalSet|deleted:user|deleted:serviceAccount|deleted:group):.+$|^(allUsers|allAuthenticatedUsers)$'}


async def token(ctx: ExecContext) -> str:
    """Monkeypatched in tests."""
    access = ctx.credential('access_token')
    if access:
        return access
    path = ctx.require_credential('credentials_file')
    try:
        from google.auth.transport.requests import Request  # lazy
        from google.oauth2 import service_account
    except ImportError as exc:  # pragma: no cover - depends on optional SDK
        raise ActionError('google-auth is not installed; set ACTIONS_GCP_ACCESS_TOKEN instead') from exc
    creds = service_account.Credentials.from_service_account_file(path, scopes=[SCOPE])
    await asyncio.to_thread(creds.refresh, Request())
    if not creds.token:
        raise ActionError('could not obtain a Google access token')
    return creds.token


async def gapi(ctx: ExecContext, method: str, url: str, *, json: Any = None, params: dict | None = None, allow: tuple[int, ...] = ()):
    bearer = await token(ctx)
    return await http(method, url, json=json, params=params, allow=allow, label='gcp', headers={'Authorization': f'Bearer {bearer}'})


# ---------------------------------------------------------------- firewall


@register
class DisableFirewallRule(ActionType):
    name = 'gcp.firewall.disable_rule'
    description = 'Set disabled=true on a VPC firewall rule (compute.firewalls.patch). Rollback restores the previous flag.'
    params_schema = {'properties': {'project': _PROJECT, 'name': _NAME}, 'required': ['project', 'name']}
    risk = 'medium'
    reversible = True
    platforms = ['gcp']
    category = 'containment'

    @staticmethod
    def _plan(params: dict) -> dict:
        return {'method': 'PATCH', 'url': f'{COMPUTE}/projects/{params["project"]}/global/firewalls/{params["name"]}', 'json': {'disabled': True},
                'blast_radius': entities(1, 'firewall_rule', [params['name']], project=params['project'])}

    async def dry_run(self, params: dict, ctx: ExecContext) -> DryRunResult:
        plan = self._plan(params)
        rule = await gapi(ctx, 'GET', plan['url'], allow=(404,))
        if rule.status_code == 404:
            return DryRunResult(ok=False, summary='firewall rule not found', blast_radius=plan['blast_radius'])
        data = body(rule)
        warnings = []
        if data.get('disabled'):
            warnings.append('rule is already disabled')
        if 'denied' in data:
            warnings.append('this is a deny rule; disabling it may open traffic')
        radius = dict(plan['blast_radius'], network=str(data.get('network', '')).rsplit('/', 1)[-1], targets=data.get('targetTags') or ['all instances'])
        return DryRunResult(ok=True, summary=f'disable firewall rule {params["name"]} ({data.get("direction", "INGRESS")}) in {params["project"]}',
                            blast_radius=radius, warnings=warnings, details={'previous_disabled': bool(data.get('disabled'))})

    async def execute(self, params: dict, ctx: ExecContext) -> ExecResult:
        plan = self._plan(params)
        rule = await gapi(ctx, 'GET', plan['url'], allow=(404,))
        if rule.status_code == 404:
            raise ActionError('firewall rule not found')
        previous = bool(body(rule).get('disabled'))
        await gapi(ctx, 'PATCH', plan['url'], json=plan['json'])
        return ExecResult(ok=True, summary=f'firewall rule {params["name"]} disabled', rollback_payload={'url': plan['url'], 'previous_disabled': previous})

    async def rollback(self, payload: dict, ctx: ExecContext) -> ExecResult:
        await gapi(ctx, 'PATCH', payload['url'], json={'disabled': bool(payload.get('previous_disabled', False))})
        return ExecResult(ok=True, summary='firewall rule disabled flag restored')


# ---------------------------------------------------------------- storage IAM


@register
class RemovePublicBucketBinding(ActionType):
    name = 'gcp.storage.remove_public_binding'
    description = 'Remove allUsers / allAuthenticatedUsers from a bucket IAM policy (storage.buckets.setIamPolicy). Rollback re-adds the removed bindings.'
    params_schema = {'properties': {'bucket': _BUCKET, 'members': {'type': 'array', 'items': {'type': 'string', 'enum': list(PUBLIC_MEMBERS)},
                                                                   'minItems': 1, 'uniqueItems': True, 'default': list(PUBLIC_MEMBERS)}},
                     'required': ['bucket']}
    risk = 'medium'
    reversible = True
    platforms = ['gcp']
    category = 'remediation'

    @staticmethod
    def _plan(policy: dict, members: list[str]) -> dict:
        """Pure: returns the new bindings and what was removed."""
        removed: list[dict] = []
        bindings: list[dict] = []
        for binding in policy.get('bindings', []):
            keep = [m for m in binding.get('members', []) if m not in members]
            for member in binding.get('members', []):
                if member in members:
                    removed.append({'role': binding.get('role'), 'member': member, 'condition': binding.get('condition')})
            if keep:
                bindings.append({**binding, 'members': keep})
        return {'bindings': bindings, 'removed': removed}

    @staticmethod
    def _url(bucket: str) -> str:
        return f'{STORAGE}/b/{bucket}/iam'

    async def dry_run(self, params: dict, ctx: ExecContext) -> DryRunResult:
        members = params.get('members') or list(PUBLIC_MEMBERS)
        response = await gapi(ctx, 'GET', self._url(params['bucket']), params={'optionsRequestedPolicyVersion': 3}, allow=(404,))
        if response.status_code == 404:
            return DryRunResult(ok=False, summary='bucket not found', blast_radius=entities(0, 'gcs_bucket'))
        plan = self._plan(body(response), members)
        radius = entities(1, 'gcs_bucket', [params['bucket']], bindings_removed=len(plan['removed']))
        if not plan['removed']:
            return DryRunResult(ok=True, summary=f'bucket {params["bucket"]} has no public bindings', blast_radius=radius, warnings=['nothing to remove'])
        return DryRunResult(ok=True, summary=f'remove {len(plan["removed"])} public binding(s) from bucket {params["bucket"]}', blast_radius=radius,
                            details={'removed': plan['removed']}, warnings=['anonymous reads of this bucket will stop working'])

    async def execute(self, params: dict, ctx: ExecContext) -> ExecResult:
        members = params.get('members') or list(PUBLIC_MEMBERS)
        url = self._url(params['bucket'])
        policy = body(await gapi(ctx, 'GET', url, params={'optionsRequestedPolicyVersion': 3}))
        plan = self._plan(policy, members)
        if not plan['removed']:
            return ExecResult(ok=True, summary='no public bindings to remove', rollback_payload={'bucket': params['bucket'], 'removed': []})
        await gapi(ctx, 'PUT', url, json={'bindings': plan['bindings'], 'etag': policy.get('etag'), 'version': 3})
        return ExecResult(ok=True, summary=f'removed {len(plan["removed"])} public binding(s) from {params["bucket"]}',
                          rollback_payload={'bucket': params['bucket'], 'removed': plan['removed']})

    async def rollback(self, payload: dict, ctx: ExecContext) -> ExecResult:
        if not payload.get('removed'):
            return ExecResult(ok=True, summary='nothing to restore')
        url = self._url(payload['bucket'])
        policy = body(await gapi(ctx, 'GET', url, params={'optionsRequestedPolicyVersion': 3}))
        bindings = _restore(policy.get('bindings', []), payload['removed'])
        await gapi(ctx, 'PUT', url, json={'bindings': bindings, 'etag': policy.get('etag'), 'version': 3})
        return ExecResult(ok=True, summary=f'restored {len(payload["removed"])} binding(s) on {payload["bucket"]}')


def _restore(bindings: list[dict], removed: list[dict]) -> list[dict]:
    out = [dict(b, members=list(b.get('members', []))) for b in bindings]
    for item in removed:
        target = next((b for b in out if b.get('role') == item['role'] and b.get('condition') == item.get('condition')), None)
        if target is None:
            target = {'role': item['role'], 'members': []}
            if item.get('condition'):
                target['condition'] = item['condition']
            out.append(target)
        if item['member'] not in target['members']:
            target['members'].append(item['member'])
    return out


# ---------------------------------------------------------------- project IAM


@register
class RemoveIamBinding(ActionType):
    name = 'gcp.iam.remove_binding'
    description = 'Remove one member from one role on a project (cloudresourcemanager.projects.setIamPolicy). Rollback re-adds the binding.'
    params_schema = {'properties': {'project': _PROJECT, 'role': _ROLE, 'member': _MEMBER}, 'required': ['project', 'role', 'member']}
    risk = 'high'
    reversible = True
    platforms = ['gcp']
    category = 'remediation'

    @staticmethod
    def _plan(policy: dict, role: str, member: str) -> dict:
        """Pure: new policy bindings plus the removed entries (one per matching binding, conditions preserved)."""
        removed: list[dict] = []
        bindings: list[dict] = []
        warnings: list[str] = []
        for binding in policy.get('bindings', []):
            if binding.get('role') == role and member in binding.get('members', []):
                removed.append({'role': role, 'member': member, 'condition': binding.get('condition')})
                keep = [m for m in binding['members'] if m != member]
                if role == 'roles/owner' and not keep:
                    warnings.append('this removes the last owner binding on the project')
                if keep:
                    bindings.append({**binding, 'members': keep})
            else:
                bindings.append(binding)
        return {'bindings': bindings, 'removed': removed, 'warnings': warnings}

    @staticmethod
    def _urls(project: str) -> tuple[str, str]:
        return f'{CRM}/projects/{project}:getIamPolicy', f'{CRM}/projects/{project}:setIamPolicy'

    async def dry_run(self, params: dict, ctx: ExecContext) -> DryRunResult:
        get_url, _ = self._urls(params['project'])
        response = await gapi(ctx, 'POST', get_url, json={'options': {'requestedPolicyVersion': 3}}, allow=(403, 404))
        radius = entities(1, 'iam_member', [params['member']], project=params['project'], role=params['role'])
        if response.status_code in (403, 404):
            return DryRunResult(ok=False, summary='project not found or getIamPolicy not permitted', blast_radius=radius)
        plan = self._plan(body(response), params['role'], params['member'])
        if not plan['removed']:
            return DryRunResult(ok=False, summary='binding not present', blast_radius=radius)
        return DryRunResult(ok=True, summary=f'remove {params["member"]} from {params["role"]} on {params["project"]}', blast_radius=radius, warnings=plan['warnings'])

    async def execute(self, params: dict, ctx: ExecContext) -> ExecResult:
        get_url, set_url = self._urls(params['project'])
        policy = body(await gapi(ctx, 'POST', get_url, json={'options': {'requestedPolicyVersion': 3}}))
        plan = self._plan(policy, params['role'], params['member'])
        if not plan['removed']:
            raise ActionError('binding not present')
        await gapi(ctx, 'POST', set_url, json={'policy': {'bindings': plan['bindings'], 'etag': policy.get('etag'), 'version': 3}})
        return ExecResult(ok=True, summary=f'removed {params["member"]} from {params["role"]}', rollback_payload={'project': params['project'], 'removed': plan['removed']})

    async def rollback(self, payload: dict, ctx: ExecContext) -> ExecResult:
        get_url, set_url = self._urls(payload['project'])
        policy = body(await gapi(ctx, 'POST', get_url, json={'options': {'requestedPolicyVersion': 3}}))
        bindings = _restore(policy.get('bindings', []), payload.get('removed', []))
        await gapi(ctx, 'POST', set_url, json={'policy': {'bindings': bindings, 'etag': policy.get('etag'), 'version': 3}})
        return ExecResult(ok=True, summary='binding restored')
