"""GitHub executors over the REST API (httpx). Credential: ACTIONS_GITHUB_TOKEN (fine-grained
PAT or GitHub App installation token) and optional ACTIONS_GITHUB_API_URL for GHES."""
from __future__ import annotations

import base64
import difflib
from typing import Any

from ..catalog import ActionError, ActionType, DryRunResult, ExecContext, ExecResult, entities, register
from ._common import body, http

DEFAULT_API = 'https://api.github.com'
API_VERSION = '2022-11-28'

_OWNER = {'type': 'string', 'minLength': 1, 'maxLength': 39, 'pattern': r'^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$'}
_REPO = {'type': 'string', 'minLength': 1, 'maxLength': 100, 'pattern': r'^[\w.-]+$'}
_BRANCH = {'type': 'string', 'minLength': 1, 'maxLength': 200, 'pattern': r'^(?!.*\.\.)(?!/)(?!.*//)[\w./-]+(?<!/)(?<!\.lock)$'}
_PATH = {'type': 'string', 'minLength': 1, 'maxLength': 500, 'pattern': r'^(?!/)(?!.*(^|/)\.\.(/|$))[^\0]+$'}


def _api_url(ctx: ExecContext) -> str:
    return (ctx.credential('api_url') or DEFAULT_API).rstrip('/')


async def gh(ctx: ExecContext, method: str, path: str, *, json: Any = None, params: dict | None = None, allow: tuple[int, ...] = ()):
    token = ctx.require_credential('token')
    return await http(method, f'{_api_url(ctx)}{path}', json=json, params=params, allow=allow, label='github',
                      headers={'Authorization': f'Bearer {token}', 'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': API_VERSION})


# ---------------------------------------------------------------- branch protection


def normalize_protection(data: dict) -> dict:
    """Turn a GET /branches/{b}/protection response into a PUT body that reproduces it."""
    checks = data.get('required_status_checks') or None
    reviews = data.get('required_pull_request_reviews') or None
    return {'required_status_checks': {'strict': bool(checks.get('strict')), 'contexts': list(checks.get('contexts') or [])} if checks else None,
            'enforce_admins': bool((data.get('enforce_admins') or {}).get('enabled')),
            'required_pull_request_reviews': {'dismiss_stale_reviews': bool(reviews.get('dismiss_stale_reviews')),
                                              'require_code_owner_reviews': bool(reviews.get('require_code_owner_reviews')),
                                              'required_approving_review_count': int(reviews.get('required_approving_review_count') or 0)} if reviews else None,
            'restrictions': None,
            'allow_force_pushes': bool((data.get('allow_force_pushes') or {}).get('enabled')),
            'allow_deletions': bool((data.get('allow_deletions') or {}).get('enabled'))}


@register
class EnableBranchProtection(ActionType):
    name = 'github.branch_protection.enable'
    description = 'Require pull-request reviews (and optionally status checks) on a branch (PUT /repos/{o}/{r}/branches/{b}/protection). Rollback restores the previous protection or removes it.'
    params_schema = {'properties': {'owner': _OWNER, 'repo': _REPO, 'branch': _BRANCH,
                                    'required_approving_review_count': {'type': 'integer', 'minimum': 0, 'maximum': 6, 'default': 1},
                                    'dismiss_stale_reviews': {'type': 'boolean', 'default': True}, 'require_code_owner_reviews': {'type': 'boolean', 'default': False},
                                    'enforce_admins': {'type': 'boolean', 'default': True},
                                    'required_status_checks': {'type': 'array', 'items': {'type': 'string', 'maxLength': 200}, 'maxItems': 50, 'default': []},
                                    'strict_status_checks': {'type': 'boolean', 'default': True}},
                     'required': ['owner', 'repo', 'branch']}
    risk = 'medium'
    reversible = True
    platforms = ['github']
    category = 'remediation'

    @staticmethod
    def _plan(params: dict) -> dict:
        contexts = list(params.get('required_status_checks') or [])
        payload = {'required_status_checks': {'strict': bool(params.get('strict_status_checks', True)), 'contexts': contexts} if contexts else None,
                   'enforce_admins': bool(params.get('enforce_admins', True)),
                   'required_pull_request_reviews': {'dismiss_stale_reviews': bool(params.get('dismiss_stale_reviews', True)),
                                                     'require_code_owner_reviews': bool(params.get('require_code_owner_reviews', False)),
                                                     'required_approving_review_count': int(params.get('required_approving_review_count', 1))},
                   'restrictions': None, 'allow_force_pushes': False, 'allow_deletions': False}
        path = f'/repos/{params["owner"]}/{params["repo"]}/branches/{params["branch"]}/protection'
        return {'method': 'PUT', 'path': path, 'json': payload, 'blast_radius': entities(1, 'branch', [f'{params["owner"]}/{params["repo"]}@{params["branch"]}'])}

    async def _previous(self, ctx: ExecContext, params: dict) -> tuple[bool, dict | None]:
        branch = await gh(ctx, 'GET', f'/repos/{params["owner"]}/{params["repo"]}/branches/{params["branch"]}', allow=(404,))
        if branch.status_code == 404:
            return False, None
        protection = await gh(ctx, 'GET', self._plan(params)['path'], allow=(404,))
        return True, (normalize_protection(body(protection)) if protection.status_code != 404 else None)

    async def dry_run(self, params: dict, ctx: ExecContext) -> DryRunResult:
        plan = self._plan(params)
        exists, previous = await self._previous(ctx, params)
        if not exists:
            return DryRunResult(ok=False, summary='branch not found', blast_radius=plan['blast_radius'])
        warnings = ['branch is already protected; its settings will be replaced'] if previous else []
        warnings.append('direct pushes to this branch will be rejected until a reviewed pull request merges')
        return DryRunResult(ok=True, summary=f'protect {params["owner"]}/{params["repo"]}@{params["branch"]} '
                                             f'({plan["json"]["required_pull_request_reviews"]["required_approving_review_count"]} review(s))',
                            blast_radius=plan['blast_radius'], warnings=warnings, details={'previous': previous, 'protection': plan['json']})

    async def execute(self, params: dict, ctx: ExecContext) -> ExecResult:
        plan = self._plan(params)
        exists, previous = await self._previous(ctx, params)
        if not exists:
            raise ActionError('branch not found')
        await gh(ctx, 'PUT', plan['path'], json=plan['json'])
        return ExecResult(ok=True, summary=f'branch protection enabled on {params["owner"]}/{params["repo"]}@{params["branch"]}',
                          rollback_payload={'path': plan['path'], 'previous': previous})

    async def rollback(self, payload: dict, ctx: ExecContext) -> ExecResult:
        if payload.get('previous'):
            await gh(ctx, 'PUT', payload['path'], json=payload['previous'])
            return ExecResult(ok=True, summary='previous branch protection restored')
        await gh(ctx, 'DELETE', payload['path'], allow=(404,))
        return ExecResult(ok=True, summary='branch protection removed (none existed before)')


# ---------------------------------------------------------------- secret scanning


@register
class EnableSecretScanning(ActionType):
    name = 'github.secret_scanning.enable'
    description = 'Enable secret scanning (and push protection) on a repository (PATCH /repos/{o}/{r} security_and_analysis). Rollback restores the previous statuses.'
    params_schema = {'properties': {'owner': _OWNER, 'repo': _REPO, 'push_protection': {'type': 'boolean', 'default': True}}, 'required': ['owner', 'repo']}
    risk = 'low'
    reversible = True
    platforms = ['github']
    category = 'remediation'

    @staticmethod
    def _plan(params: dict) -> dict:
        analysis = {'secret_scanning': {'status': 'enabled'}}
        if params.get('push_protection', True):
            analysis['secret_scanning_push_protection'] = {'status': 'enabled'}
        return {'method': 'PATCH', 'path': f'/repos/{params["owner"]}/{params["repo"]}', 'json': {'security_and_analysis': analysis},
                'blast_radius': entities(1, 'repository', [f'{params["owner"]}/{params["repo"]}'])}

    @staticmethod
    def _previous(repo: dict) -> dict:
        analysis = repo.get('security_and_analysis') or {}
        return {key: (analysis.get(key) or {}).get('status') for key in ('secret_scanning', 'secret_scanning_push_protection') if analysis.get(key)}

    async def dry_run(self, params: dict, ctx: ExecContext) -> DryRunResult:
        plan = self._plan(params)
        response = await gh(ctx, 'GET', plan['path'], allow=(404,))
        if response.status_code == 404:
            return DryRunResult(ok=False, summary='repository not found', blast_radius=plan['blast_radius'])
        repo = body(response)
        previous = self._previous(repo)
        warnings = []
        if repo.get('visibility') == 'public':
            warnings.append('secret scanning is always on for public repositories; only push protection changes')
        if previous.get('secret_scanning') == 'enabled':
            warnings.append('secret scanning is already enabled')
        if 'security_and_analysis' not in repo:
            warnings.append('token cannot read security settings; the PATCH may be rejected')
        return DryRunResult(ok=True, summary=f'enable secret scanning on {params["owner"]}/{params["repo"]}', blast_radius=plan['blast_radius'],
                            warnings=warnings, details={'previous': previous})

    async def execute(self, params: dict, ctx: ExecContext) -> ExecResult:
        plan = self._plan(params)
        response = await gh(ctx, 'GET', plan['path'], allow=(404,))
        if response.status_code == 404:
            raise ActionError('repository not found')
        previous = self._previous(body(response))
        await gh(ctx, 'PATCH', plan['path'], json=plan['json'])
        return ExecResult(ok=True, summary=f'secret scanning enabled on {params["owner"]}/{params["repo"]}', rollback_payload={'path': plan['path'], 'previous': previous})

    async def rollback(self, payload: dict, ctx: ExecContext) -> ExecResult:
        previous = payload.get('previous') or {}
        analysis = {key: {'status': status} for key, status in previous.items() if status in {'enabled', 'disabled'}}
        if not analysis:
            analysis = {'secret_scanning': {'status': 'disabled'}, 'secret_scanning_push_protection': {'status': 'disabled'}}
        await gh(ctx, 'PATCH', payload['path'], json={'security_and_analysis': analysis})
        return ExecResult(ok=True, summary='secret scanning settings restored')


# ---------------------------------------------------------------- fix pull request


def _decode(file: dict) -> bytes:
    content = file.get('content', '')
    if file.get('encoding', 'utf-8') == 'base64':
        try:
            return base64.b64decode(content, validate=True)
        except (ValueError, TypeError) as exc:
            raise ActionError(f'file {file.get("path")} is not valid base64') from exc
    return content.encode('utf-8')


def _diff_counts(old: str | None, new: str | None) -> tuple[int, int]:
    old_lines = (old or '').splitlines()
    new_lines = (new or '').splitlines()
    added = removed = 0
    for line in difflib.unified_diff(old_lines, new_lines, lineterm='', n=0):
        if line.startswith('+') and not line.startswith('+++'):
            added += 1
        elif line.startswith('-') and not line.startswith('---'):
            removed += 1
    return added, removed


@register
class OpenFixPr(ActionType):
    name = 'github.open_fix_pr'
    description = 'Create a branch from the base branch, commit the given file changes through the Contents API and open a pull request. Rollback closes the PR and deletes the branch.'
    params_schema = {'properties': {'owner': _OWNER, 'repo': _REPO, 'head_branch': _BRANCH, 'base_branch': _BRANCH,
                                    'title': {'type': 'string', 'minLength': 1, 'maxLength': 200}, 'body': {'type': 'string', 'maxLength': 20000, 'default': ''},
                                    'commit_message': {'type': 'string', 'maxLength': 500, 'default': ''},
                                    'files': {'type': 'array', 'minItems': 1, 'maxItems': 50,
                                              'items': {'type': 'object', 'additionalProperties': False, 'required': ['path'],
                                                        'properties': {'path': _PATH, 'content': {'type': 'string', 'maxLength': 1_000_000, 'default': ''},
                                                                       'encoding': {'type': 'string', 'enum': ['utf-8', 'base64'], 'default': 'utf-8'},
                                                                       'delete': {'type': 'boolean', 'default': False}}}}},
                     'required': ['owner', 'repo', 'head_branch', 'title', 'files']}
    risk = 'medium'
    reversible = True
    platforms = ['github']
    category = 'remediation'

    @staticmethod
    def _plan(params: dict, existing: dict[str, str | None]) -> dict:
        """Pure diff summary. `existing` maps path -> current text (None when the file does not exist)."""
        files: list[dict] = []
        total_added = total_removed = 0
        for file in params['files']:
            path = file['path']
            old = existing.get(path)
            if file.get('delete'):
                if old is None:
                    raise ActionError(f'cannot delete {path}: file does not exist on the base branch')
                added, removed = _diff_counts(old, None)
                action = 'delete'
            else:
                new_text = _decode(file).decode('utf-8', errors='replace')
                added, removed = _diff_counts(old, new_text)
                action = 'add' if old is None else 'modify'
            files.append({'path': path, 'action': action, 'added': added, 'removed': removed})
            total_added += added
            total_removed += removed
        repo = f'{params["owner"]}/{params["repo"]}'
        return {'repo': repo, 'files': files, 'added': total_added, 'removed': total_removed,
                'commit_message': params.get('commit_message') or params['title'],
                'blast_radius': entities(1, 'repository', [repo], files=len(files), lines_added=total_added, lines_removed=total_removed)}

    async def _base(self, ctx: ExecContext, params: dict) -> tuple[str, str] | None:
        prefix = f'/repos/{params["owner"]}/{params["repo"]}'
        repo = await gh(ctx, 'GET', prefix, allow=(404,))
        if repo.status_code == 404:
            return None
        base = params.get('base_branch') or body(repo).get('default_branch') or 'main'
        branch = await gh(ctx, 'GET', f'{prefix}/branches/{base}', allow=(404,))
        if branch.status_code == 404:
            raise ActionError(f'base branch {base} not found')
        return base, body(branch)['commit']['sha']

    async def _existing(self, ctx: ExecContext, params: dict, base: str) -> dict[str, dict]:
        prefix = f'/repos/{params["owner"]}/{params["repo"]}/contents/'
        out: dict[str, dict] = {}
        for file in params['files']:
            response = await gh(ctx, 'GET', prefix + file['path'], params={'ref': base}, allow=(404,))
            if response.status_code == 404:
                out[file['path']] = {'sha': None, 'text': None}
                continue
            data = body(response)
            text = None
            if data.get('encoding') == 'base64' and data.get('content') is not None:
                try:
                    text = base64.b64decode(data['content']).decode('utf-8', errors='replace')
                except (ValueError, TypeError):
                    text = None
            out[file['path']] = {'sha': data.get('sha'), 'text': text}
            await ctx.heartbeat()
        return out

    async def dry_run(self, params: dict, ctx: ExecContext) -> DryRunResult:
        base = await self._base(ctx, params)
        if base is None:
            return DryRunResult(ok=False, summary='repository not found', blast_radius=entities(0, 'repository'))
        base_branch, _ = base
        prefix = f'/repos/{params["owner"]}/{params["repo"]}'
        head = await gh(ctx, 'GET', f'{prefix}/git/ref/heads/{params["head_branch"]}', allow=(404,))
        if head.status_code != 404:
            return DryRunResult(ok=False, summary=f'head branch {params["head_branch"]} already exists', blast_radius=entities(1, 'repository'))
        existing = await self._existing(ctx, params, base_branch)
        plan = self._plan(params, {path: info['text'] for path, info in existing.items()})
        summary = ', '.join(f'{f["action"]} {f["path"]} (+{f["added"]}/-{f["removed"]})' for f in plan['files'])
        return DryRunResult(ok=True, summary=f'open PR "{params["title"]}" on {plan["repo"]} from {params["head_branch"]} into {base_branch}: {summary}',
                            blast_radius=plan['blast_radius'], details={'files': plan['files'], 'base_branch': base_branch})

    async def execute(self, params: dict, ctx: ExecContext) -> ExecResult:
        base = await self._base(ctx, params)
        if base is None:
            raise ActionError('repository not found')
        base_branch, base_sha = base
        prefix = f'/repos/{params["owner"]}/{params["repo"]}'
        existing = await self._existing(ctx, params, base_branch)
        plan = self._plan(params, {path: info['text'] for path, info in existing.items()})
        ref = f'refs/heads/{params["head_branch"]}'
        await gh(ctx, 'POST', f'{prefix}/git/refs', json={'ref': ref, 'sha': base_sha})
        try:
            for file in params['files']:
                payload: dict[str, Any] = {'message': plan['commit_message'], 'branch': params['head_branch']}
                sha = existing[file['path']]['sha']
                if sha:
                    payload['sha'] = sha
                if file.get('delete'):
                    await gh(ctx, 'DELETE', f'{prefix}/contents/{file["path"]}', json=payload)
                else:
                    payload['content'] = base64.b64encode(_decode(file)).decode('ascii')
                    await gh(ctx, 'PUT', f'{prefix}/contents/{file["path"]}', json=payload)
                await ctx.heartbeat()
            pull = body(await gh(ctx, 'POST', f'{prefix}/pulls', json={'title': params['title'], 'body': params.get('body', ''),
                                                                          'head': params['head_branch'], 'base': base_branch}))
        except ActionError:
            await gh(ctx, 'DELETE', f'{prefix}/git/refs/heads/{params["head_branch"]}', allow=(404, 422))
            raise
        return ExecResult(ok=True, summary=f'opened PR #{pull.get("number")} on {plan["repo"]}: {pull.get("html_url", "")}',
                          rollback_payload={'owner': params['owner'], 'repo': params['repo'], 'head_branch': params['head_branch'], 'pr_number': pull.get('number')},
                          details={'pr_number': pull.get('number'), 'url': pull.get('html_url', ''), 'files': plan['files']})

    async def rollback(self, payload: dict, ctx: ExecContext) -> ExecResult:
        prefix = f'/repos/{payload["owner"]}/{payload["repo"]}'
        if payload.get('pr_number'):
            await gh(ctx, 'PATCH', f'{prefix}/pulls/{payload["pr_number"]}', json={'state': 'closed'}, allow=(404,))
        await gh(ctx, 'DELETE', f'{prefix}/git/refs/heads/{payload["head_branch"]}', allow=(404, 422))
        return ExecResult(ok=True, summary=f'PR #{payload.get("pr_number")} closed and branch {payload["head_branch"]} deleted')
