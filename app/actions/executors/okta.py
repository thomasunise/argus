"""Okta executors over the Users API (httpx). Credentials: ACTIONS_OKTA_ORG_URL and
ACTIONS_OKTA_TOKEN (SSWS API token)."""
from __future__ import annotations

from typing import Any

from ..catalog import ActionError, ActionType, DryRunResult, ExecContext, ExecResult, entities, register
from ._common import body, http

_USER = {'type': 'string', 'minLength': 1, 'maxLength': 256, 'pattern': r'^[^/?#\s]+$'}


async def okta(ctx: ExecContext, method: str, path: str, *, json: Any = None, params: dict | None = None, allow: tuple[int, ...] = ()):
    org = ctx.require_credential('org_url').rstrip('/')
    if not org.startswith('https://'):
        raise ActionError('ACTIONS_OKTA_ORG_URL must be an https URL')
    token = ctx.require_credential('token')
    return await http(method, f'{org}{path}', json=json, params=params, allow=allow, label='okta',
                      headers={'Authorization': f'SSWS {token}', 'Accept': 'application/json', 'Content-Type': 'application/json'})


async def _user(ctx: ExecContext, user: str) -> dict | None:
    response = await okta(ctx, 'GET', f'/api/v1/users/{user}', allow=(404,))
    return None if response.status_code == 404 else body(response)


def _login(user: dict) -> str:
    return (user.get('profile') or {}).get('login') or user.get('id', '')


@register
class SuspendUser(ActionType):
    name = 'okta.user.suspend'
    description = 'Suspend an Okta user (POST /api/v1/users/{id}/lifecycle/suspend). Rollback unsuspends.'
    params_schema = {'properties': {'user': _USER}, 'required': ['user']}
    risk = 'medium'
    reversible = True
    platforms = ['okta']
    category = 'containment'

    @staticmethod
    def _plan(user: dict) -> dict:
        return {'method': 'POST', 'path': f'/api/v1/users/{user["id"]}/lifecycle/suspend', 'rollback_path': f'/api/v1/users/{user["id"]}/lifecycle/unsuspend',
                'blast_radius': entities(1, 'user', [_login(user)])}

    async def dry_run(self, params: dict, ctx: ExecContext) -> DryRunResult:
        user = await _user(ctx, params['user'])
        if user is None:
            return DryRunResult(ok=False, summary='user not found', blast_radius=entities(0, 'user'))
        plan = self._plan(user)
        if user.get('status') != 'ACTIVE':
            return DryRunResult(ok=False, summary=f'user is {user.get("status")}; only ACTIVE users can be suspended', blast_radius=plan['blast_radius'])
        return DryRunResult(ok=True, summary=f'suspend Okta user {_login(user)}', blast_radius=plan['blast_radius'],
                            warnings=['the user keeps existing sessions until they are cleared; pair with okta.user.clear_sessions if needed'])

    async def execute(self, params: dict, ctx: ExecContext) -> ExecResult:
        user = await _user(ctx, params['user'])
        if user is None:
            raise ActionError('user not found')
        plan = self._plan(user)
        await okta(ctx, 'POST', plan['path'])
        return ExecResult(ok=True, summary=f'user {_login(user)} suspended', rollback_payload={'id': user['id'], 'login': _login(user)})

    async def rollback(self, payload: dict, ctx: ExecContext) -> ExecResult:
        await okta(ctx, 'POST', f'/api/v1/users/{payload["id"]}/lifecycle/unsuspend')
        return ExecResult(ok=True, summary=f'user {payload.get("login", payload["id"])} unsuspended')


@register
class ClearUserSessions(ActionType):
    name = 'okta.user.clear_sessions'
    description = 'Revoke all active sessions of an Okta user (DELETE /api/v1/users/{id}/sessions). Not reversible.'
    params_schema = {'properties': {'user': _USER, 'oauth_tokens': {'type': 'boolean', 'default': False}}, 'required': ['user']}
    risk = 'high'
    reversible = False
    platforms = ['okta']
    category = 'containment'

    @staticmethod
    def _plan(user: dict, oauth_tokens: bool = False) -> dict:
        return {'method': 'DELETE', 'path': f'/api/v1/users/{user["id"]}/sessions', 'params': {'oauthTokens': 'true'} if oauth_tokens else None,
                'blast_radius': entities(1, 'user', [_login(user)])}

    async def dry_run(self, params: dict, ctx: ExecContext) -> DryRunResult:
        user = await _user(ctx, params['user'])
        if user is None:
            return DryRunResult(ok=False, summary='user not found', blast_radius=entities(0, 'user'))
        plan = self._plan(user, bool(params.get('oauth_tokens')))
        return DryRunResult(ok=True, summary=f'clear sessions of Okta user {_login(user)}', blast_radius=plan['blast_radius'],
                            warnings=['the user is signed out everywhere' + (' and OAuth refresh tokens are revoked' if params.get('oauth_tokens') else '')])

    async def execute(self, params: dict, ctx: ExecContext) -> ExecResult:
        user = await _user(ctx, params['user'])
        if user is None:
            raise ActionError('user not found')
        plan = self._plan(user, bool(params.get('oauth_tokens')))
        await okta(ctx, 'DELETE', plan['path'], params=plan['params'])
        return ExecResult(ok=True, summary=f'sessions cleared for {_login(user)}')
