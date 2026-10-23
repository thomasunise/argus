"""Azure executors over the ARM and Microsoft Graph REST APIs (httpx, no SDK).
Credentials: ACTIONS_AZURE_TENANT_ID / CLIENT_ID / CLIENT_SECRET (app registration, client
credentials grant) and ACTIONS_AZURE_SUBSCRIPTION_ID (default subscription)."""
from __future__ import annotations

from typing import Any

from ..catalog import ActionError, ActionType, DryRunResult, ExecContext, ExecResult, entities, register
from ._common import body, http

LOGIN = 'https://login.microsoftonline.com'
ARM = 'https://management.azure.com'
GRAPH = 'https://graph.microsoft.com/v1.0'
ARM_SCOPE = 'https://management.azure.com/.default'
GRAPH_SCOPE = 'https://graph.microsoft.com/.default'

_RG = {'type': 'string', 'minLength': 1, 'maxLength': 90, 'pattern': r'^[\w.()-]+$'}
_RES = {'type': 'string', 'minLength': 1, 'maxLength': 80, 'pattern': r'^[\w.-]+$'}
_SUB = {'type': 'string', 'pattern': r'^[0-9a-fA-F-]{36}$'}
_USER = {'type': 'string', 'minLength': 1, 'maxLength': 256, 'pattern': r"^[^/?#\s]+$"}


async def token(ctx: ExecContext, scope: str, platform: str | None = None) -> str:
    tenant = ctx.require_credential('tenant_id', platform)
    client_id = ctx.require_credential('client_id', platform)
    secret = ctx.require_credential('client_secret', platform)
    response = await http('POST', f'{LOGIN}/{tenant}/oauth2/v2.0/token', label='azure-login',
                          data={'grant_type': 'client_credentials', 'client_id': client_id, 'client_secret': secret, 'scope': scope})
    access = body(response).get('access_token')
    if not access:
        raise ActionError('azure token response had no access_token')
    return access


async def arm(ctx: ExecContext, method: str, path: str, *, api_version: str, json: Any = None, allow: tuple[int, ...] = ()):
    bearer = await token(ctx, ARM_SCOPE)
    return await http(method, f'{ARM}{path}', params={'api-version': api_version}, json=json, allow=allow, label='azure-arm',
                      headers={'Authorization': f'Bearer {bearer}', 'Content-Type': 'application/json'})


async def graph(ctx: ExecContext, method: str, path: str, *, json: Any = None, params: dict | None = None, allow: tuple[int, ...] = (),
                platform: str | None = None):
    bearer = await token(ctx, GRAPH_SCOPE, platform)
    return await http(method, f'{GRAPH}{path}', params=params, json=json, allow=allow, label='ms-graph',
                      headers={'Authorization': f'Bearer {bearer}', 'Content-Type': 'application/json'})


def _subscription(ctx: ExecContext, params: dict) -> str:
    sub = params.get('subscription_id') or ctx.credential('subscription_id')
    if not sub:
        raise ActionError('subscription_id is required (param or ACTIONS_AZURE_SUBSCRIPTION_ID)')
    return sub


# ---------------------------------------------------------------- NSG


@register
class RemoveNsgRule(ActionType):
    name = 'azure.nsg.remove_rule'
    description = 'Delete one security rule from a network security group (ARM DELETE securityRules). Rollback re-creates the rule with its previous properties.'
    params_schema = {'properties': {'subscription_id': _SUB, 'resource_group': _RG, 'nsg_name': _RES, 'rule_name': _RES},
                     'required': ['resource_group', 'nsg_name', 'rule_name']}
    risk = 'medium'
    reversible = True
    platforms = ['azure']
    category = 'containment'
    api_version = '2023-09-01'

    @staticmethod
    def _plan(params: dict, subscription_id: str) -> dict:
        nsg = f'/subscriptions/{subscription_id}/resourceGroups/{params["resource_group"]}/providers/Microsoft.Network/networkSecurityGroups/{params["nsg_name"]}'
        return {'method': 'DELETE', 'path': f'{nsg}/securityRules/{params["rule_name"]}', 'nsg_path': nsg, 'api_version': RemoveNsgRule.api_version,
                'blast_radius': entities(1, 'nsg_rule', [params['rule_name']], nsg=params['nsg_name'])}

    async def dry_run(self, params: dict, ctx: ExecContext) -> DryRunResult:
        plan = self._plan(params, _subscription(ctx, params))
        rule = await arm(ctx, 'GET', plan['path'], api_version=plan['api_version'], allow=(404,))
        if rule.status_code == 404:
            return DryRunResult(ok=False, summary='security rule not found', blast_radius=plan['blast_radius'])
        props = body(rule).get('properties', {})
        nsg = body(await arm(ctx, 'GET', plan['nsg_path'], api_version=plan['api_version'])).get('properties', {})
        radius = dict(plan['blast_radius'], attached_subnets=len(nsg.get('subnets', [])), attached_nics=len(nsg.get('networkInterfaces', [])))
        warnings = []
        if props.get('access') == 'Deny':
            warnings.append('this rule is a Deny rule; removing it may open traffic')
        return DryRunResult(ok=True, summary=f'delete rule {params["rule_name"]} ({props.get("direction")} {props.get("access")} {props.get("protocol")} '
                                             f'{props.get("sourceAddressPrefix", "")}->{props.get("destinationPortRange", "")}) from {params["nsg_name"]}',
                            blast_radius=radius, warnings=warnings, details={'rule': props})

    async def execute(self, params: dict, ctx: ExecContext) -> ExecResult:
        plan = self._plan(params, _subscription(ctx, params))
        rule = await arm(ctx, 'GET', plan['path'], api_version=plan['api_version'], allow=(404,))
        if rule.status_code == 404:
            raise ActionError('security rule not found')
        props = {k: v for k, v in body(rule).get('properties', {}).items() if k != 'provisioningState'}
        await arm(ctx, 'DELETE', plan['path'], api_version=plan['api_version'])
        return ExecResult(ok=True, summary=f'rule {params["rule_name"]} deleted from {params["nsg_name"]}',
                          rollback_payload={'path': plan['path'], 'api_version': plan['api_version'], 'properties': props})

    async def rollback(self, payload: dict, ctx: ExecContext) -> ExecResult:
        await arm(ctx, 'PUT', payload['path'], api_version=payload.get('api_version', self.api_version), json={'properties': payload['properties']})
        return ExecResult(ok=True, summary='security rule re-created')


# ---------------------------------------------------------------- Storage


@register
class DisablePublicBlobAccess(ActionType):
    name = 'azure.storage.disable_public_blob_access'
    description = 'Set allowBlobPublicAccess=false on a storage account (ARM PATCH storageAccounts). Rollback restores the previous value.'
    params_schema = {'properties': {'subscription_id': _SUB, 'resource_group': _RG,
                                    'account_name': {'type': 'string', 'minLength': 3, 'maxLength': 24, 'pattern': r'^[a-z0-9]+$'}},
                     'required': ['resource_group', 'account_name']}
    risk = 'medium'
    reversible = True
    platforms = ['azure']
    category = 'remediation'
    api_version = '2023-01-01'

    @staticmethod
    def _plan(params: dict, subscription_id: str) -> dict:
        path = f'/subscriptions/{subscription_id}/resourceGroups/{params["resource_group"]}/providers/Microsoft.Storage/storageAccounts/{params["account_name"]}'
        return {'method': 'PATCH', 'path': path, 'api_version': DisablePublicBlobAccess.api_version, 'json': {'properties': {'allowBlobPublicAccess': False}},
                'blast_radius': entities(1, 'storage_account', [params['account_name']])}

    async def dry_run(self, params: dict, ctx: ExecContext) -> DryRunResult:
        plan = self._plan(params, _subscription(ctx, params))
        account = await arm(ctx, 'GET', plan['path'], api_version=plan['api_version'], allow=(404,))
        if account.status_code == 404:
            return DryRunResult(ok=False, summary='storage account not found', blast_radius=plan['blast_radius'])
        previous = body(account).get('properties', {}).get('allowBlobPublicAccess')
        warnings = ['public blob access is already disabled'] if previous is False else ['anonymous reads of public containers will stop working']
        return DryRunResult(ok=True, summary=f'disable public blob access on {params["account_name"]}', blast_radius=plan['blast_radius'],
                            warnings=warnings, details={'previous': previous})

    async def execute(self, params: dict, ctx: ExecContext) -> ExecResult:
        plan = self._plan(params, _subscription(ctx, params))
        account = await arm(ctx, 'GET', plan['path'], api_version=plan['api_version'], allow=(404,))
        if account.status_code == 404:
            raise ActionError('storage account not found')
        previous = body(account).get('properties', {}).get('allowBlobPublicAccess')
        await arm(ctx, 'PATCH', plan['path'], api_version=plan['api_version'], json=plan['json'])
        return ExecResult(ok=True, summary=f'public blob access disabled on {params["account_name"]}',
                          rollback_payload={'path': plan['path'], 'api_version': plan['api_version'], 'previous': previous})

    async def rollback(self, payload: dict, ctx: ExecContext) -> ExecResult:
        previous = payload.get('previous')
        value = True if previous is None else bool(previous)
        await arm(ctx, 'PATCH', payload['path'], api_version=payload.get('api_version', self.api_version), json={'properties': {'allowBlobPublicAccess': value}})
        return ExecResult(ok=True, summary=f'allowBlobPublicAccess restored to {value}')


# ---------------------------------------------------------------- Entra ID (Graph)


async def _user(ctx: ExecContext, user: str, platform: str | None = None) -> dict | None:
    response = await graph(ctx, 'GET', f'/users/{user}', params={'$select': 'id,userPrincipalName,accountEnabled,displayName'}, allow=(404,), platform=platform)
    return None if response.status_code == 404 else body(response)


@register
class RevokeUserSessions(ActionType):
    name = 'azure.ad.revoke_user_sessions'
    description = 'Invalidate all refresh tokens and session cookies of a user (Graph POST /users/{id}/revokeSignInSessions). Not reversible: the user must sign in again.'
    params_schema = {'properties': {'user': _USER}, 'required': ['user']}
    risk = 'high'
    reversible = False
    platforms = ['azure', 'entra']
    platform = 'azure'
    category = 'containment'

    @staticmethod
    def _plan(user: dict) -> dict:
        return {'method': 'POST', 'path': f'/users/{user["id"]}/revokeSignInSessions', 'blast_radius': entities(1, 'user', [user.get('userPrincipalName', user['id'])])}

    async def dry_run(self, params: dict, ctx: ExecContext) -> DryRunResult:
        user = await _user(ctx, params['user'], self.platform)
        if user is None:
            return DryRunResult(ok=False, summary='user not found', blast_radius=entities(0, 'user'))
        plan = self._plan(user)
        return DryRunResult(ok=True, summary=f'revoke sign-in sessions of {user.get("userPrincipalName")}', blast_radius=plan['blast_radius'],
                            warnings=['every device and app session of this user will be signed out'])

    async def execute(self, params: dict, ctx: ExecContext) -> ExecResult:
        user = await _user(ctx, params['user'], self.platform)
        if user is None:
            raise ActionError('user not found')
        plan = self._plan(user)
        await graph(ctx, 'POST', plan['path'], platform=self.platform)
        return ExecResult(ok=True, summary=f'sessions revoked for {user.get("userPrincipalName")}')


@register
class DisableUser(ActionType):
    name = 'azure.ad.disable_user'
    description = 'Block sign-in for a user by setting accountEnabled=false (Graph PATCH /users/{id}). Rollback re-enables the account.'
    params_schema = {'properties': {'user': _USER}, 'required': ['user']}
    risk = 'high'
    reversible = True
    platforms = ['azure', 'entra']
    platform = 'azure'
    category = 'containment'

    @staticmethod
    def _plan(user: dict) -> dict:
        return {'method': 'PATCH', 'path': f'/users/{user["id"]}', 'json': {'accountEnabled': False},
                'blast_radius': entities(1, 'user', [user.get('userPrincipalName', user['id'])])}

    async def dry_run(self, params: dict, ctx: ExecContext) -> DryRunResult:
        user = await _user(ctx, params['user'], self.platform)
        if user is None:
            return DryRunResult(ok=False, summary='user not found', blast_radius=entities(0, 'user'))
        plan = self._plan(user)
        warnings = ['account is already disabled'] if user.get('accountEnabled') is False else []
        return DryRunResult(ok=True, summary=f'disable account {user.get("userPrincipalName")}', blast_radius=plan['blast_radius'], warnings=warnings,
                            details={'account_enabled': user.get('accountEnabled')})

    async def execute(self, params: dict, ctx: ExecContext) -> ExecResult:
        user = await _user(ctx, params['user'], self.platform)
        if user is None:
            raise ActionError('user not found')
        plan = self._plan(user)
        await graph(ctx, 'PATCH', plan['path'], json=plan['json'], platform=self.platform)
        return ExecResult(ok=True, summary=f'account {user.get("userPrincipalName")} disabled',
                          rollback_payload={'id': user['id'], 'previous_enabled': user.get('accountEnabled', True)})

    async def rollback(self, payload: dict, ctx: ExecContext) -> ExecResult:
        value = bool(payload.get('previous_enabled', True))
        await graph(ctx, 'PATCH', f'/users/{payload["id"]}', json={'accountEnabled': value}, platform=self.platform)
        return ExecResult(ok=True, summary=f'accountEnabled restored to {value}')
