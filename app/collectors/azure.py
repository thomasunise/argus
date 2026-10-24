"""Azure collector (azure-identity + azure-mgmt-*, read-only). Inventories subscriptions,
resource groups, VMs, NSGs, storage accounts, role assignments and AKS clusters.

API calls made (ARM, all GET/list):
  SubscriptionClient.subscriptions.list()
  ResourceManagementClient.resource_groups.list()                        (per subscription)
  ComputeManagementClient.virtual_machines.list_all()                   (per subscription)
  NetworkManagementClient.network_security_groups.list_all()            (per subscription)
  NetworkManagementClient.network_interfaces.list_all()                 (per subscription)
  NetworkManagementClient.public_ip_addresses.list_all()                (per subscription)
  StorageManagementClient.storage_accounts.list()                       (per subscription, optional package)
  AuthorizationManagementClient.role_assignments.list_for_subscription()(per subscription)
  AuthorizationManagementClient.role_definitions.get_by_id()            (per distinct role definition)
  ContainerServiceClient.managed_clusters.list()                        (per subscription, optional package)
Credential: ClientSecretCredential (tenant_id, client_id, client_secret), ManagedIdentityCredential,
or DefaultAzureCredential. Grant the principal the built-in Reader role only.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

from .base import Collector, CollectorContext, CollectorResult, jsonable, modules_available, registry

log = logging.getLogger('argus.collectors.azure')

PRIVILEGED_ROLES = {'Owner', 'Contributor', 'User Access Administrator', 'Role Based Access Control Administrator'}
INTERNET_SOURCES = {'*', 'Internet', '0.0.0.0/0', '0.0.0.0', '::/0', 'any'}  # nosec B104
SENSITIVE_PORTS = {22, 3389, 1433, 3306, 5432, 6379, 27017, 445, 5985, 5986, 23, 21}


class AzureCollector(Collector):
    name = 'azure'
    kind = 'cloud'
    description = 'Azure subscription inventory: resource groups, VMs, NSG rules open to the Internet, storage accounts, privileged role assignments and AKS.'
    sdk_modules = ('azure.identity', 'azure.mgmt.resource', 'azure.mgmt.compute', 'azure.mgmt.network', 'azure.mgmt.authorization')
    secret_fields = ['client_secret']
    config_schema = {
        'type': 'object', 'additionalProperties': False,
        'properties': {
            'auth': {'type': 'string', 'enum': ['client_secret', 'managed_identity', 'default'], 'description': 'Credential type; default client_secret'},
            'tenant_id': {'type': 'string', 'maxLength': 64},
            'client_id': {'type': 'string', 'maxLength': 64},
            'subscriptions': {'type': 'array', 'items': {'type': 'string'}, 'description': 'Subscription ids to limit to; default all visible'},
            'cloud': {'type': 'string', 'enum': ['public', 'usgovernment', 'china']},
        },
    }

    async def collect(self, ctx: CollectorContext) -> CollectorResult:
        raw = await asyncio.to_thread(_fetch, ctx.config, ctx.logger)
        return self._normalize(raw)

    def _normalize(self, raw: dict[str, Any]) -> CollectorResult:
        r = CollectorResult()
        source = self.source
        counts = {'subscriptions': 0, 'resource_groups': 0, 'vms': 0, 'nsgs': 0, 'storage_accounts': 0, 'role_assignments': 0, 'aks': 0}
        for warning in raw.get('warnings', []) or []:
            r.warn(str(warning))
        tenant_id = raw.get('tenant_id') or ''
        for sub in raw.get('subscriptions', []) or []:
            sub_id = str(sub.get('subscription_id') or '')
            sub_scope = f'/subscriptions/{sub_id}'
            sub_node = r.node('asset', f'azure:subscription:{sub_id}', {'provider': 'azure', 'type': 'subscription', 'name': sub.get('display_name'),
                                                                        'state': sub.get('state'), 'tenant_id': tenant_id},
                              label=f"Azure subscription {sub.get('display_name') or sub_id}", criticality='high')
            counts['subscriptions'] += 1
            for rg in sub.get('resource_groups', []) or []:
                node = r.node('asset', f"azure:rg:{(rg.get('id') or rg.get('name') or '').lower()}", {'provider': 'azure', 'type': 'resource_group', 'name': rg.get('name'),
                                                                                                    'location': rg.get('location'), 'tags': rg.get('tags') or {}},
                              label=f"RG {rg.get('name')}", criticality='low')
                r.edge(sub_node, node, 'owns')
                counts['resource_groups'] += 1

            public_ips = {(p.get('id') or '').lower(): p.get('ip_address') for p in sub.get('public_ips', []) or []}
            nsg_open: dict[str, list[dict[str, Any]]] = {}
            nsg_nodes: dict[str, Any] = {}
            for nsg in sub.get('nsgs', []) or []:
                nsg_id = (nsg.get('id') or '').lower()
                rules = _open_rules(nsg)
                nsg_open[nsg_id] = rules
                node = r.node('network', f'azure:nsg:{nsg_id}', {'provider': 'azure', 'type': 'nsg', 'name': nsg.get('name'), 'location': nsg.get('location'),
                                                                 'open_ingress': rules}, label=f"NSG {nsg.get('name')}", criticality='high' if rules else 'low')
                nsg_nodes[nsg_id] = node
                r.edge(sub_node, node, 'owns')
                counts['nsgs'] += 1
                for rule in rules:
                    exposure = r.node('exposure', f"azure:exposure:nsg:{nsg_id}:{rule['name']}", {'type': 'open_nsg_rule', **rule},
                                      label=f"{nsg.get('name')} {rule['name']} {rule['ports']} from Internet", criticality='critical' if rule['sensitive'] else 'high')
                    r.edge(node, exposure, 'exposes')
                    if rule['sensitive']:
                        r.event(source, f"azure:{sub_id}:nsg-open:{nsg.get('name')}:{rule['name']}", f"NSG {nsg.get('name')} allows {rule['ports']} from the Internet",
                                'high', 'cloud_api', entity=node.key, action='nsg_rule_open', metadata={'subscription_id': sub_id, 'ports': rule['ports'], 'rule': rule['name']})

            for vm in sub.get('vms', []) or []:
                vm_id = (vm.get('id') or '').lower()
                identity = vm.get('identity') or {}
                node = r.node('asset', f'azure:vm:{vm_id}', {'provider': 'azure', 'type': 'virtual_machine', 'name': vm.get('name'), 'location': vm.get('location'),
                                                             'vm_size': (vm.get('hardware_profile') or {}).get('vm_size'),
                                                             'os': ((vm.get('storage_profile') or {}).get('os_disk') or {}).get('os_type'),
                                                             'managed_identity': identity.get('type'), 'tags': vm.get('tags') or {}},
                              label=vm.get('name') or vm_id, criticality='medium')
                r.edge(sub_node, node, 'owns')
                counts['vms'] += 1
                for nic in (vm.get('network_profile') or {}).get('network_interfaces', []) or []:
                    nic_detail = nic.get('detail') or {}
                    nsg_ref = ((nic_detail.get('network_security_group') or {}).get('id') or '').lower()
                    if nsg_ref:
                        r.edge(node, nsg_nodes.get(nsg_ref) or ('network', f'azure:nsg:{nsg_ref}'), 'connects_to', {'via': 'nic'})
                        for rule in nsg_open.get(nsg_ref, []):
                            r.edge(node, ('exposure', f"azure:exposure:nsg:{nsg_ref}:{rule['name']}"), 'exposes')
                    for ipc in nic_detail.get('ip_configurations', []) or []:
                        pip = ((ipc.get('public_ip_address') or {}).get('id') or '').lower()
                        if pip:
                            node.props['public_ip'] = public_ips.get(pip) or True
                            node.criticality = 'high'
                if identity.get('principal_id'):
                    ident = r.node('identity', f"azure:principal:{identity['principal_id']}", {'provider': 'azure', 'type': 'managed_identity', 'vm': vm.get('name')},
                                   label=f"MI {vm.get('name')}")
                    r.edge(node, ident, 'can_assume', {'via': 'system_assigned_identity'})

            for sa in sub.get('storage_accounts', []) or []:
                sa_id = (sa.get('id') or '').lower()
                public_blob = bool(sa.get('allow_blob_public_access'))
                https_only = sa.get('enable_https_traffic_only', True)
                net = sa.get('network_rule_set') or {}
                node = r.node('data_store', f'azure:storage:{sa_id}', {'provider': 'azure', 'type': 'storage_account', 'name': sa.get('name'), 'location': sa.get('location'),
                                                                       'allow_blob_public_access': public_blob, 'https_only': https_only,
                                                                       'minimum_tls_version': sa.get('minimum_tls_version'),
                                                                       'network_default_action': net.get('default_action'),
                                                                       'public_network_access': sa.get('public_network_access')},
                              label=f"Storage {sa.get('name')}", criticality='critical' if public_blob else 'high')
                r.edge(sub_node, node, 'owns')
                counts['storage_accounts'] += 1
                if public_blob:
                    exposure = r.node('exposure', f'azure:exposure:storage:{sa_id}', {'type': 'public_blob_access', 'name': sa.get('name')},
                                      label=f"Public blob access {sa.get('name')}", criticality='critical')
                    r.edge(node, exposure, 'exposes')
                    r.event(source, f"azure:{sub_id}:storage-public:{sa.get('name')}", f"Storage account {sa.get('name')} allows anonymous blob access", 'high',
                            'cloud_api', entity=node.key, action='storage_public', metadata={'subscription_id': sub_id})
                if https_only is False:
                    r.event(source, f"azure:{sub_id}:storage-http:{sa.get('name')}", f"Storage account {sa.get('name')} permits plain HTTP", 'medium', 'cloud_api',
                            entity=node.key, action='storage_http_allowed', metadata={'subscription_id': sub_id})

            for ra in sub.get('role_assignments', []) or []:
                role_name = ra.get('role_name') or (ra.get('role_definition_id') or '').rsplit('/', 1)[-1]
                scope = ra.get('scope') or ''
                principal_id = ra.get('principal_id') or ''
                ptype = ra.get('principal_type') or 'Unknown'
                perm = r.node('permission', f'azure:role:{role_name}@{scope.lower()}', {'provider': 'azure', 'role': role_name, 'scope': scope,
                                                                                      'admin': role_name == 'Owner', 'privileged': role_name in PRIVILEGED_ROLES,
                                                                                      'subscription_scope': scope.lower() == sub_scope.lower()},
                              label=f'{role_name} @ {scope.rsplit("/", 1)[-1] or scope}', criticality='critical' if role_name == 'Owner' else 'high' if role_name in PRIVILEGED_ROLES else 'medium')
                kind = 'role' if ptype == 'Group' else 'identity'
                ident = r.node(kind, f'azure:principal:{principal_id}', {'provider': 'azure', 'type': ptype.lower(), 'principal_id': principal_id,
                                                                        'display_name': ra.get('principal_name')}, label=ra.get('principal_name') or principal_id)
                r.edge(ident, perm, 'has_permission', {'assignment_id': ra.get('id')})
                counts['role_assignments'] += 1
                if role_name in PRIVILEGED_ROLES and scope.lower() == sub_scope.lower():
                    ident.criticality = 'critical' if role_name == 'Owner' else 'high'
                    ident.props['privileged'] = True
                    r.event(source, f'azure:{sub_id}:privileged-assignment:{principal_id}:{role_name}',
                            f'{ptype} {ra.get("principal_name") or principal_id} holds {role_name} on subscription {sub.get("display_name") or sub_id}',
                            'high' if role_name == 'Owner' else 'medium', 'cloud_api', actor=principal_id, entity=perm.key, action='privileged_role_assignment',
                            metadata={'subscription_id': sub_id, 'role': role_name, 'principal_type': ptype})

            for aks in sub.get('aks', []) or []:
                aks_id = (aks.get('id') or '').lower()
                api = aks.get('api_server_access_profile') or {}
                private = bool(api.get('enable_private_cluster'))
                ranges = api.get('authorized_ip_ranges') or []
                open_api = not private and not ranges
                node = r.node('asset', f'azure:aks:{aks_id}', {'provider': 'azure', 'type': 'aks_cluster', 'name': aks.get('name'), 'location': aks.get('location'),
                                                               'kubernetes_version': aks.get('kubernetes_version'), 'private_cluster': private,
                                                               'authorized_ip_ranges': ranges, 'rbac_enabled': aks.get('enable_rbac'),
                                                               'local_accounts_disabled': aks.get('disable_local_accounts')},
                              label=f"AKS {aks.get('name')}", criticality='critical' if open_api else 'high')
                r.edge(sub_node, node, 'owns')
                counts['aks'] += 1
                if open_api:
                    exposure = r.node('exposure', f'azure:exposure:aks:{aks_id}', {'type': 'public_k8s_api'}, label=f"Public AKS API {aks.get('name')}", criticality='high')
                    r.edge(node, exposure, 'exposes')
                    r.event(source, f"azure:{sub_id}:aks-public:{aks.get('name')}", f"AKS cluster {aks.get('name')} API server is reachable from any IP", 'medium',
                            'cloud_api', entity=node.key, action='k8s_api_public', metadata={'subscription_id': sub_id})
        r.stats.update(counts)
        return r.finalize()


def _open_rules(nsg: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for rule in nsg.get('security_rules', []) or []:
        if rule.get('direction') != 'Inbound' or rule.get('access') != 'Allow':
            continue
        sources = [rule.get('source_address_prefix')] + list(rule.get('source_address_prefixes') or [])
        if not any(str(s) in INTERNET_SOURCES for s in sources if s):
            continue
        ports = [str(rule.get('destination_port_range') or '')] + [str(p) for p in rule.get('destination_port_ranges') or []]
        ports = [p for p in ports if p]
        out.append({'name': rule.get('name'), 'protocol': rule.get('protocol'), 'ports': ','.join(ports) or '*', 'priority': rule.get('priority'),
                    'sensitive': _sensitive(ports)})
    return out


def _sensitive(ports: list[str]) -> bool:
    for spec in ports:
        if spec == '*':
            return True
        for part in spec.split(','):
            part = part.strip()
            if '-' in part:
                lo, _, hi = part.partition('-')
                if lo.isdigit() and hi.isdigit() and any(int(lo) <= p <= int(hi) for p in SENSITIVE_PORTS):
                    return True
            elif part.isdigit() and int(part) in SENSITIVE_PORTS:
                return True
    return False


# ---------------------------------------------------------------- fetch


def _credential(config: dict[str, Any]) -> Any:
    """Tests monkeypatch this."""
    from azure.identity import ClientSecretCredential, DefaultAzureCredential, ManagedIdentityCredential  # lazy

    mode = config.get('auth') or 'client_secret'
    if mode == 'client_secret':
        if not (config.get('tenant_id') and config.get('client_id') and config.get('client_secret')):
            raise ValueError('azure collector needs tenant_id, client_id and client_secret for client_secret auth')
        return ClientSecretCredential(config['tenant_id'], config['client_id'], config['client_secret'])
    if mode == 'managed_identity':
        return ManagedIdentityCredential(client_id=config['client_id']) if config.get('client_id') else ManagedIdentityCredential()
    return DefaultAzureCredential()


def _subscription_client(credential: Any) -> Any:
    from azure.mgmt.resource import SubscriptionClient  # lazy

    return SubscriptionClient(credential)


def _clients(credential: Any, subscription_id: str) -> dict[str, Any]:
    """Per-subscription ARM clients. Storage and container-service packages are optional."""
    from azure.mgmt.authorization import AuthorizationManagementClient
    from azure.mgmt.compute import ComputeManagementClient
    from azure.mgmt.network import NetworkManagementClient
    from azure.mgmt.resource import ResourceManagementClient

    clients: dict[str, Any] = {
        'resource': ResourceManagementClient(credential, subscription_id),
        'compute': ComputeManagementClient(credential, subscription_id),
        'network': NetworkManagementClient(credential, subscription_id),
        'authorization': AuthorizationManagementClient(credential, subscription_id),
    }
    if modules_available('azure.mgmt.storage'):
        from azure.mgmt.storage import StorageManagementClient

        clients['storage'] = StorageManagementClient(credential, subscription_id)
    if modules_available('azure.mgmt.containerservice'):
        from azure.mgmt.containerservice import ContainerServiceClient

        clients['containerservice'] = ContainerServiceClient(credential, subscription_id)
    return clients


def _dump(obj: Any) -> Any:
    if obj is None:
        return None
    if hasattr(obj, 'as_dict'):
        return obj.as_dict()
    return jsonable(obj)


def _fetch(config: dict[str, Any], logger: logging.Logger) -> dict[str, Any]:
    warnings: list[str] = []
    credential = _credential(config)
    wanted = {s.lower() for s in config.get('subscriptions') or []}
    raw: dict[str, Any] = {'tenant_id': config.get('tenant_id', ''), 'subscriptions': [], 'warnings': warnings}

    def guarded(label: str, fn, default):
        try:
            return fn()
        except Exception as exc:
            warnings.append(f'{label}: {type(exc).__name__}')
            logger.warning('azure collector: %s failed: %s', label, type(exc).__name__)
            return default

    subs = guarded('subscriptions.list', lambda: [_dump(s) for s in _subscription_client(credential).subscriptions.list()], [])
    for sub in subs:
        sub_id = sub.get('subscription_id') or (sub.get('id') or '').rsplit('/', 1)[-1]
        if wanted and sub_id.lower() not in wanted:
            continue
        clients = _clients(credential, sub_id)
        entry: dict[str, Any] = {'subscription_id': sub_id, 'display_name': sub.get('display_name'), 'state': sub.get('state')}
        entry['resource_groups'] = guarded(f'resource_groups.list[{sub_id}]', lambda: [_dump(x) for x in clients['resource'].resource_groups.list()], [])
        entry['vms'] = guarded(f'virtual_machines.list_all[{sub_id}]', lambda: [_dump(x) for x in clients['compute'].virtual_machines.list_all()], [])
        nics = {n['id'].lower(): n for n in guarded(f'network_interfaces.list_all[{sub_id}]', lambda: [_dump(x) for x in clients['network'].network_interfaces.list_all()], [])}
        for vm in entry['vms']:
            for ref in (vm.get('network_profile') or {}).get('network_interfaces', []) or []:
                ref['detail'] = nics.get((ref.get('id') or '').lower(), {})
        entry['nsgs'] = guarded(f'network_security_groups.list_all[{sub_id}]', lambda: [_dump(x) for x in clients['network'].network_security_groups.list_all()], [])
        entry['public_ips'] = guarded(f'public_ip_addresses.list_all[{sub_id}]', lambda: [_dump(x) for x in clients['network'].public_ip_addresses.list_all()], [])
        if 'storage' in clients:
            entry['storage_accounts'] = guarded(f'storage_accounts.list[{sub_id}]', lambda: [_dump(x) for x in clients['storage'].storage_accounts.list()], [])
        else:
            warnings.append('azure-mgmt-storage not installed: storage accounts skipped')
        assignments = guarded(f'role_assignments.list_for_subscription[{sub_id}]',
                              lambda: [_dump(x) for x in clients['authorization'].role_assignments.list_for_subscription()], [])
        role_names: dict[str, str] = {}
        for ra in assignments:
            rd_id = ra.get('role_definition_id') or ''
            if rd_id and rd_id not in role_names:
                role_names[rd_id] = guarded(f'role_definitions.get_by_id', lambda: _dump(clients['authorization'].role_definitions.get_by_id(rd_id)).get('role_name', ''), '')
            ra['role_name'] = role_names.get(rd_id, '')
        entry['role_assignments'] = assignments
        if 'containerservice' in clients:
            entry['aks'] = guarded(f'managed_clusters.list[{sub_id}]', lambda: [_dump(x) for x in clients['containerservice'].managed_clusters.list()], [])
        else:
            warnings.append('azure-mgmt-containerservice not installed: AKS skipped')
        raw['subscriptions'].append(entry)
    return jsonable(raw)


registry.register(AzureCollector())
