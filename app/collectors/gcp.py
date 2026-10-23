"""GCP collector (google-cloud-asset + google-cloud-resource-manager, read-only). Uses Cloud
Asset Inventory so one API covers compute, firewalls, buckets, GKE and IAM policies.

API calls made:
  resourcemanager_v3.ProjectsClient.search_projects(query='state:ACTIVE')     (or configured projects)
  asset_v1.AssetServiceClient.list_assets(parent='projects/<id>', content_type=RESOURCE,
        asset_types=[compute.googleapis.com/Instance, compute.googleapis.com/Firewall,
                     storage.googleapis.com/Bucket, container.googleapis.com/Cluster])
  asset_v1.AssetServiceClient.list_assets(parent='projects/<id>', content_type=IAM_POLICY,
        asset_types=[cloudresourcemanager.googleapis.com/Project, storage.googleapis.com/Bucket])
Credential: service account JSON (secret `service_account_json`) or Application Default Credentials.
Required roles: roles/cloudasset.viewer and roles/browser (or Security Reviewer).
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from .base import Collector, CollectorContext, CollectorResult, jsonable, registry

log = logging.getLogger('sentinel.collectors.gcp')

RESOURCE_TYPES = ['compute.googleapis.com/Instance', 'compute.googleapis.com/Firewall', 'storage.googleapis.com/Bucket', 'container.googleapis.com/Cluster']
IAM_TYPES = ['cloudresourcemanager.googleapis.com/Project', 'storage.googleapis.com/Bucket']
PRIMITIVE_ROLES = {'roles/owner', 'roles/editor', 'roles/viewer'}
PUBLIC_MEMBERS = {'allUsers', 'allAuthenticatedUsers'}
WORLD = {'0.0.0.0/0', '::/0'}
SENSITIVE_PORTS = {22, 3389, 3306, 5432, 1433, 27017, 6379, 9200, 2375, 6443, 10250, 23, 21}


class GcpCollector(Collector):
    name = 'gcp'
    kind = 'cloud'
    description = 'GCP project inventory via Cloud Asset Inventory: compute instances, firewall rules open to the Internet, public GCS buckets, primitive IAM roles and GKE.'
    sdk_modules = ('google.cloud.asset_v1', 'google.cloud.resourcemanager_v3')
    secret_fields = ['service_account_json']
    config_schema = {
        'type': 'object', 'additionalProperties': False,
        'properties': {
            'projects': {'type': 'array', 'items': {'type': 'string', 'pattern': r'^[a-z][a-z0-9-]{4,28}[a-z0-9]$'}, 'description': 'Project ids; default all projects visible'},
            'organization_id': {'type': 'string', 'pattern': r'^\d+$', 'description': 'Limit project search to this organization'},
        },
    }

    async def collect(self, ctx: CollectorContext) -> CollectorResult:
        raw = await asyncio.to_thread(_fetch, ctx.config, ctx.logger)
        return self._normalize(raw)

    def _normalize(self, raw: dict[str, Any]) -> CollectorResult:
        r = CollectorResult()
        source = self.source
        counts = {'projects': 0, 'instances': 0, 'firewalls': 0, 'buckets': 0, 'gke_clusters': 0, 'iam_bindings': 0}
        for warning in raw.get('warnings', []) or []:
            r.warn(str(warning))
        for project in raw.get('projects', []) or []:
            pid = str(project.get('project_id') or '')
            pnode = r.node('asset', f'gcp:project:{pid}', {'provider': 'gcp', 'type': 'project', 'name': project.get('display_name'), 'state': project.get('state'),
                                                           'project_number': project.get('project_number')}, label=f'GCP project {pid}', criticality='high')
            counts['projects'] += 1

            open_fw: list[dict[str, Any]] = []
            for fw in project.get('firewalls', []) or []:
                data = fw.get('data') or fw
                if data.get('direction', 'INGRESS') != 'INGRESS' or data.get('disabled'):
                    continue
                if not any(rng in WORLD for rng in data.get('sourceRanges') or []):
                    continue
                allowed = []
                sensitive = False
                for entry in data.get('allowed') or []:
                    proto = entry.get('IPProtocol', 'all')
                    ports = entry.get('ports') or ['all']
                    allowed.append(f"{proto}:{','.join(ports)}")
                    sensitive = sensitive or proto == 'all' or _sensitive(ports)
                rule = {'name': data.get('name'), 'network': (data.get('network') or '').rsplit('/', 1)[-1], 'allowed': allowed,
                        'target_tags': data.get('targetTags') or [], 'target_service_accounts': data.get('targetServiceAccounts') or [], 'sensitive': sensitive,
                        'priority': data.get('priority')}
                open_fw.append(rule)
                counts['firewalls'] += 1
                net = r.node('network', f"gcp:firewall:{pid}:{rule['name']}", {'provider': 'gcp', 'type': 'firewall_rule', **rule}, label=f"Firewall {rule['name']}",
                             criticality='high')
                r.edge(pnode, net, 'owns')
                exposure = r.node('exposure', f"gcp:exposure:firewall:{pid}:{rule['name']}", {'type': 'open_firewall_rule', 'allowed': allowed, 'network': rule['network']},
                                  label=f"{rule['name']} {' '.join(allowed)} from Internet", criticality='critical' if sensitive else 'high')
                r.edge(net, exposure, 'exposes')
                if sensitive:
                    r.event(source, f"gcp:{pid}:firewall-open:{rule['name']}", f"Firewall rule {rule['name']} allows {' '.join(allowed)} from 0.0.0.0/0", 'high',
                            'cloud_api', entity=net.key, action='firewall_rule_open', metadata={'project_id': pid, 'allowed': allowed, 'network': rule['network']})

            for inst in project.get('instances', []) or []:
                data = inst.get('data') or inst
                name = data.get('name', '')
                zone = (data.get('zone') or '').rsplit('/', 1)[-1]
                nat_ips = [ac.get('natIP') for ni in data.get('networkInterfaces') or [] for ac in ni.get('accessConfigs') or [] if ac.get('natIP')]
                tags = (data.get('tags') or {}).get('items') or []
                sas = [sa.get('email') for sa in data.get('serviceAccounts') or []]
                scopes = [s for sa in data.get('serviceAccounts') or [] for s in sa.get('scopes') or []]
                node = r.node('asset', f'gcp:instance:{pid}:{zone}:{name}', {'provider': 'gcp', 'type': 'compute_instance', 'name': name, 'zone': zone, 'status': data.get('status'),
                                                                            'machine_type': (data.get('machineType') or '').rsplit('/', 1)[-1], 'public_ips': nat_ips,
                                                                            'network_tags': tags, 'service_accounts': sas,
                                                                            'cloud_platform_scope': 'https://www.googleapis.com/auth/cloud-platform' in scopes,
                                                                            'shielded_vm': bool((data.get('shieldedInstanceConfig') or {}).get('enableSecureBoot'))},
                              label=name, criticality='high' if nat_ips else 'medium')
                r.edge(pnode, node, 'owns')
                counts['instances'] += 1
                for sa in sas:
                    ident = r.node('identity', f'gcp:sa:{sa}', {'provider': 'gcp', 'type': 'service_account', 'email': sa}, label=sa)
                    r.edge(node, ident, 'can_assume', {'via': 'attached_service_account'})
                networks = {(ni.get('network') or '').rsplit('/', 1)[-1] for ni in data.get('networkInterfaces') or []}
                for rule in open_fw:
                    applies = rule['network'] in networks and (not rule['target_tags'] or set(rule['target_tags']) & set(tags)) and \
                        (not rule['target_service_accounts'] or set(rule['target_service_accounts']) & set(sas))
                    if applies:
                        r.edge(node, ('exposure', f"gcp:exposure:firewall:{pid}:{rule['name']}"), 'exposes', {'public_ip': bool(nat_ips)})

            bucket_iam = project.get('bucket_iam') or {}
            for bucket in project.get('buckets', []) or []:
                data = bucket.get('data') or bucket
                name = data.get('name') or data.get('id', '')
                bindings = bucket_iam.get(name) or bucket_iam.get(f'//storage.googleapis.com/{name}') or []
                public_roles = sorted({b.get('role') for b in bindings if set(b.get('members') or []) & PUBLIC_MEMBERS})
                iam_cfg = data.get('iamConfiguration') or {}
                node = r.node('data_store', f'gcp:bucket:{name}', {'provider': 'gcp', 'type': 'gcs_bucket', 'name': name, 'location': data.get('location'),
                                                                  'storage_class': data.get('storageClass'), 'public': bool(public_roles), 'public_roles': public_roles,
                                                                  'public_access_prevention': iam_cfg.get('publicAccessPrevention'),
                                                                  'uniform_bucket_level_access': bool((iam_cfg.get('uniformBucketLevelAccess') or {}).get('enabled'))},
                              label=f'gs://{name}', criticality='critical' if public_roles else 'high')
                r.edge(pnode, node, 'owns')
                counts['buckets'] += 1
                if public_roles:
                    exposure = r.node('exposure', f'gcp:exposure:bucket:{name}', {'type': 'public_bucket', 'roles': public_roles}, label=f'Public bucket {name}', criticality='critical')
                    r.edge(node, exposure, 'exposes')
                    r.event(source, f'gcp:{pid}:public-bucket:{name}', f'GCS bucket {name} grants {", ".join(public_roles)} to allUsers/allAuthenticatedUsers', 'high',
                            'cloud_api', entity=node.key, action='bucket_public', metadata={'project_id': pid, 'roles': public_roles})

            for binding in project.get('iam_bindings', []) or []:
                role = binding.get('role', '')
                for member in binding.get('members') or []:
                    counts['iam_bindings'] += 1
                    mtype, _, mid = member.partition(':')
                    if member in PUBLIC_MEMBERS:
                        mtype, mid = 'public', member
                    kind = 'role' if mtype in ('group', 'domain') else 'identity'
                    ident = r.node(kind, f'gcp:member:{member}', {'provider': 'gcp', 'type': mtype, 'id': mid}, label=member,
                                   criticality='critical' if role == 'roles/owner' else 'medium')
                    perm = r.node('permission', f'gcp:role:{role}@{pid}', {'provider': 'gcp', 'role': role, 'project_id': pid, 'admin': role == 'roles/owner',
                                                                          'primitive': role in PRIMITIVE_ROLES, 'wildcard': role in {'roles/owner', 'roles/editor'}},
                                  label=f'{role} @ {pid}', criticality='critical' if role == 'roles/owner' else 'high' if role in PRIMITIVE_ROLES else 'medium')
                    r.edge(ident, perm, 'has_permission', {'condition': bool(binding.get('condition'))})
                    if role in PRIMITIVE_ROLES and role != 'roles/viewer':
                        r.event(source, f'gcp:{pid}:primitive-role:{member}:{role}', f'{member} holds primitive role {role} on project {pid}',
                                'high' if role == 'roles/owner' else 'medium', 'cloud_api', actor=member, entity=perm.key, action='primitive_role_binding',
                                metadata={'project_id': pid, 'role': role})
                    if member in PUBLIC_MEMBERS:
                        r.event(source, f'gcp:{pid}:public-member:{member}:{role}', f'Project {pid} grants {role} to {member}', 'critical', 'cloud_api',
                                actor=member, entity=perm.key, action='project_public_binding', metadata={'project_id': pid, 'role': role})

            for cluster in project.get('gke_clusters', []) or []:
                data = cluster.get('data') or cluster
                name = data.get('name', '')
                location = data.get('location') or data.get('zone', '')
                private = data.get('privateClusterConfig') or {}
                man = data.get('masterAuthorizedNetworksConfig') or {}
                public_master = not private.get('enablePrivateEndpoint') and not man.get('enabled')
                node = r.node('asset', f'gcp:gke:{pid}:{location}:{name}', {'provider': 'gcp', 'type': 'gke_cluster', 'name': name, 'location': location,
                                                                           'version': data.get('currentMasterVersion'), 'private_endpoint': bool(private.get('enablePrivateEndpoint')),
                                                                           'private_nodes': bool(private.get('enablePrivateNodes')), 'authorized_networks': bool(man.get('enabled')),
                                                                           'legacy_abac': bool((data.get('legacyAbac') or {}).get('enabled')),
                                                                           'workload_identity': bool((data.get('workloadIdentityConfig') or {}).get('workloadPool')),
                                                                           'shielded_nodes': bool((data.get('shieldedNodes') or {}).get('enabled'))},
                              label=f'GKE {name}', criticality='critical' if public_master else 'high')
                r.edge(pnode, node, 'owns')
                counts['gke_clusters'] += 1
                if public_master:
                    exposure = r.node('exposure', f'gcp:exposure:gke:{pid}:{name}', {'type': 'public_k8s_api'}, label=f'Public GKE API {name}', criticality='high')
                    r.edge(node, exposure, 'exposes')
                    r.event(source, f'gcp:{pid}:gke-public:{name}', f'GKE cluster {name} control plane is reachable from any IP', 'medium', 'cloud_api',
                            entity=node.key, action='k8s_api_public', metadata={'project_id': pid, 'location': location})
        r.stats.update(counts)
        return r.finalize()


def _sensitive(ports: list[str]) -> bool:
    for spec in ports:
        if spec == 'all':
            return True
        if '-' in spec:
            lo, _, hi = spec.partition('-')
            if lo.isdigit() and hi.isdigit() and any(int(lo) <= p <= int(hi) for p in SENSITIVE_PORTS):
                return True
        elif spec.isdigit() and int(spec) in SENSITIVE_PORTS:
            return True
    return False


# ---------------------------------------------------------------- fetch


def _credentials(config: dict[str, Any]) -> Any:
    """Tests monkeypatch this. None means Application Default Credentials."""
    if not config.get('service_account_json'):
        return None
    from google.oauth2 import service_account  # lazy

    info = json.loads(config['service_account_json'])
    return service_account.Credentials.from_service_account_info(info, scopes=['https://www.googleapis.com/auth/cloud-platform.read-only'])


def _projects_client(credentials: Any) -> Any:
    from google.cloud import resourcemanager_v3  # lazy

    return resourcemanager_v3.ProjectsClient(credentials=credentials)


def _asset_client(credentials: Any) -> Any:
    from google.cloud import asset_v1  # lazy

    return asset_v1.AssetServiceClient(credentials=credentials)


def _to_dict(message: Any) -> dict[str, Any]:
    if isinstance(message, dict):
        return message
    try:
        return type(message).to_dict(message)  # proto-plus
    except Exception:
        from google.protobuf.json_format import MessageToDict

        return MessageToDict(getattr(message, '_pb', message))


def _fetch(config: dict[str, Any], logger: logging.Logger) -> dict[str, Any]:
    warnings: list[str] = []
    credentials = _credentials(config)
    raw: dict[str, Any] = {'projects': [], 'warnings': warnings}

    def guarded(label: str, fn, default):
        try:
            return fn()
        except Exception as exc:
            warnings.append(f'{label}: {type(exc).__name__}')
            logger.warning('gcp collector: %s failed: %s', label, type(exc).__name__)
            return default

    project_ids = list(config.get('projects') or [])
    projects: list[dict[str, Any]] = []
    if project_ids:
        projects = [{'project_id': p, 'display_name': p, 'state': 'ACTIVE'} for p in project_ids]
    else:
        query = 'state:ACTIVE' + (f" parent:organizations/{config['organization_id']}" if config.get('organization_id') else '')
        for p in guarded('projects.search_projects', lambda: list(_projects_client(credentials).search_projects(query=query)), []):
            d = _to_dict(p)
            projects.append({'project_id': d.get('project_id') or d.get('projectId'), 'display_name': d.get('display_name') or d.get('displayName'),
                             'state': d.get('state'), 'project_number': (d.get('name') or '').rsplit('/', 1)[-1]})
    assets = _asset_client(credentials)
    for project in projects:
        pid = project['project_id']
        entry: dict[str, Any] = {**project, 'instances': [], 'firewalls': [], 'buckets': [], 'gke_clusters': [], 'iam_bindings': [], 'bucket_iam': {}}
        resources = guarded(f'assets.list_assets[{pid}]', lambda: list(assets.list_assets(request={'parent': f'projects/{pid}', 'asset_types': RESOURCE_TYPES,
                                                                                                    'content_type': 'RESOURCE'})), [])
        for asset in resources:
            d = _to_dict(asset)
            atype = d.get('asset_type') or d.get('assetType', '')
            data = ((d.get('resource') or {}).get('data')) or {}
            bucket = {'name': d.get('name'), 'data': data}
            if atype.endswith('/Instance'):
                entry['instances'].append(bucket)
            elif atype.endswith('/Firewall'):
                entry['firewalls'].append(bucket)
            elif atype.endswith('/Bucket'):
                entry['buckets'].append(bucket)
            elif atype.endswith('/Cluster'):
                entry['gke_clusters'].append(bucket)
        policies = guarded(f'assets.list_assets[{pid}:iam]', lambda: list(assets.list_assets(request={'parent': f'projects/{pid}', 'asset_types': IAM_TYPES,
                                                                                                       'content_type': 'IAM_POLICY'})), [])
        for asset in policies:
            d = _to_dict(asset)
            atype = d.get('asset_type') or d.get('assetType', '')
            bindings = (d.get('iam_policy') or d.get('iamPolicy') or {}).get('bindings') or []
            if atype.endswith('/Project'):
                entry['iam_bindings'].extend(bindings)
            elif atype.endswith('/Bucket'):
                entry['bucket_iam'][(d.get('name') or '').rsplit('/', 1)[-1]] = bindings
        raw['projects'].append(entry)
    return jsonable(raw)


registry.register(GcpCollector())
