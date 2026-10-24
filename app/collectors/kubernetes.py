"""Kubernetes collector (official python client, read-only). Inventories namespaces, workloads
with their security posture, service accounts, cluster-admin bindings, exposed services and
secret names (never values).

API calls made (all list, no watch):
  CoreV1Api.list_namespace, list_pod_for_all_namespaces, list_service_account_for_all_namespaces,
  list_service_for_all_namespaces, list_secret_for_all_namespaces (data stripped before serialization)
  AppsV1Api.list_deployment_for_all_namespaces, list_daemon_set_for_all_namespaces, list_stateful_set_for_all_namespaces
  RbacAuthorizationV1Api.list_cluster_role_binding
Auth: kubeconfig file (+context), inline kubeconfig (secret `kubeconfig`), bearer token (secret `token`
with api_url) or in-cluster service account. Bind the identity to the built-in `view` ClusterRole
plus `list secrets` metadata only if you want secret names.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

from .base import Collector, CollectorContext, CollectorResult, jsonable, registry

log = logging.getLogger('argus.collectors.kubernetes')

SYSTEM_NAMESPACES = {'kube-system', 'kube-public', 'kube-node-lease'}
SHELL_IMAGES = ('busybox', 'alpine', 'ubuntu', 'debian', 'kali')


class KubernetesCollector(Collector):
    name = 'kubernetes'
    kind = 'k8s'
    description = 'Kubernetes cluster inventory: namespaces, workloads with privileged/hostPID/hostNetwork/root flags, service accounts, cluster-admin bindings, exposed services, secret names.'
    sdk_modules = ('kubernetes',)
    secret_fields = ['kubeconfig', 'token']
    config_schema = {
        'type': 'object', 'additionalProperties': False,
        'properties': {
            'mode': {'type': 'string', 'enum': ['kubeconfig', 'in_cluster', 'token'], 'description': 'How to connect; default kubeconfig'},
            'cluster_name': {'type': 'string', 'maxLength': 120, 'description': 'Label used for graph keys; default from context'},
            'kubeconfig_path': {'type': 'string', 'maxLength': 512},
            'context': {'type': 'string', 'maxLength': 120},
            'api_url': {'type': 'string', 'pattern': r'^https://', 'description': 'API server URL for token mode'},
            'ca_cert_path': {'type': 'string', 'maxLength': 512},
            'verify_ssl': {'type': 'boolean'},
            'namespaces': {'type': 'array', 'items': {'type': 'string'}, 'description': 'Limit to these namespaces; default all'},
            'include_secrets': {'type': 'boolean', 'description': 'List secret names (metadata only); default true'},
        },
    }

    async def collect(self, ctx: CollectorContext) -> CollectorResult:
        raw = await asyncio.to_thread(_fetch, ctx.config, ctx.logger)
        return self._normalize(raw)

    def _normalize(self, raw: dict[str, Any]) -> CollectorResult:
        r = CollectorResult()
        source = self.source
        cluster = str(raw.get('cluster') or 'default')
        wanted = set(raw.get('namespaces_filter') or [])
        for warning in raw.get('warnings', []) or []:
            r.warn(str(warning))
        counts = {'namespaces': 0, 'workloads': 0, 'pods': 0, 'service_accounts': 0, 'cluster_role_bindings': 0, 'services': 0, 'secrets': 0,
                  'privileged_workloads': 0}
        cnode = r.node('asset', f'k8s:cluster:{cluster}', {'provider': 'kubernetes', 'type': 'k8s_cluster', 'name': cluster, 'version': raw.get('version')},
                       label=f'Cluster {cluster}', criticality='high')

        def in_scope(ns: str) -> bool:
            return not wanted or ns in wanted

        ns_nodes: dict[str, Any] = {}
        for ns in raw.get('namespaces', []) or []:
            meta = ns.get('metadata') or {}
            name = meta.get('name', '')
            if not in_scope(name):
                continue
            labels = meta.get('labels') or {}
            node = r.node('asset', f'k8s:ns:{cluster}/{name}', {'provider': 'kubernetes', 'type': 'namespace', 'name': name, 'cluster': cluster,
                                                               'pod_security_enforce': labels.get('pod-security.kubernetes.io/enforce'), 'system': name in SYSTEM_NAMESPACES},
                          label=f'ns/{name}', criticality='low')
            ns_nodes[name] = node
            r.edge(cnode, node, 'owns')
            counts['namespaces'] += 1

        def ns_node(name: str) -> Any:
            return ns_nodes.get(name) or r.node('asset', f'k8s:ns:{cluster}/{name}', {'provider': 'kubernetes', 'type': 'namespace', 'name': name, 'cluster': cluster},
                                               label=f'ns/{name}', criticality='low')

        sa_nodes: dict[tuple[str, str], Any] = {}
        for sa in raw.get('service_accounts', []) or []:
            meta = sa.get('metadata') or {}
            ns, name = meta.get('namespace', 'default'), meta.get('name', '')
            if not in_scope(ns):
                continue
            node = r.node('identity', f'k8s:sa:{cluster}/{ns}/{name}', {'provider': 'kubernetes', 'type': 'service_account', 'namespace': ns, 'name': name,
                                                                        'automount_token': sa.get('automountServiceAccountToken', True) is not False},
                          label=f'sa/{ns}/{name}', criticality='low')
            sa_nodes[(ns, name)] = node
            r.edge(ns_node(ns), node, 'owns')
            counts['service_accounts'] += 1

        def sa_node(ns: str, name: str) -> Any:
            return sa_nodes.get((ns, name)) or r.node('identity', f'k8s:sa:{cluster}/{ns}/{name}', {'provider': 'kubernetes', 'type': 'service_account', 'namespace': ns, 'name': name},
                                                     label=f'sa/{ns}/{name}', criticality='low')

        for crb in raw.get('cluster_role_bindings', []) or []:
            role_ref = crb.get('roleRef') or {}
            role_name = role_ref.get('name', '')
            is_admin = role_name == 'cluster-admin'
            counts['cluster_role_bindings'] += 1
            perm = r.node('permission', f'k8s:clusterrole:{cluster}/{role_name}', {'provider': 'kubernetes', 'type': 'cluster_role', 'name': role_name, 'admin': is_admin,
                                                                                  'wildcard': is_admin}, label=f'ClusterRole {role_name}',
                          criticality='critical' if is_admin else 'medium')
            for subject in crb.get('subjects') or []:
                skind, sname, sns = subject.get('kind'), subject.get('name', ''), subject.get('namespace', '')
                if skind == 'ServiceAccount':
                    subj = sa_node(sns or 'default', sname)
                elif skind == 'Group':
                    subj = r.node('role', f'k8s:group:{cluster}/{sname}', {'provider': 'kubernetes', 'type': 'group', 'name': sname}, label=f'group/{sname}')
                else:
                    subj = r.node('identity', f'k8s:user:{cluster}/{sname}', {'provider': 'kubernetes', 'type': 'user', 'name': sname}, label=f'user/{sname}')
                r.edge(subj, perm, 'has_permission', {'binding': (crb.get('metadata') or {}).get('name')})
                if is_admin:
                    subj.criticality = 'critical'
                    subj.props['cluster_admin'] = True
                    if not (skind == 'Group' and sname == 'system:masters'):  # the built-in bootstrap binding is expected
                        sev = 'critical' if sname in {'system:authenticated', 'system:unauthenticated', 'system:serviceaccounts'} else 'high'
                        r.event(source, f"k8s:{cluster}:cluster-admin:{skind}:{sns}:{sname}", f'{skind} {sname} is bound to cluster-admin', sev, 'k8s',
                                actor=f'{skind}/{sname}', entity=perm.key, action='cluster_admin_binding',
                                metadata={'cluster': cluster, 'binding': (crb.get('metadata') or {}).get('name'), 'namespace': sns})

        # -- workloads (controllers first, then pods so pod flags roll up to their owners)
        workload_nodes: dict[tuple[str, str, str], Any] = {}
        for kind_name, key in (('Deployment', 'deployments'), ('DaemonSet', 'daemonsets'), ('StatefulSet', 'statefulsets')):
            for obj in raw.get(key, []) or []:
                meta = obj.get('metadata') or {}
                ns, name = meta.get('namespace', 'default'), meta.get('name', '')
                if not in_scope(ns):
                    continue
                pod_spec = ((obj.get('spec') or {}).get('template') or {}).get('spec') or {}
                flags = _pod_flags(pod_spec)
                node = r.node('asset', f'k8s:{kind_name.lower()}:{cluster}/{ns}/{name}', {'provider': 'kubernetes', 'type': kind_name.lower(), 'namespace': ns, 'name': name,
                                                                                          'cluster': cluster, 'replicas': (obj.get('spec') or {}).get('replicas'),
                                                                                          'images': flags.pop('images'), **flags},
                              label=f'{kind_name.lower()}/{ns}/{name}', criticality='high' if flags['privileged'] or flags['host_pid'] or flags['host_network'] else 'medium')
                workload_nodes[(kind_name, ns, name)] = node
                r.edge(ns_node(ns), node, 'owns')
                counts['workloads'] += 1
                sa = pod_spec.get('serviceAccountName') or 'default'
                r.edge(node, sa_node(ns, sa), 'can_assume', {'via': 'pod_service_account'})
                if flags['privileged'] or flags['host_pid'] or flags['host_network']:
                    counts['privileged_workloads'] += 1
                    r.event(source, f'k8s:{cluster}:privileged:{kind_name}:{ns}/{name}', f'{kind_name} {ns}/{name} runs with elevated host access', 'high' if flags['privileged'] else 'medium',
                            'k8s', entity=node.key, action='privileged_workload', metadata={'cluster': cluster, 'namespace': ns, **_flag_meta(flags)})

        replicaset_owner: dict[tuple[str, str], tuple[str, str, str]] = {}
        for rs in raw.get('replicasets', []) or []:
            meta = rs.get('metadata') or {}
            for owner in meta.get('ownerReferences') or []:
                replicaset_owner[(meta.get('namespace', 'default'), meta.get('name', ''))] = (owner.get('kind', ''), meta.get('namespace', 'default'), owner.get('name', ''))

        for pod in raw.get('pods', []) or []:
            meta = pod.get('metadata') or {}
            ns, name = meta.get('namespace', 'default'), meta.get('name', '')
            if not in_scope(ns):
                continue
            counts['pods'] += 1
            spec = pod.get('spec') or {}
            flags = _pod_flags(spec)
            owner_key = None
            for owner in meta.get('ownerReferences') or []:
                okind, oname = owner.get('kind', ''), owner.get('name', '')
                owner_key = replicaset_owner.get((ns, oname)) if okind == 'ReplicaSet' else (okind, ns, oname)
                if owner_key is None and okind == 'ReplicaSet':
                    owner_key = ('Deployment', ns, oname.rsplit('-', 1)[0])
            owner_node = workload_nodes.get(owner_key) if owner_key else None
            if owner_node is not None:
                owner_node.props['pods'] = owner_node.props.get('pods', 0) + 1
                if spec.get('nodeName'):
                    node_asset = r.node('asset', f"k8s:node:{cluster}/{spec['nodeName']}", {'provider': 'kubernetes', 'type': 'node', 'name': spec['nodeName'], 'cluster': cluster},
                                        label=f"node/{spec['nodeName']}", criticality='high')
                    r.edge(node_asset, owner_node, 'runs')
                continue
            # Bare pod (no controller): model it directly
            node = r.node('asset', f'k8s:pod:{cluster}/{ns}/{name}', {'provider': 'kubernetes', 'type': 'pod', 'namespace': ns, 'name': name, 'cluster': cluster,
                                                                      'phase': (pod.get('status') or {}).get('phase'), 'images': flags.pop('images'), **flags},
                          label=f'pod/{ns}/{name}', criticality='high' if flags['privileged'] or flags['host_pid'] else 'medium')
            r.edge(ns_node(ns), node, 'owns')
            r.edge(node, sa_node(ns, spec.get('serviceAccountName') or 'default'), 'can_assume', {'via': 'pod_service_account'})
            if spec.get('nodeName'):
                node_asset = r.node('asset', f"k8s:node:{cluster}/{spec['nodeName']}", {'provider': 'kubernetes', 'type': 'node', 'name': spec['nodeName'], 'cluster': cluster},
                                    label=f"node/{spec['nodeName']}", criticality='high')
                r.edge(node_asset, node, 'runs')
            if flags['privileged'] or flags['host_pid'] or flags['host_network']:
                counts['privileged_workloads'] += 1
                r.event(source, f'k8s:{cluster}:privileged:Pod:{ns}/{name}', f'Pod {ns}/{name} runs with elevated host access', 'high' if flags['privileged'] else 'medium', 'k8s',
                        entity=node.key, action='privileged_workload', metadata={'cluster': cluster, 'namespace': ns, **_flag_meta(flags)})

        for svc in raw.get('services', []) or []:
            meta = svc.get('metadata') or {}
            ns, name = meta.get('namespace', 'default'), meta.get('name', '')
            if not in_scope(ns):
                continue
            spec = svc.get('spec') or {}
            stype = spec.get('type', 'ClusterIP')
            counts['services'] += 1
            if stype not in ('LoadBalancer', 'NodePort'):
                continue
            ports = [f"{p.get('port')}/{p.get('protocol', 'TCP')}" + (f"->np{p.get('nodePort')}" if p.get('nodePort') else '') for p in spec.get('ports') or []]
            ingress = [i.get('ip') or i.get('hostname') for i in ((svc.get('status') or {}).get('loadBalancer') or {}).get('ingress') or []]
            internal = any('internal' in k and str(v).lower() == 'true' for k, v in (meta.get('annotations') or {}).items())
            exposure = r.node('exposure', f'k8s:exposure:svc:{cluster}/{ns}/{name}', {'type': 'exposed_service', 'service_type': stype, 'ports': ports, 'ingress': ingress,
                                                                                   'internal_lb': internal, 'namespace': ns},
                              label=f'{stype} {ns}/{name} {" ".join(ports)}', criticality='medium' if internal else 'high')
            selector = spec.get('selector') or {}
            matched = False
            for (wkind, wns, wname), wnode in workload_nodes.items():
                if wns != ns or not selector:
                    continue
                labels = wnode.props.get('pod_labels') or {}
                if all(labels.get(k) == v for k, v in selector.items()):
                    r.edge(wnode, exposure, 'exposes', {'service': name})
                    matched = True
            if not matched:
                r.edge(ns_node(ns), exposure, 'exposes', {'service': name})

        for secret in raw.get('secrets', []) or []:
            meta = secret.get('metadata') or {}
            ns, name = meta.get('namespace', 'default'), meta.get('name', '')
            if not in_scope(ns):
                continue
            stype = secret.get('type', 'Opaque')
            if stype == 'kubernetes.io/service-account-token' or name.startswith('default-token-'):
                continue
            counts['secrets'] += 1
            node = r.node('secret', f'k8s:secret:{cluster}/{ns}/{name}', {'provider': 'kubernetes', 'type': stype, 'namespace': ns, 'name': name,
                                                                          'keys': sorted((secret.get('keys') or [])[:20])}, label=f'secret/{ns}/{name}',
                          criticality='high' if stype in ('kubernetes.io/tls', 'kubernetes.io/dockerconfigjson', 'kubernetes.io/basic-auth', 'kubernetes.io/ssh-auth') else 'medium')
            r.edge(ns_node(ns), node, 'owns')
        r.stats.update(counts)
        r.stats['cluster'] = cluster
        return r.finalize()


def _flag_meta(flags: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in flags.items() if k not in ('images', 'pod_labels')}


def _pod_flags(spec: dict[str, Any]) -> dict[str, Any]:
    pod_sc = spec.get('securityContext') or {}
    containers = list(spec.get('containers') or []) + list(spec.get('initContainers') or [])
    privileged = run_as_root = allow_escalation = host_path = False
    images: list[str] = []
    for c in containers:
        sc = c.get('securityContext') or {}
        images.append(c.get('image', ''))
        privileged = privileged or bool(sc.get('privileged'))
        allow_escalation = allow_escalation or sc.get('allowPrivilegeEscalation', True) is not False and bool(sc.get('privileged') or (sc.get('capabilities') or {}).get('add'))
        run_as_non_root = sc.get('runAsNonRoot', pod_sc.get('runAsNonRoot'))
        run_as_user = sc.get('runAsUser', pod_sc.get('runAsUser'))
        if run_as_user == 0 or (not run_as_non_root and run_as_user is None):
            run_as_root = True
    for vol in spec.get('volumes') or []:
        if vol.get('hostPath'):
            host_path = True
    labels = (spec.get('_labels') or {})
    return {'privileged': privileged, 'host_pid': bool(spec.get('hostPID')), 'host_network': bool(spec.get('hostNetwork')), 'host_ipc': bool(spec.get('hostIPC')),
            'run_as_root': run_as_root, 'allow_privilege_escalation': allow_escalation, 'host_path': host_path, 'service_account': spec.get('serviceAccountName') or 'default',
            'automount_token': spec.get('automountServiceAccountToken', True) is not False, 'images': images[:10], 'pod_labels': labels}


# ---------------------------------------------------------------- fetch


def _api_clients(config: dict[str, Any]) -> dict[str, Any]:
    """Return {'core','apps','rbac','version','cluster'} clients; tests monkeypatch this."""
    from kubernetes import client, config as kube_config  # lazy

    mode = config.get('mode') or 'kubeconfig'
    api_client = None
    cluster = config.get('cluster_name') or ''
    if mode == 'in_cluster':
        kube_config.load_incluster_config()
        cluster = cluster or 'in-cluster'
    elif mode == 'token':
        configuration = client.Configuration()
        configuration.host = config['api_url']
        configuration.api_key = {'authorization': f"Bearer {config['token']}"}
        configuration.verify_ssl = config.get('verify_ssl', True)
        if config.get('ca_cert_path'):
            configuration.ssl_ca_cert = config['ca_cert_path']
        api_client = client.ApiClient(configuration)
        cluster = cluster or config['api_url'].split('//', 1)[-1].split('/', 1)[0]
    elif config.get('kubeconfig'):
        import yaml  # lazy; PyYAML is a core dependency

        doc = yaml.safe_load(config['kubeconfig'])
        api_client = kube_config.new_client_from_config_dict(doc, context=config.get('context'))
        cluster = cluster or config.get('context') or doc.get('current-context') or 'kubeconfig'
    else:
        kube_config.load_kube_config(config_file=config.get('kubeconfig_path'), context=config.get('context'))
        cluster = cluster or config.get('context') or 'kubeconfig'
    return {'core': client.CoreV1Api(api_client), 'apps': client.AppsV1Api(api_client), 'rbac': client.RbacAuthorizationV1Api(api_client),
            'version': client.VersionApi(api_client), 'serializer': client.ApiClient(), 'cluster': cluster}


def _fetch(config: dict[str, Any], logger: logging.Logger) -> dict[str, Any]:
    warnings: list[str] = []
    apis = _api_clients(config)
    serializer = apis.get('serializer')

    def dump(obj: Any) -> Any:
        if serializer is not None and hasattr(serializer, 'sanitize_for_serialization'):
            return serializer.sanitize_for_serialization(obj)
        return jsonable(obj)

    def guarded(label: str, fn, default):
        try:
            return fn()
        except Exception as exc:
            warnings.append(f'{label}: {type(exc).__name__}')
            logger.warning('kubernetes collector: %s failed: %s', label, type(exc).__name__)
            return default

    def items(label: str, fn) -> list[Any]:
        result = guarded(label, fn, None)
        seq = (result.get('items') if isinstance(result, dict) else getattr(result, 'items', None)) or []
        return [dump(i) for i in seq]

    core, apps, rbac = apis['core'], apis['apps'], apis['rbac']
    raw: dict[str, Any] = {'cluster': apis.get('cluster') or 'default', 'namespaces_filter': config.get('namespaces') or [], 'warnings': warnings}
    version = guarded('version.get_code', lambda: dump(apis['version'].get_code()), {}) if apis.get('version') else {}
    raw['version'] = version.get('gitVersion') if isinstance(version, dict) else None
    raw['namespaces'] = items('list_namespace', lambda: core.list_namespace())
    raw['pods'] = items('list_pod_for_all_namespaces', lambda: core.list_pod_for_all_namespaces())
    raw['service_accounts'] = items('list_service_account_for_all_namespaces', lambda: core.list_service_account_for_all_namespaces())
    raw['services'] = items('list_service_for_all_namespaces', lambda: core.list_service_for_all_namespaces())
    raw['deployments'] = items('list_deployment_for_all_namespaces', lambda: apps.list_deployment_for_all_namespaces())
    raw['daemonsets'] = items('list_daemon_set_for_all_namespaces', lambda: apps.list_daemon_set_for_all_namespaces())
    raw['statefulsets'] = items('list_stateful_set_for_all_namespaces', lambda: apps.list_stateful_set_for_all_namespaces())
    raw['replicasets'] = [{'metadata': {k: v for k, v in (rs.get('metadata') or {}).items() if k in ('name', 'namespace', 'ownerReferences')}}
                          for rs in items('list_replica_set_for_all_namespaces', lambda: apps.list_replica_set_for_all_namespaces())]
    raw['cluster_role_bindings'] = items('list_cluster_role_binding', lambda: rbac.list_cluster_role_binding())
    raw['secrets'] = []
    if config.get('include_secrets', True):
        for secret in items('list_secret_for_all_namespaces', lambda: core.list_secret_for_all_namespaces()):
            meta = secret.get('metadata') or {}
            # Keep metadata only. Values never leave this function.
            raw['secrets'].append({'metadata': {'name': meta.get('name'), 'namespace': meta.get('namespace')}, 'type': secret.get('type'),
                                   'keys': sorted((secret.get('data') or {}).keys())})
    # carry pod template labels so services can be matched to workloads
    for key in ('deployments', 'daemonsets', 'statefulsets'):
        for obj in raw[key]:
            template = ((obj.get('spec') or {}).get('template') or {})
            if template.get('spec') is not None:
                template['spec']['_labels'] = (template.get('metadata') or {}).get('labels') or {}
    raw['namespaces'] = [ns for ns in raw['namespaces']]
    return jsonable(raw)


registry.register(KubernetesCollector())
