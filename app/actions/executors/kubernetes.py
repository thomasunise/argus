"""Kubernetes executors (official `kubernetes` client, imported lazily). Credential:
ACTIONS_K8S_KUBECONFIG (path to a kubeconfig) and optional ACTIONS_K8S_CONTEXT.
Tests monkeypatch `_clients`."""
from __future__ import annotations

import hashlib
from types import SimpleNamespace

from ..catalog import ActionError, ActionType, DryRunResult, ExecContext, ExecResult, entities, register
from ._common import is_not_found, run_blocking

_DNS = {'type': 'string', 'minLength': 1, 'maxLength': 253, 'pattern': r'^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$'}
LABEL_KEY = 'sentinel.io/isolated'
MANAGED_BY = {'app.kubernetes.io/managed-by': 'sentinel'}


def _clients(ctx: ExecContext) -> SimpleNamespace:
    """Build API clients from the configured kubeconfig. Monkeypatched in tests."""
    from kubernetes import client, config  # lazy

    config.load_kube_config(config_file=ctx.require_credential('kubeconfig'), context=ctx.credential('context') or None)
    return SimpleNamespace(core=client.CoreV1Api(), apps=client.AppsV1Api(), networking=client.NetworkingV1Api())


async def _call(fn, *args, **kwargs):
    return await run_blocking(fn, *args, **kwargs)


async def _maybe(fn, *args, **kwargs):
    try:
        return await run_blocking(fn, *args, **kwargs)
    except ActionError as exc:
        if exc.__cause__ is not None and is_not_found(exc.__cause__):
            return None
        raise


def _attr(obj, *path, default=None):
    for part in path:
        if obj is None:
            return default
        obj = obj.get(part) if isinstance(obj, dict) else getattr(obj, part, None)
    return default if obj is None else obj


def _owner(pod) -> str:
    refs = _attr(pod, 'metadata', 'owner_references') or _attr(pod, 'metadata', 'ownerReferences') or []
    if not refs:
        return ''
    ref = refs[0]
    return f'{_attr(ref, "kind", default="")}/{_attr(ref, "name", default="")}'


def _policy_name(pod: str) -> str:
    name = f'sentinel-isolate-{pod}'
    if len(name) > 63:
        name = f'sentinel-isolate-{hashlib.sha256(pod.encode()).hexdigest()[:16]}'
    return name


# ---------------------------------------------------------------- isolate pod


@register
class IsolatePod(ActionType):
    name = 'kubernetes.network_policy.isolate_pod'
    description = 'Label a pod and create a deny-all NetworkPolicy selecting only that label (ingress and egress). Rollback deletes the policy and removes the label.'
    params_schema = {'properties': {'namespace': _DNS, 'pod': _DNS}, 'required': ['namespace', 'pod']}
    risk = 'high'
    reversible = True
    platforms = ['kubernetes']
    sdk = 'kubernetes'
    category = 'containment'

    @staticmethod
    def _plan(namespace: str, pod: str) -> dict:
        label_value = pod[:63]
        manifest = {'apiVersion': 'networking.k8s.io/v1', 'kind': 'NetworkPolicy',
                    'metadata': {'name': _policy_name(pod), 'namespace': namespace, 'labels': dict(MANAGED_BY)},
                    'spec': {'podSelector': {'matchLabels': {LABEL_KEY: label_value}}, 'policyTypes': ['Ingress', 'Egress']}}
        return {'policy_name': manifest['metadata']['name'], 'label_key': LABEL_KEY, 'label_value': label_value, 'manifest': manifest,
                'label_patch': {'metadata': {'labels': {LABEL_KEY: label_value}}}, 'blast_radius': entities(1, 'pod', [f'{namespace}/{pod}'])}

    async def dry_run(self, params: dict, ctx: ExecContext) -> DryRunResult:
        plan = self._plan(params['namespace'], params['pod'])
        k8s = _clients(ctx)
        pod = await _maybe(k8s.core.read_namespaced_pod, params['pod'], params['namespace'])
        if pod is None:
            return DryRunResult(ok=False, summary='pod not found', blast_radius=plan['blast_radius'])
        existing = await _maybe(k8s.networking.read_namespaced_network_policy, plan['policy_name'], params['namespace'])
        warnings = ['a Sentinel isolation policy already exists for this pod'] if existing is not None else []
        warnings.append('isolation requires a CNI that enforces NetworkPolicy (Calico, Cilium, etc.)')
        return DryRunResult(ok=True, summary=f'isolate pod {params["namespace"]}/{params["pod"]} with deny-all NetworkPolicy {plan["policy_name"]}',
                            blast_radius=dict(plan['blast_radius'], owner=_owner(pod)), warnings=warnings, details={'manifest': plan['manifest']})

    async def execute(self, params: dict, ctx: ExecContext) -> ExecResult:
        plan = self._plan(params['namespace'], params['pod'])
        k8s = _clients(ctx)
        pod = await _maybe(k8s.core.read_namespaced_pod, params['pod'], params['namespace'])
        if pod is None:
            raise ActionError('pod not found')
        previous = (_attr(pod, 'metadata', 'labels') or {}).get(LABEL_KEY)
        await _call(k8s.core.patch_namespaced_pod, params['pod'], params['namespace'], plan['label_patch'])
        existing = await _maybe(k8s.networking.read_namespaced_network_policy, plan['policy_name'], params['namespace'])
        if existing is None:
            await _call(k8s.networking.create_namespaced_network_policy, params['namespace'], plan['manifest'])
        return ExecResult(ok=True, summary=f'pod {params["namespace"]}/{params["pod"]} isolated by {plan["policy_name"]}',
                          rollback_payload={'namespace': params['namespace'], 'pod': params['pod'], 'policy_name': plan['policy_name'],
                                            'label_key': LABEL_KEY, 'previous_label': previous, 'created_policy': existing is None})

    async def rollback(self, payload: dict, ctx: ExecContext) -> ExecResult:
        k8s = _clients(ctx)
        if payload.get('created_policy', True):
            await _maybe(k8s.networking.delete_namespaced_network_policy, payload['policy_name'], payload['namespace'])
        patch = {'metadata': {'labels': {payload.get('label_key', LABEL_KEY): payload.get('previous_label')}}}
        await _maybe(k8s.core.patch_namespaced_pod, payload['pod'], payload['namespace'], patch)
        return ExecResult(ok=True, summary=f'isolation removed from {payload["namespace"]}/{payload["pod"]}')


# ---------------------------------------------------------------- scale to zero


@register
class ScaleToZero(ActionType):
    name = 'kubernetes.scale_to_zero'
    description = 'Scale a Deployment or StatefulSet to zero replicas (apps/v1 scale subresource). Rollback restores the previous replica count.'
    params_schema = {'properties': {'namespace': _DNS, 'kind': {'type': 'string', 'enum': ['deployment', 'statefulset']}, 'name': _DNS},
                     'required': ['namespace', 'kind', 'name']}
    risk = 'high'
    reversible = True
    platforms = ['kubernetes']
    sdk = 'kubernetes'
    category = 'containment'

    @staticmethod
    def _plan(params: dict, replicas: int | None = None) -> dict:
        kind = params['kind']
        read = 'read_namespaced_deployment' if kind == 'deployment' else 'read_namespaced_stateful_set'
        scale = 'patch_namespaced_deployment_scale' if kind == 'deployment' else 'patch_namespaced_stateful_set_scale'
        return {'read': read, 'scale': scale, 'body': {'spec': {'replicas': 0}},
                'blast_radius': entities(1, kind, [f'{params["namespace"]}/{params["name"]}'], replicas=replicas if replicas is not None else 0)}

    async def dry_run(self, params: dict, ctx: ExecContext) -> DryRunResult:
        plan = self._plan(params)
        workload = await _maybe(getattr(_clients(ctx).apps, plan['read']), params['name'], params['namespace'])
        if workload is None:
            return DryRunResult(ok=False, summary=f'{params["kind"]} not found', blast_radius=plan['blast_radius'])
        replicas = int(_attr(workload, 'spec', 'replicas', default=0) or 0)
        plan = self._plan(params, replicas)
        warnings = ['already at zero replicas'] if replicas == 0 else [f'{replicas} running pod(s) will be terminated']
        warnings.append('a HorizontalPodAutoscaler targeting this workload may scale it back up')
        return DryRunResult(ok=True, summary=f'scale {params["kind"]} {params["namespace"]}/{params["name"]} from {replicas} to 0', blast_radius=plan['blast_radius'],
                            warnings=warnings, details={'previous_replicas': replicas})

    async def execute(self, params: dict, ctx: ExecContext) -> ExecResult:
        plan = self._plan(params)
        k8s = _clients(ctx)
        workload = await _maybe(getattr(k8s.apps, plan['read']), params['name'], params['namespace'])
        if workload is None:
            raise ActionError(f'{params["kind"]} not found')
        replicas = int(_attr(workload, 'spec', 'replicas', default=0) or 0)
        await _call(getattr(k8s.apps, plan['scale']), params['name'], params['namespace'], plan['body'])
        return ExecResult(ok=True, summary=f'{params["kind"]} {params["namespace"]}/{params["name"]} scaled to 0 (was {replicas})',
                          rollback_payload={'namespace': params['namespace'], 'kind': params['kind'], 'name': params['name'], 'previous_replicas': replicas})

    async def rollback(self, payload: dict, ctx: ExecContext) -> ExecResult:
        plan = self._plan(payload)
        replicas = int(payload.get('previous_replicas', 1))
        await _call(getattr(_clients(ctx).apps, plan['scale']), payload['name'], payload['namespace'], {'spec': {'replicas': replicas}})
        return ExecResult(ok=True, summary=f'{payload["kind"]} {payload["namespace"]}/{payload["name"]} restored to {replicas} replicas')


# ---------------------------------------------------------------- delete pod


@register
class DeletePod(ActionType):
    name = 'kubernetes.delete_pod'
    description = 'Delete a pod (CoreV1 deleteNamespacedPod). Not reversible; a controller-owned pod is recreated, a bare pod is gone.'
    params_schema = {'properties': {'namespace': _DNS, 'pod': _DNS, 'grace_period_seconds': {'type': 'integer', 'minimum': 0, 'maximum': 3600, 'default': 30}},
                     'required': ['namespace', 'pod']}
    risk = 'high'
    reversible = False
    platforms = ['kubernetes']
    sdk = 'kubernetes'
    category = 'containment'

    @staticmethod
    def _plan(params: dict, owner: str = '') -> dict:
        warnings = [f'pod is owned by {owner} and will be recreated by its controller'] if owner else ['pod has no controller; deletion is permanent']
        return {'call': 'delete_namespaced_pod', 'args': (params['pod'], params['namespace']), 'kwargs': {'grace_period_seconds': int(params.get('grace_period_seconds', 30))},
                'warnings': warnings, 'blast_radius': entities(1, 'pod', [f'{params["namespace"]}/{params["pod"]}'], owner=owner)}

    async def dry_run(self, params: dict, ctx: ExecContext) -> DryRunResult:
        pod = await _maybe(_clients(ctx).core.read_namespaced_pod, params['pod'], params['namespace'])
        if pod is None:
            return DryRunResult(ok=False, summary='pod not found', blast_radius=entities(0, 'pod'))
        plan = self._plan(params, _owner(pod))
        return DryRunResult(ok=True, summary=f'delete pod {params["namespace"]}/{params["pod"]}', blast_radius=plan['blast_radius'], warnings=plan['warnings'])

    async def execute(self, params: dict, ctx: ExecContext) -> ExecResult:
        k8s = _clients(ctx)
        pod = await _maybe(k8s.core.read_namespaced_pod, params['pod'], params['namespace'])
        if pod is None:
            raise ActionError('pod not found')
        plan = self._plan(params, _owner(pod))
        await _call(k8s.core.delete_namespaced_pod, *plan['args'], **plan['kwargs'])
        return ExecResult(ok=True, summary=f'pod {params["namespace"]}/{params["pod"]} deleted', details={'owner': plan['blast_radius'].get('owner', '')})
