# Scanner execution isolation

Argus testing scopes enforce permission, asset, tier, time window and request rate at request time and execution time. **That is not a substitute for operating-system/network egress enforcement.**

## Kubernetes

The Helm chart now renders separate API and worker egress NetworkPolicies. The default worker policy allows private PostgreSQL (5432) and Redis (6379), plus DNS, only. **It does not allow arbitrary HTTPS to the internet.**

Configure `networkPolicy.workerEgress` with the specific CIDRs and ports required by your collectors, provider APIs and authorized scan targets. Remove all broad `0.0.0.0/0` allowances; network policies are additive, so an overlapping permissive policy defeats isolation. Use a CNI that actually enforces Kubernetes NetworkPolicy egress. Confirm policies with a negative connectivity test to 169.254.169.254, 127.0.0.1 (host network), an unrelated RFC1918 host and an arbitrary public destination.

You can select a separate scanner-tool image using `worker.image` (pin it by digest). `sandbox/offensive-tools.Dockerfile` provides SHA-verified scanner binaries, but image pinning and tool hashes must still be reviewed during releases.

The Kubernetes worker is **currently a shared job worker**, not a per-scope sandbox. Its allowlist is therefore an environment-wide upper bound. Do not add unrelated customer networks to the same worker egress policy. Per-run /32 egress is already supported for exploit PoC jobs created by the sandbox executor. Other active network scanners require separate executor integration before they can claim equivalent per-scope network isolation.

## Local or Compose

Docker Compose's worker does **not** provide per-scope network isolation. Limit authorized active scans to a dedicated test environment with firewall egress rules. For untrusted or multi-tenant scanning, use the sandbox executor and per-run NetworkPolicy. Until an adapter can use that executor, do not enable it in environments requiring hard per-scope isolation.

## Subprocess safety

`run_tool` now drains stdout and stderr with fixed 2 MiB caps, does not invoke a shell, sanitizes its environment, and terminates the process group on timeout or cancellation. These protections prevent stale child processes and unbounded output memory use. They do not stop a process from making network connections prior to termination.

## Operator acceptance checks

1. Render the Helm chart and verify **the worker pod does not select the general API egress policy**.
2. Confirm the worker cannot reach cloud instance metadata and unrelated public/private addresses.
3. Test a permitted target and a rejected target under the same scope.
4. Cancel a long-running scanner and confirm no descendant processes or network sessions remain.
5. Ensure DB/Redis/provider service endpoints remain reachable through narrowly scoped allowlists.
6. Confirm sandbox-executor service account and namespace cannot create privileged pods or overly broad egress rules.

Independent validation of deployment-specific CNI, credentials and allowed CIDRs is mandatory before claiming per-scope containment.
