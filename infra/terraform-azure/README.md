# Argus on Azure (Terraform)

A production-shaped skeleton parallel to `infra/terraform` (AWS): Azure Container Apps (API +
worker), Azure Database for PostgreSQL Flexible Server, Azure Cache for Redis, an immutable
blob container for the audit mirror, Key Vault for secrets, and Azure Front Door Premium with
a WAF policy. Review every file before `apply`; several choices (immutability lock, Front
Door origin wiring, Key Vault network rules) are deliberately left for you to decide.

## What it builds

| Component | Resource | Notes |
|---|---|---|
| Network | VNet with delegated subnets for Container Apps and Postgres, a private-endpoint subnet, private DNS zones | Postgres, Redis and Storage have no public endpoints |
| Compute | Container Apps environment (internal, zone redundant), `api` app with HTTP scaling, `worker` app with fixed replicas | Same image; `args` selects the role; user-assigned identity reads Key Vault |
| Database | PostgreSQL Flexible Server 16, zone-redundant HA, `require_secure_transport=on`, `prevent_destroy` | `DATABASE_URL` assembled into Key Vault with `sslmode=require` |
| Queue | Azure Cache for Redis, TLS only, `noeviction`, private endpoint | `REDIS_URL` uses `rediss://` |
| Audit WORM | GZRS storage account, versioning, container with a time-based immutability policy | `lock_audit_policy=true` makes it irreversible, which is the point of WORM |
| Secrets | Key Vault (RBAC, purge protection) with generated secrets and placeholders for OIDC / model keys | Container Apps reference Key Vault secrets via the app identity |
| Edge | Front Door Premium endpoint, custom domain with managed certificate, HTTPS redirect, HSTS rule, `/metrics` blocked, WAF (rate limit + DRS 2.1 + bot manager) in Prevention mode | |
| Observability | Log Analytics workspace (Container Apps console/system logs), Application Insights connection string exported to the API | Set `OTEL_EXPORTER_OTLP_ENDPOINT` to an OTLP collector if you prefer OpenTelemetry |

## Usage

```bash
cd infra/terraform-azure
az login
cp terraform.tfvars.example terraform.tfvars   # edit image digest and domain
terraform init
terraform plan -out plan.tfplan
terraform apply plan.tfplan
```

Then:

1. Create DNS: CNAME `domain_name` to `frontdoor_endpoint_hostname` and the `_dnsauth` TXT
   record with `frontdoor_domain_validation_token`.
2. Populate external secrets (never in Terraform):
   `az keyvault secret set --vault-name <key_vault_name> --name oidc-client-secret --value '...'`
3. Read the bootstrap owner password:
   `az keyvault secret show --vault-name <key_vault_name> --name admin-password --query value -o tsv`
4. Follow the production checklist in `docs/DEPLOYMENT.md`.

## Decisions you must make

- **Front Door to an internal environment**: with `internal_load_balancer_enabled = true` the
  Container App FQDN resolves only inside the VNet. Either add a Front Door private link
  origin (Premium; requires approval on the environment) or set the environment external and
  restrict the app's ingress to Front Door by validating the `X-Azure-FDID` header at an
  edge rule. This skeleton leaves the origin as the app FQDN so the HCL stays provider-portable.
- **Key Vault network access**: public access is left on so Terraform can write secrets from
  anywhere. Add `network_acls` IP rules or a private endpoint and run Terraform from inside.
- **Immutability lock**: `azurerm_storage_container_immutability_policy.locked` is false by
  default so a mis-sized period can be corrected. Lock it once confirmed.
- **Audit sink identity**: `AzureImmutableBlobSink` uses a connection string today
  (`AUDIT_AZURE_CONNECTION_STRING`). The storage account therefore keeps shared keys enabled.
- **Testing tools**: the image does not bundle nuclei, zap, prowler, semgrep or trivy.

## Validation

```bash
terraform fmt -check -recursive
terraform init -backend=false && terraform validate
```

CI runs `terraform fmt -check`. No credentials are embedded; the azurerm provider uses the
ambient Azure credential chain.
