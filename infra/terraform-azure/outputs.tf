output "resource_group" {
  value = azurerm_resource_group.this.name
}

output "base_url" {
  value = "https://${var.domain_name}"
}

output "frontdoor_endpoint_hostname" {
  description = "Create a CNAME from domain_name to this hostname, plus the _dnsauth TXT record Front Door shows for domain validation."
  value       = azurerm_cdn_frontdoor_endpoint.this.host_name
}

output "frontdoor_domain_validation_token" {
  value = azurerm_cdn_frontdoor_custom_domain.this.validation_token
}

output "container_app_api_fqdn" {
  value = azurerm_container_app.api.ingress[0].fqdn
}

output "container_app_names" {
  value = {
    api    = azurerm_container_app.api.name
    worker = azurerm_container_app.worker.name
  }
}

output "postgres_fqdn" {
  value = azurerm_postgresql_flexible_server.this.fqdn
}

output "redis_hostname" {
  value = azurerm_redis_cache.this.hostname
}

output "audit_storage_account" {
  value = azurerm_storage_account.audit.name
}

output "audit_container" {
  value = azurerm_storage_container.audit.name
}

output "key_vault_name" {
  description = "Read ADMIN_PASSWORD with: az keyvault secret show --vault-name <name> --name admin-password --query value -o tsv"
  value       = azurerm_key_vault.this.name
}

output "app_identity_client_id" {
  value = azurerm_user_assigned_identity.app.client_id
}

output "log_analytics_workspace_id" {
  value = azurerm_log_analytics_workspace.this.id
}
