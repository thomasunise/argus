resource "random_password" "session_secret" {
  length  = 64
  special = false
}

resource "random_password" "admin_password" {
  length  = 32
  special = false
}

resource "random_password" "ingest_api_key" {
  length  = 48
  special = false
}

resource "random_password" "audit_signing_key" {
  length  = 64
  special = false
}

# Encryption at rest for stored secrets (TOTP seeds, integration credentials); required in production.
resource "random_password" "data_encryption_key" {
  length  = 64
  special = false
}

resource "azurerm_key_vault" "this" {
  name                          = "${local.short}kv"
  location                      = azurerm_resource_group.this.location
  resource_group_name           = azurerm_resource_group.this.name
  tenant_id                     = data.azurerm_client_config.current.tenant_id
  sku_name                      = "standard"
  rbac_authorization_enabled    = true
  purge_protection_enabled      = true
  soft_delete_retention_days    = 30
  public_network_access_enabled = true # needed for Terraform to write secrets; restrict with network_acls / private endpoint in your environment

  network_acls {
    default_action = "Allow"
    bypass         = "AzureServices"
  }

  tags = local.tags
}

# The deploying principal must be able to write secrets.
resource "azurerm_role_assignment" "deployer_secrets" {
  scope                = azurerm_key_vault.this.id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = data.azurerm_client_config.current.object_id
}

# The app identity may only read.
resource "azurerm_role_assignment" "app_secrets" {
  scope                = azurerm_key_vault.this.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.app.principal_id
}

locals {
  secret_values = {
    session-secret                = random_password.session_secret.result
    admin-password                = random_password.admin_password.result
    ingest-api-key                = random_password.ingest_api_key.result
    audit-signing-key             = random_password.audit_signing_key.result
    data-encryption-key           = random_password.data_encryption_key.result
    database-url                  = "postgresql+psycopg://sentinel:${random_password.db.result}@${azurerm_postgresql_flexible_server.this.fqdn}:5432/sentinel?sslmode=require"
    redis-url                     = "rediss://:${azurerm_redis_cache.this.primary_access_key}@${azurerm_redis_cache.this.hostname}:${azurerm_redis_cache.this.ssl_port}/0"
    audit-azure-connection-string = azurerm_storage_account.audit.primary_connection_string
  }
  # Key Vault secret name -> environment variable name
  secret_env = {
    session-secret                = "SESSION_SECRET"
    admin-password                = "ADMIN_PASSWORD"
    ingest-api-key                = "INGEST_API_KEY"
    audit-signing-key             = "AUDIT_SIGNING_KEY"
    data-encryption-key           = "DATA_ENCRYPTION_KEY"
    database-url                  = "DATABASE_URL"
    redis-url                     = "REDIS_URL"
    audit-azure-connection-string = "AUDIT_AZURE_CONNECTION_STRING"
  }
}

resource "azurerm_key_vault_secret" "app" {
  for_each     = local.secret_values
  name         = each.key
  value        = each.value
  key_vault_id = azurerm_key_vault.this.id
  content_type = "text/plain"
  depends_on   = [azurerm_role_assignment.deployer_secrets]
}

# Secrets you set out of band (empty placeholders so the Container App references resolve):
#   az keyvault secret set --vault-name <kv> --name oidc-client-secret --value '...'
resource "azurerm_key_vault_secret" "external" {
  for_each     = toset(["oidc-client-secret", "anthropic-api-key", "openai-api-key"])
  name         = each.key
  value        = "unset"
  key_vault_id = azurerm_key_vault.this.id
  content_type = "text/plain"
  depends_on   = [azurerm_role_assignment.deployer_secrets]

  lifecycle {
    ignore_changes = [value]
  }
}
