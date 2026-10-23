# Audit sink: app/core/audit.py AzureImmutableBlobSink writes one blob per entry with
# overwrite=False. A time-based immutability policy on the container makes those blobs WORM
# for audit_retention_days. Set lock_audit_policy=true once you are sure about the period:
# a locked policy can be extended but never shortened or removed.

resource "azurerm_storage_account" "audit" {
  name                            = "${local.short}audit"
  resource_group_name             = azurerm_resource_group.this.name
  location                        = azurerm_resource_group.this.location
  account_tier                    = "Standard"
  account_replication_type        = "GZRS"
  account_kind                    = "StorageV2"
  min_tls_version                 = "TLS1_2"
  https_traffic_only_enabled      = true
  allow_nested_items_to_be_public = false
  shared_access_key_enabled       = true # the sink uses a connection string; switch to identity when the app supports it
  public_network_access_enabled   = false

  blob_properties {
    versioning_enabled = true
    delete_retention_policy {
      days = 30
    }
    container_delete_retention_policy {
      days = 30
    }
  }

  network_rules {
    default_action             = "Deny"
    bypass                     = ["AzureServices"]
    virtual_network_subnet_ids = [azurerm_subnet.data.id]
  }

  tags = local.tags
}

resource "azurerm_storage_container" "audit" {
  name                  = "sentinel-audit"
  storage_account_id    = azurerm_storage_account.audit.id
  container_access_type = "private"
}

resource "azurerm_storage_container_immutability_policy" "audit" {
  storage_container_resource_manager_id = azurerm_storage_container.audit.id
  immutability_period_in_days           = var.audit_retention_days
  protected_append_writes_all_enabled   = false
  locked                                = var.lock_audit_policy
}

resource "azurerm_private_dns_zone" "blob" {
  name                = "privatelink.blob.core.windows.net"
  resource_group_name = azurerm_resource_group.this.name
  tags                = local.tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "blob" {
  name                  = "${local.prefix}-blob"
  resource_group_name   = azurerm_resource_group.this.name
  private_dns_zone_name = azurerm_private_dns_zone.blob.name
  virtual_network_id    = azurerm_virtual_network.this.id
}

resource "azurerm_private_endpoint" "blob" {
  name                = "${local.prefix}-blob-pe"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  subnet_id           = azurerm_subnet.private_endpoints.id

  private_service_connection {
    name                           = "blob"
    private_connection_resource_id = azurerm_storage_account.audit.id
    subresource_names              = ["blob"]
    is_manual_connection           = false
  }

  private_dns_zone_group {
    name                 = "blob"
    private_dns_zone_ids = [azurerm_private_dns_zone.blob.id]
  }

  tags = local.tags
}
