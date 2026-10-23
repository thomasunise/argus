locals {
  prefix = "${var.name}-${var.environment}"
  short  = substr(replace(local.prefix, "-", ""), 0, 20) # storage/key vault names: alphanumeric, <= 24
  tags = merge({
    Project     = "sentinel"
    Environment = var.environment
    ManagedBy   = "terraform"
  }, var.tags)

  common_environment = merge({
    APP_ENV                  = var.environment
    BASE_URL                 = "https://${var.domain_name}"
    COOKIE_SECURE            = "true"
    DB_AUTO_CREATE           = "false"
    LOG_JSON                 = "true"
    METRICS_ENABLED          = "true"
    SCAN_ROOT                = "/app/targets"
    AUDIT_AZURE_CONTAINER    = azurerm_storage_container.audit.name
    ACTIONS_KILL_SWITCH      = "false"
    ACTIONS_AUTO_APPROVE_LOW = "false"
    FORWARDED_ALLOW_IPS      = "*" # Container Apps ingress is the only client
  }, var.extra_environment)
}

data "azurerm_client_config" "current" {}

resource "azurerm_resource_group" "this" {
  name     = "${local.prefix}-rg"
  location = var.location
  tags     = local.tags
}

# ---------------------------------------------------------------- network

resource "azurerm_virtual_network" "this" {
  name                = "${local.prefix}-vnet"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  address_space       = [var.vnet_cidr]
  tags                = local.tags
}

# Container Apps environment subnet (workload profiles need /27 or larger; /23 recommended).
resource "azurerm_subnet" "apps" {
  name                 = "apps"
  resource_group_name  = azurerm_resource_group.this.name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = [cidrsubnet(var.vnet_cidr, 7, 0)]
  delegation {
    name = "containerapps"
    service_delegation {
      name    = "Microsoft.App/environments"
      actions = ["Microsoft.Network/virtualNetworks/subnets/join/action"]
    }
  }
}

resource "azurerm_subnet" "data" {
  name                 = "data"
  resource_group_name  = azurerm_resource_group.this.name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = [cidrsubnet(var.vnet_cidr, 8, 10)]
  service_endpoints    = ["Microsoft.Storage", "Microsoft.KeyVault"]
  delegation {
    name = "postgres"
    service_delegation {
      name    = "Microsoft.DBforPostgreSQL/flexibleServers"
      actions = ["Microsoft.Network/virtualNetworks/subnets/join/action"]
    }
  }
}

resource "azurerm_subnet" "private_endpoints" {
  name                 = "private-endpoints"
  resource_group_name  = azurerm_resource_group.this.name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = [cidrsubnet(var.vnet_cidr, 8, 11)]
}

# ---------------------------------------------------------------- monitoring

resource "azurerm_log_analytics_workspace" "this" {
  name                = "${local.prefix}-law"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  sku                 = "PerGB2018"
  retention_in_days   = var.log_retention_days
  tags                = local.tags
}

resource "azurerm_application_insights" "this" {
  name                = "${local.prefix}-appi"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  workspace_id        = azurerm_log_analytics_workspace.this.id
  application_type    = "web"
  tags                = local.tags
}

# ---------------------------------------------------------------- identity

resource "azurerm_user_assigned_identity" "app" {
  name                = "${local.prefix}-app"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  tags                = local.tags
}
