resource "azurerm_container_app_environment" "this" {
  name                           = "${local.prefix}-cae"
  location                       = azurerm_resource_group.this.location
  resource_group_name            = azurerm_resource_group.this.name
  log_analytics_workspace_id     = azurerm_log_analytics_workspace.this.id
  infrastructure_subnet_id       = azurerm_subnet.apps.id
  internal_load_balancer_enabled = true # only Front Door (via private link) reaches the apps
  zone_redundancy_enabled        = true

  workload_profile {
    name                  = "Consumption"
    workload_profile_type = "Consumption"
  }

  tags = local.tags
}

locals {
  env_list = [for k, v in local.common_environment : { name = k, value = v }]
  # Container App secret references: name must be lowercase alphanumeric with dashes.
  kv_secrets = merge(
    { for name, s in azurerm_key_vault_secret.app : name => s.versionless_id },
    { for name, s in azurerm_key_vault_secret.external : name => s.versionless_id },
  )
  secret_env_list = concat(
    [for name, env in local.secret_env : { name = env, secret_name = name }],
    [
      { name = "OIDC_CLIENT_SECRET", secret_name = "oidc-client-secret" },
      { name = "ANTHROPIC_API_KEY", secret_name = "anthropic-api-key" },
      { name = "OPENAI_API_KEY", secret_name = "openai-api-key" },
    ],
  )
}

resource "azurerm_container_app" "api" {
  name                         = "${local.prefix}-api"
  container_app_environment_id = azurerm_container_app_environment.this.id
  resource_group_name          = azurerm_resource_group.this.name
  revision_mode                = "Single"
  workload_profile_name        = "Consumption"
  tags                         = local.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.app.id]
  }

  dynamic "secret" {
    for_each = local.kv_secrets
    content {
      name                = secret.key
      key_vault_secret_id = secret.value
      identity            = azurerm_user_assigned_identity.app.id
    }
  }

  ingress {
    external_enabled = true # external to the environment; the environment itself is internal-only
    target_port      = 8080
    transport        = "http"
    traffic_weight {
      latest_revision = true
      percentage      = 100
    }
  }

  template {
    min_replicas = var.api_min_replicas
    max_replicas = var.api_max_replicas

    container {
      name   = "api"
      image  = var.image
      cpu    = var.api_cpu
      memory = var.api_memory
      args   = ["api"]

      dynamic "env" {
        for_each = concat(local.env_list, [
          { name = "RUN_MIGRATIONS", value = "true" },
          { name = "WORKERS_INPROCESS", value = "false" },
          { name = "APPLICATIONINSIGHTS_CONNECTION_STRING", value = azurerm_application_insights.this.connection_string },
        ])
        content {
          name  = env.value.name
          value = env.value.value
        }
      }
      dynamic "env" {
        for_each = local.secret_env_list
        content {
          name        = env.value.name
          secret_name = env.value.secret_name
        }
      }

      startup_probe {
        transport               = "HTTP"
        path                    = "/health"
        port                    = 8080
        interval_seconds        = 5
        failure_count_threshold = 24
      }
      liveness_probe {
        transport        = "HTTP"
        path             = "/health"
        port             = 8080
        interval_seconds = 20
      }
      readiness_probe {
        transport        = "HTTP"
        path             = "/ready"
        port             = 8080
        interval_seconds = 10
      }
    }

    http_scale_rule {
      name                = "http"
      concurrent_requests = "50"
    }
  }

  depends_on = [azurerm_role_assignment.app_secrets]
}

resource "azurerm_container_app" "worker" {
  name                         = "${local.prefix}-worker"
  container_app_environment_id = azurerm_container_app_environment.this.id
  resource_group_name          = azurerm_resource_group.this.name
  revision_mode                = "Single"
  workload_profile_name        = "Consumption"
  tags                         = local.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.app.id]
  }

  dynamic "secret" {
    for_each = local.kv_secrets
    content {
      name                = secret.key
      key_vault_secret_id = secret.value
      identity            = azurerm_user_assigned_identity.app.id
    }
  }

  template {
    min_replicas = var.worker_replicas
    max_replicas = var.worker_replicas

    container {
      name   = "worker"
      image  = var.image
      cpu    = var.worker_cpu
      memory = var.worker_memory
      args   = ["worker"]

      dynamic "env" {
        for_each = concat(local.env_list, [
          { name = "RUN_MIGRATIONS", value = "false" },
          { name = "WORKERS_INPROCESS", value = "false" },
          { name = "WORKER_CONCURRENCY", value = "4" },
        ])
        content {
          name  = env.value.name
          value = env.value.value
        }
      }
      dynamic "env" {
        for_each = local.secret_env_list
        content {
          name        = env.value.name
          secret_name = env.value.secret_name
        }
      }
    }
  }

  depends_on = [azurerm_role_assignment.app_secrets]
}
