# Azure Front Door Premium in front of the Container App, with a WAF policy (managed rules
# + rate limit). Premium is required for private link origins; this skeleton uses the
# Container App FQDN as origin with the environment internal, so you must also create the
# private link approval or switch internal_load_balancer_enabled to false and restrict
# ingress by Front Door id header. See README.md.

resource "azurerm_cdn_frontdoor_profile" "this" {
  name                = "${local.prefix}-afd"
  resource_group_name = azurerm_resource_group.this.name
  sku_name            = "Premium_AzureFrontDoor"
  tags                = local.tags
}

resource "azurerm_cdn_frontdoor_endpoint" "this" {
  name                     = local.prefix
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.this.id
  tags                     = local.tags
}

resource "azurerm_cdn_frontdoor_origin_group" "api" {
  name                     = "api"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.this.id
  session_affinity_enabled = false

  health_probe {
    interval_in_seconds = 30
    path                = "/ready"
    protocol            = "Https"
    request_type        = "GET"
  }

  load_balancing {
    sample_size                 = 4
    successful_samples_required = 3
  }
}

resource "azurerm_cdn_frontdoor_origin" "api" {
  name                           = "containerapp"
  cdn_frontdoor_origin_group_id  = azurerm_cdn_frontdoor_origin_group.api.id
  enabled                        = true
  host_name                      = azurerm_container_app.api.ingress[0].fqdn
  origin_host_header             = azurerm_container_app.api.ingress[0].fqdn
  http_port                      = 80
  https_port                     = 443
  priority                       = 1
  weight                         = 1000
  certificate_name_check_enabled = true
}

resource "azurerm_cdn_frontdoor_custom_domain" "this" {
  name                     = replace(var.domain_name, ".", "-")
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.this.id
  host_name                = var.domain_name
  tls {
    certificate_type = "ManagedCertificate"
    minimum_version  = "TLS12"
  }
}

resource "azurerm_cdn_frontdoor_rule_set" "security" {
  name                     = "security"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.this.id
}

# Block /metrics at the edge; add HSTS.
resource "azurerm_cdn_frontdoor_rule" "block_metrics" {
  name                      = "blockmetrics"
  cdn_frontdoor_rule_set_id = azurerm_cdn_frontdoor_rule_set.security.id
  order                     = 1
  behavior_on_match         = "Stop"

  conditions {
    url_path_condition {
      operator     = "Equal"
      match_values = ["/metrics"]
    }
  }
  actions {
    url_redirect_action {
      redirect_type        = "Found"
      destination_hostname = var.domain_name
      destination_path     = "/"
    }
  }

  depends_on = [azurerm_cdn_frontdoor_origin_group.api, azurerm_cdn_frontdoor_origin.api]
}

resource "azurerm_cdn_frontdoor_rule" "hsts" {
  name                      = "hsts"
  cdn_frontdoor_rule_set_id = azurerm_cdn_frontdoor_rule_set.security.id
  order                     = 2
  behavior_on_match         = "Continue"

  actions {
    response_header_action {
      header_action = "Overwrite"
      header_name   = "Strict-Transport-Security"
      value         = "max-age=63072000; includeSubDomains; preload"
    }
  }

  depends_on = [azurerm_cdn_frontdoor_origin_group.api, azurerm_cdn_frontdoor_origin.api]
}

resource "azurerm_cdn_frontdoor_route" "api" {
  name                            = "api"
  cdn_frontdoor_endpoint_id       = azurerm_cdn_frontdoor_endpoint.this.id
  cdn_frontdoor_origin_group_id   = azurerm_cdn_frontdoor_origin_group.api.id
  cdn_frontdoor_origin_ids        = [azurerm_cdn_frontdoor_origin.api.id]
  cdn_frontdoor_rule_set_ids      = [azurerm_cdn_frontdoor_rule_set.security.id]
  cdn_frontdoor_custom_domain_ids = [azurerm_cdn_frontdoor_custom_domain.this.id]
  supported_protocols             = ["Http", "Https"]
  patterns_to_match               = ["/*"]
  forwarding_protocol             = "HttpsOnly"
  https_redirect_enabled          = true
  link_to_default_domain          = false
}

resource "azurerm_cdn_frontdoor_custom_domain_association" "this" {
  cdn_frontdoor_custom_domain_id = azurerm_cdn_frontdoor_custom_domain.this.id
  cdn_frontdoor_route_ids        = [azurerm_cdn_frontdoor_route.api.id]
}

# ---------------------------------------------------------------- WAF

resource "azurerm_cdn_frontdoor_firewall_policy" "this" {
  name                              = replace("${local.prefix}waf", "-", "")
  resource_group_name               = azurerm_resource_group.this.name
  sku_name                          = azurerm_cdn_frontdoor_profile.this.sku_name
  enabled                           = true
  mode                              = "Prevention"
  request_body_check_enabled        = true
  custom_block_response_status_code = 429
  tags                              = local.tags

  custom_rule {
    name                           = "ratelimit"
    enabled                        = true
    priority                       = 1
    type                           = "RateLimitRule"
    rate_limit_duration_in_minutes = 1
    rate_limit_threshold           = var.waf_rate_limit
    action                         = "Block"
    match_condition {
      match_variable     = "RequestUri"
      operator           = "Contains"
      negation_condition = false
      match_values       = ["/"]
    }
  }

  managed_rule {
    type    = "Microsoft_DefaultRuleSet"
    version = "2.1"
    action  = "Block"
  }

  managed_rule {
    type    = "Microsoft_BotManagerRuleSet"
    version = "1.0"
    action  = "Block"
  }
}

resource "azurerm_cdn_frontdoor_security_policy" "this" {
  name                     = "security"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.this.id

  security_policies {
    firewall {
      cdn_frontdoor_firewall_policy_id = azurerm_cdn_frontdoor_firewall_policy.this.id
      association {
        domain {
          cdn_frontdoor_domain_id = azurerm_cdn_frontdoor_custom_domain.this.id
        }
        patterns_to_match = ["/*"]
      }
    }
  }
}
