locals {
  prefix = "${var.name}-${var.environment}"
  tags = merge({
    Project     = "sentinel"
    Environment = var.environment
    ManagedBy   = "terraform"
  }, var.tags)

  # Non-secret environment shared by the API and worker tasks. Secrets are injected from
  # Secrets Manager (see ecs.tf) and never appear in the task definition in plain text.
  common_environment = merge({
    APP_ENV                  = var.environment
    BASE_URL                 = "https://${var.domain_name}"
    COOKIE_SECURE            = "true"
    DB_AUTO_CREATE           = "false"
    LOG_JSON                 = "true"
    METRICS_ENABLED          = "true"
    SCAN_ROOT                = "/app/targets"
    AUDIT_S3_BUCKET          = aws_s3_bucket.audit.id
    AUDIT_S3_PREFIX          = "sentinel-audit/"
    ACTIONS_KILL_SWITCH      = "false"
    ACTIONS_AUTO_APPROVE_LOW = "false"
    FORWARDED_ALLOW_IPS      = "*" # the ALB is the only client of the task ENI (security group)
  }, var.extra_environment)
}

data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_caller_identity" "current" {}
