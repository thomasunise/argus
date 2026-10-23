# Application secrets. Terraform generates the random ones; it never prints them (they live
# in state, so protect the state backend). Rotation runbook: docs/RUNBOOKS.md.

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

locals {
  secret_values = {
    SESSION_SECRET    = random_password.session_secret.result
    ADMIN_PASSWORD    = random_password.admin_password.result
    INGEST_API_KEY    = random_password.ingest_api_key.result
    AUDIT_SIGNING_KEY = random_password.audit_signing_key.result
    DATABASE_URL      = "postgresql+psycopg://sentinel:${random_password.db.result}@${aws_db_instance.this.address}:5432/sentinel?sslmode=require"
    REDIS_URL         = "rediss://:${random_password.redis.result}@${aws_elasticache_replication_group.this.primary_endpoint_address}:6379/0"
  }
}

resource "aws_secretsmanager_secret" "app" {
  for_each                = local.secret_values
  name                    = "${local.prefix}/${each.key}"
  kms_key_id              = aws_kms_key.data.arn
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_version" "app" {
  for_each      = local.secret_values
  secret_id     = aws_secretsmanager_secret.app[each.key].id
  secret_string = each.value
}

# Placeholders for secrets you set out of band (model provider keys, OIDC client secret).
# Terraform creates the container; you write the value with the CLI or console:
#   aws secretsmanager put-secret-value --secret-id sentinel-production/ANTHROPIC_API_KEY --secret-string '...'
resource "aws_secretsmanager_secret" "external" {
  for_each                = toset(["OIDC_CLIENT_SECRET", "ANTHROPIC_API_KEY", "OPENAI_API_KEY"])
  name                    = "${local.prefix}/${each.key}"
  kms_key_id              = aws_kms_key.data.arn
  recovery_window_in_days = 7
}
