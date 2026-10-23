output "alb_dns_name" {
  description = "Point domain_name at this (done automatically when hosted_zone_id is set)."
  value       = aws_lb.this.dns_name
}

output "base_url" {
  value = "https://${var.domain_name}"
}

output "ecs_cluster" {
  value = aws_ecs_cluster.this.name
}

output "api_service" {
  value = aws_ecs_service.api.name
}

output "worker_service" {
  value = aws_ecs_service.worker.name
}

output "rds_endpoint" {
  value = aws_db_instance.this.address
}

output "redis_endpoint" {
  value = aws_elasticache_replication_group.this.primary_endpoint_address
}

output "audit_bucket" {
  value = aws_s3_bucket.audit.id
}

output "secret_arns" {
  description = "Secrets Manager ARNs injected into the tasks. Read ADMIN_PASSWORD from here for first login."
  value       = { for k, s in aws_secretsmanager_secret.app : k => s.arn }
}

output "external_secret_arns" {
  description = "Secrets you must populate out of band (OIDC client secret, model provider keys)."
  value       = { for k, s in aws_secretsmanager_secret.external : k => s.arn }
}

output "log_groups" {
  value = {
    api    = aws_cloudwatch_log_group.api.name
    worker = aws_cloudwatch_log_group.worker.name
    waf    = aws_cloudwatch_log_group.waf.name
  }
}

output "kms_key_arn" {
  value = aws_kms_key.data.arn
}
