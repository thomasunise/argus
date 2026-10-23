variable "name" {
  description = "Resource name prefix."
  type        = string
  default     = "sentinel"
}

variable "environment" {
  description = "Deployment environment label (staging, production). Also exported as APP_ENV."
  type        = string
  default     = "production"
}

variable "region" {
  description = "AWS region."
  type        = string
  default     = "us-east-1"
}

variable "vpc_cidr" {
  description = "CIDR for the VPC."
  type        = string
  default     = "10.40.0.0/16"
}

variable "az_count" {
  description = "Number of availability zones to spread across."
  type        = number
  default     = 2
}

variable "image" {
  description = "Sentinel container image, digest-pinned in production (ghcr.io/eekosystems/sentinel@sha256:...)."
  type        = string
}

variable "domain_name" {
  description = "Public hostname for the API (BASE_URL). Used for the ACM certificate and Route 53 record when hosted_zone_id is set."
  type        = string
}

variable "hosted_zone_id" {
  description = "Route 53 hosted zone id for domain_name. Empty = you create the DNS record and certificate validation yourself."
  type        = string
  default     = ""
}

variable "acm_certificate_arn" {
  description = "Existing ACM certificate for domain_name. Empty = request one (requires hosted_zone_id for DNS validation)."
  type        = string
  default     = ""
}

variable "api_desired_count" {
  description = "ECS tasks for the API service."
  type        = number
  default     = 2
}

variable "worker_desired_count" {
  description = "ECS tasks for the worker service."
  type        = number
  default     = 2
}

variable "api_cpu" {
  type    = number
  default = 1024
}

variable "api_memory" {
  type    = number
  default = 2048
}

variable "worker_cpu" {
  type    = number
  default = 1024
}

variable "worker_memory" {
  type    = number
  default = 4096
}

variable "db_instance_class" {
  type    = string
  default = "db.t4g.medium"
}

variable "db_allocated_storage" {
  type    = number
  default = 50
}

variable "db_multi_az" {
  type    = bool
  default = true
}

variable "db_backup_retention_days" {
  type    = number
  default = 14
}

variable "redis_node_type" {
  type    = string
  default = "cache.t4g.small"
}

variable "audit_retention_days" {
  description = "Object Lock retention (compliance mode) for audit records. Cannot be shortened after creation."
  type        = number
  default     = 365
}

variable "log_retention_days" {
  type    = number
  default = 90
}

variable "waf_rate_limit" {
  description = "WAF rate-based rule: requests per 5 minutes per IP before blocking."
  type        = number
  default     = 2000
}

variable "allowed_cidrs" {
  description = "CIDRs allowed through the ALB security group. Default is open (WAF + app auth in front); narrow for internal deployments."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "extra_environment" {
  description = "Additional plain environment variables for API and worker (map of NAME => value). Never put secrets here."
  type        = map(string)
  default     = {}
}

variable "extra_secret_arns" {
  description = "Additional Secrets Manager secrets to inject as environment variables (map of ENV_NAME => secret ARN)."
  type        = map(string)
  default     = {}
}

variable "tags" {
  type    = map(string)
  default = {}
}
