variable "name" {
  description = "Resource name prefix (lowercase, letters and digits)."
  type        = string
  default     = "sentinel"
}

variable "environment" {
  description = "Deployment environment label (staging, production). Exported as APP_ENV."
  type        = string
  default     = "production"
}

variable "location" {
  description = "Azure region."
  type        = string
  default     = "eastus2"
}

variable "image" {
  description = "Sentinel container image, digest-pinned in production. Use the `<tag>-extras` image: the Azure Blob audit sink configured here needs azure-storage-blob."
  type        = string
}

variable "domain_name" {
  description = "Public hostname served by Front Door (BASE_URL)."
  type        = string
}

variable "vnet_cidr" {
  type    = string
  default = "10.50.0.0/16"
}

variable "api_min_replicas" {
  type    = number
  default = 2
}

variable "api_max_replicas" {
  type    = number
  default = 6
}

variable "worker_replicas" {
  type    = number
  default = 2
}

variable "api_cpu" {
  type    = number
  default = 1.0
}

variable "api_memory" {
  type    = string
  default = "2Gi"
}

variable "worker_cpu" {
  type    = number
  default = 1.0
}

variable "worker_memory" {
  type    = string
  default = "4Gi"
}

variable "postgres_sku" {
  type    = string
  default = "GP_Standard_D2ds_v5"
}

variable "postgres_storage_mb" {
  type    = number
  default = 65536
}

variable "postgres_backup_retention_days" {
  type    = number
  default = 14
}

variable "redis_sku" {
  description = "Basic | Standard | Premium. Standard+ for a replica."
  type        = string
  default     = "Standard"
}

variable "redis_capacity" {
  type    = number
  default = 1
}

variable "audit_retention_days" {
  description = "Immutability policy (time-based retention) for the audit container. Locked policies cannot be shortened."
  type        = number
  default     = 365
}

variable "lock_audit_policy" {
  description = "Lock the immutability policy (irreversible, required for a true WORM guarantee)."
  type        = bool
  default     = false
}

variable "log_retention_days" {
  type    = number
  default = 90
}

variable "waf_rate_limit" {
  description = "Front Door WAF rate limit: requests per minute per client IP."
  type        = number
  default     = 600
}

variable "extra_environment" {
  description = "Additional plain environment variables (map NAME => value). Never put secrets here."
  type        = map(string)
  default     = {}
}

variable "tags" {
  type    = map(string)
  default = {}
}
