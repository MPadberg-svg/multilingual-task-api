variable "aws_region" {
  description = "AWS region for all provisioned resources"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Resource naming prefix"
  type        = string
  default     = "multilingual-task-api"
}

variable "environment" {
  description = "Deployment environment (staging or production)"
  type        = string
}

variable "image_tag" {
  description = "Immutable container image tag (e.g. git SHA or release tag)"
  type        = string
  default     = "v1.3.2"
}

variable "domain_name" {
  description = "Primary API hostname for ALLOWED_HOSTS"
  type        = string
  default     = ""
}

variable "acm_certificate_arn" {
  description = "Optional ACM certificate ARN for HTTPS ALB listener"
  type        = string
  default     = ""
}

variable "django_secret_key_arn" {
  description = "Secrets Manager / SSM Parameter ARN for Django SECRET_KEY"
  type        = string
  default     = ""
}

variable "db_password_secret_arn" {
  description = "Secrets Manager / SSM Parameter ARN for POSTGRES_PASSWORD"
  type        = string
  default     = ""
}

variable "openai_api_key_secret_arn" {
  description = "Secrets Manager / SSM Parameter ARN for OPENAI_API_KEY"
  type        = string
  default     = ""
}

variable "metrics_token_secret_arn" {
  description = "Optional Secrets Manager / SSM Parameter ARN for Prometheus METRICS_TOKEN"
  type        = string
  default     = ""
}

variable "otel_exporter_otlp_endpoint" {
  description = "Optional OTLP/HTTP trace collector URL (e.g. https://collector.example.com/v1/traces)"
  type        = string
  default     = ""
}

variable "github_repository" {
  description = "GitHub owner/repo allowed to assume the OIDC deployment IAM role"
  type        = string
  default     = "MPadberg-svg/multilingual-task-api"
}

variable "create_github_oidc_provider" {
  description = "Whether to create the AWS IAM OIDC provider for token.actions.githubusercontent.com"
  type        = bool
  default     = true
}

variable "existing_github_oidc_provider_arn" {
  description = "Existing GitHub OIDC provider ARN when create_github_oidc_provider is false"
  type        = string
  default     = ""
}

variable "enable_waf" {
  description = "Attach an AWS WAFv2 WebACL (IP rate limit + OWASP managed rules) to CloudFront"
  type        = bool
  default     = true
}

variable "waf_rate_limit_per_5m" {
  description = "Maximum requests per 5-minute window from a single client IP at the WAFv2 edge"
  type        = number
  default     = 2000
}

variable "origin_verify_secret" {
  description = "Optional shared secret header injected by CloudFront and enforced on the ALB to prevent direct-origin WAF bypass"
  type        = string
  default     = ""
  sensitive   = true
}

variable "vpc_cidr" {
  type    = string
  default = "10.0.0.0/16"
}

variable "availability_zones" {
  type    = list(string)
  default = ["us-east-1a", "us-east-1b"]
}

variable "private_subnet_cidrs" {
  type    = list(string)
  default = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "public_subnet_cidrs" {
  type    = list(string)
  default = ["10.0.101.0/24", "10.0.102.0/24"]
}

variable "db_instance_class" {
  type    = string
  default = "db.t3.micro"
}

variable "db_allocated_storage" {
  type    = number
  default = 20
}

variable "db_name" {
  type    = string
  default = "multilingual_task_api"
}

variable "db_username" {
  type    = string
  default = "postgres"
}

variable "db_password" {
  type      = string
  sensitive = true
}

variable "redis_node_type" {
  type    = string
  default = "cache.t3.micro"
}

variable "ecs_desired_count" {
  type    = number
  default = 2
}

variable "ecs_task_cpu" {
  description = "Fargate task CPU units (1024 = 1 vCPU)"
  type        = string
  default     = "512"
}

variable "ecs_task_memory" {
  description = "Fargate task memory (MiB)"
  type        = string
  default     = "1024"
}

variable "common_tags" {
  type = map(string)
  default = {
    Project   = "multilingual-task-api"
    ManagedBy = "terraform"
  }
}
