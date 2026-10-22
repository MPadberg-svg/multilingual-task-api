variable "aws_region" {
  default = "us-east-1"
}

variable "project_name" {
  default = "multilingual-task-api"
}

variable "environment" {
  description = "staging or production"
}

variable "image_tag" {
  description = "Immutable container image tag (e.g. git SHA)"
  default     = "v1.0.0"
}

variable "domain_name" {
  description = "Primary API hostname for ALLOWED_HOSTS"
  default     = ""
}

variable "acm_certificate_arn" {
  description = "Optional ACM certificate ARN for HTTPS ALB listener"
  default     = ""
}

variable "django_secret_key_arn" {
  description = "Secrets Manager / SSM Parameter ARN for Django SECRET_KEY"
  default     = ""
}

variable "db_password_secret_arn" {
  description = "Secrets Manager / SSM Parameter ARN for POSTGRES_PASSWORD"
  default     = ""
}

variable "openai_api_key_secret_arn" {
  description = "Secrets Manager / SSM Parameter ARN for OPENAI_API_KEY"
  default     = ""
}

variable "vpc_cidr" {
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
  default = "db.t3.micro"
}

variable "db_allocated_storage" {
  default = 20
}

variable "db_name" {
  default = "multilingual_task_api"
}

variable "db_username" {
  default = "postgres"
}

variable "db_password" {
  sensitive = true
}

variable "redis_node_type" {
  default = "cache.t3.micro"
}

variable "ecs_desired_count" {
  default = 2
}

variable "ecs_task_cpu" {
  description = "Fargate task CPU units (1024 = 1 vCPU)"
  default     = "512"
}

variable "ecs_task_memory" {
  description = "Fargate task memory (MiB)"
  default     = "1024"
}

variable "common_tags" {
  type = map(string)
  default = {
    Project   = "multilingual-task-api"
    ManagedBy = "terraform"
  }
}
