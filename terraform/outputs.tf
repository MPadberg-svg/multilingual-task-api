output "alb_dns_name" {
  description = "Public DNS name of the Application Load Balancer"
  value       = aws_lb.main.dns_name
}

output "cloudfront_domain" {
  description = "CloudFront distribution domain name (maps to GitHub Actions vars.CLOUDFRONT_DOMAIN)"
  value       = aws_cloudfront_distribution.cdn.domain_name
}

output "waf_web_acl_arn" {
  description = "AWS WAFv2 CloudFront WebACL ARN (empty when enable_waf is false)"
  value       = try(aws_wafv2_web_acl.cdn[0].arn, "")
}

output "ecr_repository_url" {
  description = "ECR repository URL for immutable API/Celery container images"
  value       = aws_ecr_repository.api.repository_url
}

output "github_actions_role_arn" {
  description = "Least-privilege AWS IAM OIDC role ARN for GitHub Actions (maps to vars.AWS_ROLE_ARN)"
  value       = try(aws_iam_role.github_actions_deploy[0].arn, "")
}

output "ecs_cluster_name" {
  description = "ECS cluster name (maps to GitHub Actions vars.ECS_CLUSTER)"
  value       = aws_ecs_cluster.main.name
}

output "ecs_api_service_name" {
  description = "ECS API service name (maps to GitHub Actions vars.ECS_SERVICE)"
  value       = aws_ecs_service.api.name
}

output "ecs_celery_service_name" {
  description = "ECS Celery worker service name (maps to GitHub Actions vars.ECS_CELERY_SERVICE)"
  value       = aws_ecs_service.celery_worker.name
}

output "ecs_celery_beat_service_name" {
  description = "ECS Celery Beat scheduler service name (maps to GitHub Actions vars.ECS_CELERY_BEAT_SERVICE)"
  value       = aws_ecs_service.celery_beat.name
}

output "ecs_api_task_family" {
  description = "ECS API task definition family (maps to GitHub Actions vars.ECS_TASK_DEFINITION)"
  value       = aws_ecs_task_definition.api.family
}

output "ecs_celery_task_family" {
  description = "ECS Celery worker task definition family (maps to GitHub Actions vars.ECS_CELERY_TASK_DEFINITION)"
  value       = aws_ecs_task_definition.celery_worker.family
}

output "ecs_celery_beat_task_family" {
  description = "ECS Celery Beat task definition family (maps to GitHub Actions vars.ECS_CELERY_BEAT_TASK_DEFINITION)"
  value       = aws_ecs_task_definition.celery_beat.family
}

output "private_subnet_ids" {
  description = "Comma-joinable private subnet IDs for one-off migration/cache ECS tasks"
  value       = module.vpc.private_subnets
}

output "ecs_security_group_id" {
  description = "Security group ID attached to ECS tasks"
  value       = aws_security_group.ecs.id
}

output "rds_endpoint" {
  description = "RDS PostgreSQL endpoint"
  value       = aws_db_instance.postgres.endpoint
  sensitive   = true
}

output "rds_replica_endpoint" {
  description = "RDS PostgreSQL read-replica endpoint (empty when enable_read_replica is false)"
  value       = try(aws_db_instance.postgres_replica[0].endpoint, "")
  sensitive   = true
}

output "audit_worm_bucket_name" {
  description = "S3 Object Lock (COMPLIANCE mode) WORM bucket for AuditChainCheckpoint archives"
  value       = try(aws_s3_bucket.audit_worm[0].bucket, "")
}

output "audit_kms_key_arn" {
  description = "AWS KMS asymmetric ECC_NIST_P256 SIGN_VERIFY key ARN for AuditChainCheckpoint transparency"
  value       = try(aws_kms_key.audit_anchor[0].arn, "")
}

output "celery_backlog_autoscaling_policy_arn" {
  description = "Application Auto Scaling policy ARN scaling Celery workers on AsyncBacklogDepth"
  value       = aws_appautoscaling_policy.celery_backlog.arn
}

output "canary_composite_alarm_arn" {
  description = "CloudWatch Composite Alarm ARN gating ECS API canary deployments"
  value       = aws_cloudwatch_composite_alarm.canary_rollout_guard.arn
}

output "redis_endpoint" {
  description = "ElastiCache Redis primary endpoint"
  value       = aws_elasticache_replication_group.redis.primary_endpoint_address
  sensitive   = true
}
