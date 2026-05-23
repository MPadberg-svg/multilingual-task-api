output "alb_dns_name" {
  value = aws_lb.main.dns_name
}

output "rds_endpoint" {
  value     = aws_db_instance.postgres.endpoint
  sensitive = true
}

output "redis_endpoint" {
  value     = aws_elasticache_replication_group.redis.primary_endpoint_address
  sensitive = true
}

output "ecr_repository_url" {
  value = aws_ecr_repository.api.repository_url
}

output "cloudfront_domain" {
  value = aws_cloudfront_distribution.cdn.domain_name
}
