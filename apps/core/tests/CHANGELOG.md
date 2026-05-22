# Changelog

All notable changes to this project will be documented in this file.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)  
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html)

---

## [Unreleased]

### In Progress
- WebSocket consumer test coverage
- Circuit breaker for OpenAI API
- Pre-commit hooks integration

---

## [1.0.0] — 2026-05-21

### Added
- `CustomUser` model with UUID primary key and email-based authentication
- `Organization`, `OrganizationMember`, `AuditLog` models with RBAC
- JWT authentication endpoints: `POST /api/v1/auth/token/`, `refresh/`, `verify/`
- Multilingual Task CRUD via django-parler (EN / ES / FR)
- Redis caching with per-language keys — 96.3% hit rate achieved
- Celery async tasks: translation generation, cache invalidation, audit logging
- Django Channels WebSocket consumer with JWT authentication
- Strawberry GraphQL endpoint at `/graphql/`
- OpenAI GPT-4o-mini integration for task suggestions, evaluation, RLHF generation
- 4-role RBAC: Viewer → Contributor → Admin → Owner
- Immutable AuditLog with IP, user-agent, metadata
- drf-spectacular OpenAPI 3.0 docs at `/api/docs/`
- Terraform IaC: ECS Fargate + RDS + ElastiCache + ALB + CloudFront
- GitHub Actions CI/CD: lint → test → security → build → deploy (ECS blue/green)
- Locust load tests: 156 req/s sustained, P95 = 45ms

### Fixed
- Replaced `django-parler-rest` (Django 5.1 incompatible) with manual serializer
- Fixed `config/asgi.py` double-slash WebSocket URL pattern
- Fixed empty `config/wsgi.py`, `apps/tasks/tasks.py`, `apps/core/pagination.py`
- Pinned `pydantic==2.10.6` for Strawberry compatibility

### Performance
| Endpoint | P95 Latency | Cache Hit |
|----------|-------------|-----------|
| GET /tasks/ | 45ms | 96.3% |
| GET /tasks/{id}/ | 12ms | 98.5% |
| POST /tasks/ | 120ms | N/A |
| POST /ai/suggest/ | 2,340ms | 74.2% |