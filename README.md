# Multilingual Task API

[![Django](https://img.shields.io/badge/Django-5.1-green)](https://www.djangoproject.com/)
[![DRF](https://img.shields.io/badge/DRF-3.15.2-red)](https://www.django-rest-framework.org/)
[![Redis](https://img.shields.io/badge/Redis-7.0-red)](https://redis.io/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-blue)](https://www.postgresql.org/)
[![OpenAI](https://img.shields.io/badge/OpenAI-1.30-black)](https://openai.com/)
[![Coverage](https://img.shields.io/badge/coverage-90%25-brightgreen)]()
[![License](https://img.shields.io/badge/license-MIT-blue)]()

**Production-grade multilingual REST API for AI annotation platforms.** Built with Django 5.1, DRF, PostgreSQL 16, Redis 7, OpenAI, and Terraform. Deployed on AWS ECS with automated CI/CD. Validated at **156 req/s with 96.3% cache hit rate**.

## Architecture

```
Client → CloudFront (CDN) → ALB (HTTPS) → ECS Fargate (Auto-scaling 2-10)
                                      ↓
                    ┌─────────┼─────────┐
                    ↓         ↓         ↓
                  RDS     ElastiCache   OpenAI
                PostgreSQL   Redis 7      API
```

## Key Metrics

| Metric | Target | Achieved |
|--------|--------|----------|
| Cache Hit Rate | 94% | **96.3%** |
| P95 List Latency | <200ms | **45ms** |
| P95 Detail Latency | <100ms | **12ms** |
| Test Coverage | 90% | **90%+** |
| Concurrent Users | 50 | **Validated** |
| Throughput | — | **156 req/s** |

## Tech Stack

| Layer | Technology | Version | Purpose |
|-------|-----------|---------|---------|
| Framework | Django | 5.1 | Web framework |
| API | Django REST Framework | 3.15.2 | REST API + OpenAPI 3.0 |
| i18n | django-parler | 2.3 | Multilingual model translations |
| Cache | Redis | 7.0 | Caching, rate limiting, pub/sub |
| Queue | Celery | 5.4.0 | Async task processing |
| Real-Time | Django Channels | 4.1.0 | WebSocket support |
| GraphQL | Strawberry | 0.235.0 | Flexible client queries |
| Auth | djangorestframework-simplejwt | 5.3.1 | JWT authentication |
| Database | PostgreSQL | 16 | Primary data store |
| AI | OpenAI | 1.30 | LLM integration |
| Container | Docker | 24.x | Application packaging |
| Orchestration | AWS ECS Fargate | — | Serverless containers |
| IaC | Terraform | 1.5+ | Infrastructure provisioning |
| CI/CD | GitHub Actions | — | Automated testing and deployment |

## Quick Start

```bash
# Start local environment
make up              # Docker Compose: Postgres, Redis, API, Celery
make migrate         # Run database migrations
make seed            # Create demo data (3 users, 15 multilingual tasks)
make test            # Run test suite with coverage (90%+ gate)
make locust-benchmark # Run load tests
```

## API Reference

- **Interactive Explorer**: Open `docs/api-explorer.html` in your browser
- **OpenAPI Docs**: `/api/schema/` (Swagger UI at `/api/docs/`)
- **Health Check**: `GET /api/v1/health/`
- **Metrics**: `GET /api/v1/metrics/` (Prometheus format)

### Key Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/tasks/` | GET | List tasks (cached, 5min TTL) |
| `/api/v1/tasks/` | POST | Create task with translations |
| `/api/v1/tasks/{id}/` | GET | Task detail (cached, 10min TTL) |
| `/api/v1/tasks/{id}/` | DELETE | Soft delete task |
| `/api/v1/tasks/{id}/restore/` | POST | Restore soft-deleted task |
| `/api/v1/ai/suggest-task/` | POST | AI-generated translations |
| `/api/v1/ai/evaluate-quality/` | POST | Prompt quality scoring |
| `/api/v1/ai/generate-test-cases/` | POST | RLHF test case generation |
| `/api/v1/auth/token/` | POST | Obtain JWT access token |
| `/api/v1/auth/token/refresh/` | POST | Refresh JWT token |
| `/graphql/` | POST | Strawberry GraphQL endpoint |
| `/ws/tasks/` | WS | Real-time task updates |

## Architecture Decisions

- [ADR-001: UUID Primary Keys](docs/adr/001-uuid-primary-keys.md) — Security and distributed systems
- [ADR-002: django-parler over JSONField](docs/adr/002-django-parler-over-jsonfield.md) — Query performance
- [ADR-003: Redis Cache Strategy](docs/adr/003-redis-cache-strategy.md) — Sub-100ms latency
- [ADR-004: Function Views for AI](docs/adr/004-function-views-for-ai.md) — Independent rate limiting

## Performance Benchmarks

See [docs/PERFORMANCE_BENCHMARK.md](docs/PERFORMANCE_BENCHMARK.md) for detailed load test results.

## Deployment

Infrastructure is provisioned via Terraform:

- **ECS Fargate**: Auto-scaling 2–10 tasks
- **RDS PostgreSQL 16**: Multi-AZ, encrypted, 7-day backups
- **ElastiCache Redis 7**: Cluster mode, failover, encryption
- **CloudFront**: Static asset CDN, DDoS protection

CI/CD via GitHub Actions: `lint → test (90% coverage gate) → security scan → build ECR → deploy ECS`.

## Security Posture

- **Authentication**: JWT with 30min access / 7-day refresh tokens
- **Authorization**: RBAC with 4 roles (Viewer → Contributor → Admin → Owner)
- **Input Validation**: HTML escaping, regex pattern blocking for SQL/script injection
- **Transport**: HTTPS only, HSTS 1 year, secure cookies
- **Headers**: CSP, X-Frame-Options, Referrer-Policy
- **Secrets**: AWS Secrets Manager, never in code
- **Audit**: Immutable logs with IP, user agent, metadata

## Monitoring & Observability

- **Logs**: Structured JSON with correlation IDs
- **Metrics**: Prometheus endpoint at `/api/v1/metrics/`
- **Health**: Comprehensive check (DB + Redis + OpenAI)
- **Alerts**: CloudWatch alarms for CPU, memory, unhealthy hosts
- **Tracing**: `X-Correlation-ID` across all requests

## License

MIT License — see [LICENSE](LICENSE) for details.
