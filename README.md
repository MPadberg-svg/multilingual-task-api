# Multilingual Task API

[![CI](https://github.com/MPadberg-svg/multilingual-task-api/actions/workflows/ci.yml/badge.svg)](https://github.com/MPadberg-svg/multilingual-task-api/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.12-blue?logo=python&logoColor=white)](https://python.org)
[![Django](https://img.shields.io/badge/Django-5.1-092E20?logo=django&logoColor=white)](https://www.djangoproject.com/)
[![DRF](https://img.shields.io/badge/DRF-3.15.2-red)](https://www.django-rest-framework.org/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-336791?logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![Redis](https://img.shields.io/badge/Redis-7.0-DC382D?logo=redis&logoColor=white)](https://redis.io/)
[![OpenAI](https://img.shields.io/badge/OpenAI-GPT--4o--mini-412991?logo=openai&logoColor=white)](https://openai.com/)
[![Coverage](https://img.shields.io/badge/coverage-90%25-brightgreen)](https://codecov.io)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![AWS](https://img.shields.io/badge/AWS-ECS_Fargate-FF9900?logo=amazonaws&logoColor=white)](https://aws.amazon.com/ecs/)

**Production-grade multilingual REST API** for AI annotation platforms (Outlier AI, DataAnnotation, Mindrift/Toloka). Built with Django 5.1, PostgreSQL 16, Redis 7, Celery, Strawberry GraphQL, and OpenAI GPT-4o-mini. Deployed on AWS ECS Fargate via Terraform. Validated at **156 req/s with 96.3% cache hit rate**.

---

## Table of Contents

- [Overview](#overview)
- [Performance](#performance)
- [Architecture](#architecture)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Quick Start](#quick-start)
- [API Reference](#api-reference)
- [Authentication](#authentication)
- [Multilingual Support](#multilingual-support)
- [AI Assist Endpoints](#ai-assist-endpoints)
- [WebSocket Real-Time Updates](#websocket-real-time-updates)
- [GraphQL](#graphql)
- [Testing](#testing)
- [Security](#security)
- [Deployment](#deployment)
- [Architecture Decisions](#architecture-decisions)
- [License](#license)

---

## Overview

The Multilingual Task API solves the core infrastructure challenge of AI annotation platforms: distributing tasks across EN / ES / FR annotator markets with sub-50ms latency, LLM-assisted quality control, and enterprise-grade observability — all behind a single REST API.

**Key capabilities:**

- **Multilingual CRUD** — Tasks stored with `django-parler` translated models; language served via `Accept-Language` header with automatic EN fallback
- **Redis Caching** — Per-language cache keys with intelligent invalidation; 96.3% hit rate measured under 50 concurrent users
- **LLM Integration** — Three OpenAI endpoints: translation suggestions, prompt quality evaluation, RLHF test case generation; protected by a circuit breaker
- **Real-Time Updates** — Django Channels + Redis Pub/Sub WebSocket endpoint for live task feed
- **RBAC** — 4-role hierarchy (Viewer → Contributor → Admin → Owner) with immutable AuditLog
- **Async Processing** — Celery 5.4 for background translation generation, cache warming, and email dispatch
- **GraphQL** — Strawberry schema alongside REST for flexible client queries

---

## Performance

Benchmarked under 50 concurrent users with Locust:

| Endpoint | Method | P95 Latency | Cache Hit Rate |
|----------|--------|-------------|----------------|
| `/api/v1/tasks/` | GET | **45ms** | **96.3%** |
| `/api/v1/tasks/{id}/` | GET | **12ms** | **98.5%** |
| `/api/v1/tasks/` | POST | 120ms | N/A |
| `/api/v1/ai/suggest-task/` | POST | 2,340ms | 74.2% |
| `/api/v1/health/` | GET | 8ms | N/A |

**Resource usage under load:**
CPU: 34% avg · Memory: 45% avg · Throughput: **156 req/s** · Error rate: **0.00%**

Full benchmark methodology: [`docs/PERFORMANCE_BENCHMARK.md`](docs/PERFORMANCE_BENCHMARK.md)

---

## Architecture

```
Client (Web / App)
        │
        ▼
  CloudFront CDN
  (DDoS protection, TLS termination)
        │
        ▼
  ALB (HTTPS / HTTP2)
  (Health checks, routing)
        │
   ┌────┴────┬─────────┐
   ▼         ▼         ▼
ECS Task  ECS Task  Celery
Uvicorn   Uvicorn   Workers
   │
   ├──────────────────────┐
   ▼                      ▼
RDS PostgreSQL 16    ElastiCache Redis 7
(Multi-AZ, encrypted) (Caching + Pub/Sub)
```

**Request flow:**
1. Client → CloudFront (CDN + DDoS) → ALB (HTTPS termination)
2. ALB → ECS Fargate auto-scaling pool (2–10 Uvicorn tasks)
3. API → Redis cache check → PostgreSQL (cache miss only)
4. Events → Redis Pub/Sub → WebSocket consumers
5. Async work → Redis broker → Celery workers

---

## Tech Stack

| Layer | Technology | Version | Purpose |
|-------|-----------|---------|---------|
| Framework | Django | 5.1 | Web framework + ORM |
| API | Django REST Framework | 3.15.2 | REST API + OpenAPI 3.0 |
| i18n | django-parler | 2.3 | Translatable models (EN / ES / FR) |
| Cache | Redis | 7.0 | Caching, rate limiting, pub/sub |
| Queue | Celery | 5.4.0 | Async task processing |
| Real-Time | Django Channels | 4.1.0 | WebSocket connections |
| GraphQL | Strawberry | 0.235.0 | Flexible client queries |
| Auth | djangorestframework-simplejwt | 5.3.1 | JWT (30min access / 7-day refresh) |
| Database | PostgreSQL | 16 | Primary data store |
| AI | OpenAI GPT-4o-mini | 1.55+ | Translation, evaluation, RLHF |
| Resilience | Circuit Breaker | custom | OpenAI failure isolation |
| Docs | drf-spectacular | 0.27.0 | OpenAPI 3.0 / Swagger / ReDoc |
| Container | Docker | 24.x | Multi-stage builds |
| Orchestration | AWS ECS Fargate | — | Serverless containers |
| IaC | Terraform | 1.5+ | VPC, RDS, ElastiCache, ALB, CF |
| CI/CD | GitHub Actions | — | Lint → Test → Security → Deploy |

---

## Project Structure

```
multilingual-task-api/
├── .github/workflows/
│   ├── ci.yml               # Lint, test (90% gate), security scan
│   └── deploy.yml           # Build ECR image → Deploy ECS (blue/green)
├── apps/
│   ├── core/                # Platform foundation
│   │   ├── models.py        # CustomUser (UUID), Organization, RBAC, AuditLog
│   │   ├── views.py         # LivenessView, HealthCheckView, ReadinessView, MetricsView
│   │   ├── middleware.py    # Language resolution, correlation ID, CSP, tenant
│   │   ├── consumers.py     # WebSocket TaskUpdateConsumer (JWT auth)
│   │   ├── events.py        # Redis pub/sub EventPublisher (singleton)
│   │   ├── security.py      # InputValidator — XSS/SQLi detection
│   │   ├── throttling.py    # AIAssistRateThrottle (20/hr), BurstRateThrottle (5/min)
│   │   ├── performance.py   # QueryProfiler, optimized_task_queryset, batch updates
│   │   ├── graphql/schema.py # Strawberry Query + Mutation types
│   │   └── tests/           # 8 test modules, 68 tests
│   ├── tasks/               # Core business logic
│   │   ├── models.py        # Task (TranslatableModel, UUID PK, soft-delete)
│   │   ├── serializers.py   # Manual EN/ES/FR translation serializer
│   │   ├── views.py         # TaskViewSet — cached, tenant-scoped, restore action
│   │   ├── filters.py       # TaskFilter — multilingual search, status, date range
│   │   ├── signals.py       # post_save/post_delete → Redis pub/sub
│   │   ├── tasks.py         # Celery: translate, invalidate cache, audit, email
│   │   └── tests/           # 2 test modules, 19 tests
│   ├── ai_assist/           # LLM integration
│   │   ├── services.py      # AIService — caching, validation, circuit breaker
│   │   ├── circuit_breaker.py # OpenAI resilience (CLOSED/OPEN/HALF_OPEN)
│   │   ├── prompt_templates.py # PromptTemplateManager (versioned)
│   │   ├── views.py         # 3 throttled function-based views
│   │   └── tests/           # 14 tests
│   └── analytics/           # Observability
│       ├── middleware.py    # RequestTimingMiddleware (0 DB queries)
│       └── tests/           # 5 tests
├── config/
│   ├── settings/            # base.py, development.py, production.py
│   ├── urls.py              # REST + GraphQL + Docs routing
│   ├── asgi.py              # ASGI + WebSocket routing
│   └── celery.py            # Celery app + task routing
├── tests/
│   ├── conftest.py          # Shared pytest fixtures
│   ├── factories.py         # UserFactory, TaskFactory (EN/ES/FR)
│   └── benchmarks/load_test.py # Locust performance tests
├── terraform/               # AWS infrastructure (ECS, RDS, ElastiCache, ALB, CF)
├── docs/
│   ├── adr/                 # Architecture Decision Records (4 ADRs)
│   ├── PERFORMANCE_BENCHMARK.md
│   └── api-explorer.html    # Interactive API demo
├── .pre-commit-config.yaml  # black, isort, flake8, mypy, bandit
├── setup.cfg                # Centralized lint configuration
├── CHANGELOG.md             # Keep-a-Changelog format
├── docker-compose.yml       # db, redis, api, celery-worker, celery-beat
├── Dockerfile               # Multi-stage build (builder + production)
└── Makefile                 # Dev shortcuts
```

---

## Quick Start

### Prerequisites

- Docker + Docker Compose
- Git

### 1. Clone and configure

```bash
git clone https://github.com/MPadberg-svg/multilingual-task-api.git
cd multilingual-task-api
cp .env.example .env
# Edit .env — set OPENAI_API_KEY and SECRET_KEY
```

### 2. Full setup (one command)

```bash
make setup
# Runs: build → up → migrate → seed → create-admin → warm-cache
```

### 3. Verify

```bash
# Liveness (process alive)
curl http://localhost:8000/api/v1/live/

# Readiness (DB + Redis healthy)
curl http://localhost:8000/api/v1/ready/

# Interactive docs
open http://localhost:8000/api/docs/

# Admin panel
open http://localhost:8000/admin/
# Email: admin@example.com  Password: adminpass123
```

### Individual make targets

```bash
make up              # Start Docker services (db, redis, api, celery)
make down            # Stop all services
make build           # Rebuild images (--no-cache)
make migrate         # Run database migrations
make seed            # Create 3 demo users + 15 multilingual tasks
make create-admin    # Create superuser (idempotent)
make warm-cache      # Pre-warm Redis cache
make test            # Run full test suite with coverage
make test-fast       # Fast run, no coverage report
make test-cov        # Generate HTML coverage report
make lint            # flake8 + mypy
make format          # black + isort (auto-fix)
make security        # bandit + pip-audit
make shell           # Django shell inside container
make cache-flush     # FLUSHDB on Redis
make locust-benchmark   # Load test UI at localhost:8089
make locust-headless    # Headless: 50 users, 60s, export CSV
make logs            # Tail API container logs
make docker-clean    # Remove volumes + images
```

---

## API Reference

- **Swagger UI:** `http://localhost:8000/api/docs/`
- **ReDoc:** `http://localhost:8000/api/redoc/`
- **OpenAPI Schema (JSON):** `http://localhost:8000/api/schema/`
- **Interactive Demo:** `docs/api-explorer.html`

### Base URL

```
http://localhost:8000/api/v1/
```

### Endpoints

#### Infrastructure

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/v1/live/` | GET | None | Liveness probe — 200 if process is alive |
| `/api/v1/health/` | GET | None | Health check — DB + Redis status |
| `/api/v1/ready/` | GET | None | Readiness probe — 503 if any dependency down |
| `/api/v1/metrics/` | GET | None | Prometheus-format metrics |

#### Authentication

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/auth/token/` | POST | Obtain JWT access + refresh tokens |
| `/api/v1/auth/token/refresh/` | POST | Refresh expired access token |
| `/api/v1/auth/token/verify/` | POST | Verify token validity |

#### Tasks

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/tasks/` | GET | List tasks (cached 5min, language-scoped) |
| `/api/v1/tasks/` | POST | Create task with EN/ES/FR translations |
| `/api/v1/tasks/{id}/` | GET | Task detail (cached 10min) |
| `/api/v1/tasks/{id}/` | PATCH | Update task fields |
| `/api/v1/tasks/{id}/` | DELETE | Soft-delete (sets `is_active=False`) |
| `/api/v1/tasks/{id}/restore/` | POST | Restore a soft-deleted task |

**Task status lifecycle:** `pending` → `in_progress` → `completed` → `archived`

**Language selection:** Pass `Accept-Language: es` or `Accept-Language: fr` header.
Falls back to `en` if translation is missing.

**Example — create a multilingual task:**

```bash
curl -X POST http://localhost:8000/api/v1/tasks/ \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "translations": {
      "en": {"title": "Review image dataset", "description": "Check for labeling errors"},
      "es": {"title": "Revisar conjunto de datos", "description": "Verificar errores"},
      "fr": {"title": "Examiner le jeu de données", "description": "Vérifier les erreurs"}
    },
    "status": "pending"
  }'
```

**Example — list tasks in Spanish:**

```bash
curl http://localhost:8000/api/v1/tasks/ \
  -H "Authorization: Bearer $TOKEN" \
  -H "Accept-Language: es"
```

**Filtering:**

```bash
# Filter by status
GET /api/v1/tasks/?status=pending

# Search across all languages
GET /api/v1/tasks/?search=quarterly

# Filter by date range
GET /api/v1/tasks/?created_after=2026-01-01&created_before=2026-06-01

# Sort by creation date
GET /api/v1/tasks/?ordering=-created_at
```

#### AI Assist

| Endpoint | Method | Rate Limit | Description |
|----------|--------|------------|-------------|
| `/api/v1/ai/suggest-task/` | POST | 20/hr, 5/min burst | Generate EN/ES/FR translations |
| `/api/v1/ai/evaluate-quality/` | POST | 20/hr, 5/min burst | Score prompt quality (0–10) |
| `/api/v1/ai/generate-test-cases/` | POST | 20/hr, 5/min burst | Generate RLHF test cases |

#### Other

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/graphql/` | POST | Strawberry GraphQL endpoint |
| `/ws/tasks/` | WebSocket | Real-time task update feed |
| `/admin/` | GET | Django admin panel |

---

## Authentication

The API uses JWT authentication via `djangorestframework-simplejwt`.

**Token lifetimes:** Access token = 30 minutes · Refresh token = 7 days

```bash
# Step 1 — obtain tokens
curl -X POST http://localhost:8000/api/v1/auth/token/ \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@example.com", "password": "adminpass123"}'

# Response:
# {
#   "access": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
#   "refresh": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
# }

# Step 2 — use access token
curl http://localhost:8000/api/v1/tasks/ \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."

# Step 3 — refresh when expired
curl -X POST http://localhost:8000/api/v1/auth/token/refresh/ \
  -H "Content-Type: application/json" \
  -d '{"refresh": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."}'
```

**RBAC roles:**

| Role | Permissions |
|------|-------------|
| `viewer` | Read-only access to tasks |
| `contributor` | Create and update tasks |
| `admin` | Full task management + team management |
| `owner` | Full access + organization settings + billing |

---

## Multilingual Support

Tasks store translations in three languages using `django-parler`:

| Language | Code | Fallback |
|----------|------|---------|
| English | `en` | Primary (default) |
| Spanish | `es` | Falls back to `en` |
| French | `fr` | Falls back to `en` |

**How it works:**
1. Client sends `Accept-Language: es` header
2. `LanguageResolutionMiddleware` sets `request.language = "es"`
3. `TaskSerializer` calls `safe_translation_getter("title", language_code="es", any_language=True)`
4. If Spanish translation exists → return it; otherwise → return English
5. Cache stores separate entries per language: `mltask:task_list:{user_id}:es`

**Celery async translation generation:**

```bash
# Trigger async translation for a task
curl -X POST http://localhost:8000/api/v1/ai/suggest-task/ \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"description": "Annotate facial expressions in video clips"}'

# Response:
# {
#   "en": "Annotate facial expressions in video clips",
#   "es": "Anotar expresiones faciales en clips de vídeo",
#   "fr": "Annoter les expressions faciales dans les clips vidéo"
# }
```

---

## AI Assist Endpoints

All AI endpoints are protected by:
- **Rate limiting:** 20 requests/hour sustained + 5 requests/minute burst
- **Input validation:** XSS and SQLi pattern detection before any LLM call
- **Circuit breaker:** Auto-opens after 5 consecutive OpenAI failures; retries after 60s
- **Response caching:** 74.2% cache hit rate on AI responses

### POST `/api/v1/ai/suggest-task/`

Generates multilingual title/description translations using GPT-4o-mini.

```bash
curl -X POST http://localhost:8000/api/v1/ai/suggest-task/ \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"description": "Review sentiment analysis labels for customer reviews"}'
```

### POST `/api/v1/ai/evaluate-quality/`

Scores a prompt on clarity, specificity, and annotator usability (0–10).

```bash
curl -X POST http://localhost:8000/api/v1/ai/evaluate-quality/ \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"prompt": "Label the emotion expressed in this tweet as: positive, negative, or neutral."}'
```

### POST `/api/v1/ai/generate-test-cases/`

Generates RLHF-style test cases (input + expected output) for a task description.

```bash
curl -X POST http://localhost:8000/api/v1/ai/generate-test-cases/ \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"task_description": "Identify objects in satellite imagery"}'
```

---

## WebSocket Real-Time Updates

Connect to receive live task events for an organization:

```javascript
const token = "your-jwt-access-token";
const ws = new WebSocket(`ws://localhost:8000/ws/tasks/?token=${token}`);

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log(data);
  // {
  //   "type": "task",
  //   "action": "updated",
  //   "timestamp": "2026-05-22T14:30:00Z",
  //   "data": { "id": "...", "status": "completed", ... }
  // }
};
```

**Events emitted:** `created` · `updated` · `deleted`
**Auth:** JWT token passed as `?token=` query parameter
**Channel pattern:** `mltask:events:{org_id}:tasks`

---

## GraphQL

The Strawberry GraphQL endpoint supports queries and mutations alongside the REST API.

```bash
# Endpoint
POST http://localhost:8000/graphql/
```

**Example queries:**

```graphql
# List tasks with translations
{
  tasks {
    id
    status
    title
    description
    translations {
      languageCode
      title
    }
  }
}

# Single task by ID
{
  task(id: "550e8400-e29b-41d4-a716-446655440000") {
    id
    status
    title
  }
}

# Update task status (mutation)
mutation {
  updateTaskStatus(taskId: "...", newStatus: "completed") {
    id
    status
  }
}
```

---

## Testing

```bash
# Full suite with coverage gate (≥90%)
make test

# Fast run (no coverage)
make test-fast

# HTML coverage report
make test-cov
open htmlcov/index.html

# Run a specific test module
docker-compose exec api pytest apps/tasks/tests/test_api.py -xvs

# Run by keyword
docker-compose exec api pytest -k "test_cache" -v

# Load test (UI at localhost:8089)
make locust-benchmark

# Headless load test: 50 users, 60s
make locust-headless
```

### Test Suite (114 tests)

| Module | Tests | Covers |
|--------|-------|--------|
| `apps/core/tests/test_custom_user.py` | 8 | CustomUser model + manager |
| `apps/core/tests/test_views.py` | 12 | Liveness, health, readiness, metrics |
| `apps/core/tests/test_security.py` | 10 | InputValidator — XSS / SQLi |
| `apps/core/tests/test_throttling.py` | 13 | AIAssistRateThrottle + BurstRateThrottle |
| `apps/core/tests/test_events.py` | 6 | EventPublisher + Redis pub/sub |
| `apps/core/tests/test_middleware.py` | 6 | Language resolution + request logging |
| `apps/core/tests/test_performance.py` | 9 | QueryProfiler, batch updates, translations |
| `apps/core/tests/test_management_commands.py` | 8 | seed_data, warm_cache, superuser |
| `apps/core/tests/test_consumers.py` | 4 | WebSocket JWT auth |
| `apps/tasks/tests/test_api.py` | 13 | CRUD, multilingual, auth, isolation |
| `apps/tasks/tests/test_cache.py` | 6 | Per-language caching + invalidation |
| `apps/ai_assist/tests/test_ai_services.py` | 14 | JSON parsing, circuit breaker, injection |
| `apps/analytics/tests/test_middleware.py` | 5 | RequestTimingMiddleware (0 DB queries) |

### Test pyramid

```
             E2E (Docker)
               5%
          ─────────────
         Integration (DRF)
               25%
        ─────────────────
             Unit (pytest)
                60%
       ─────────────────────
           Load (Locust)
         156 req/s baseline
```

---

## Security

| Control | Implementation |
|---------|---------------|
| Authentication | JWT — 30min access / 7-day refresh tokens |
| Authorization | RBAC — 4 roles: Viewer → Contributor → Admin → Owner |
| Input validation | `InputValidator` — regex-based XSS + SQLi detection on every AI call |
| Transport | HTTPS only, HSTS 1 year, secure cookies |
| Security headers | CSP, X-Frame-Options, Referrer-Policy |
| Secrets | AWS Secrets Manager — never in codebase |
| Audit trail | Immutable `AuditLog` — stores IP, user agent, metadata; no add/change/delete via admin |
| Rate limiting | 20 req/hr sustained + 5 req/min burst on all AI endpoints |
| AI resilience | Circuit breaker — auto-opens after 5 failures, retries after 60s |
| Static analysis | `bandit` (medium+ severity gate in CI) |
| Dependency scanning | `pip-audit` (CVE check in CI) |
| Container | Non-root user, read-only filesystem, multi-stage build |

---

## Deployment

### Local (Docker Compose)

```bash
git clone https://github.com/MPadberg-svg/multilingual-task-api.git
cd multilingual-task-api
cp .env.example .env   # Add OPENAI_API_KEY, SECRET_KEY
make setup             # Full setup in one command
```

### AWS Production (Terraform)

```bash
cd terraform/

# Initialize providers
terraform init

# Create production workspace
terraform workspace new production

# Preview changes
terraform plan -var="environment=production"

# Apply (provisions ECS, RDS, ElastiCache, ALB, CloudFront)
terraform apply -var="environment=production"

# Outputs:
# alb_dns_name      = multilingual-task-api-alb-xxx.us-east-1.elb.amazonaws.com
# cloudfront_domain = dxxx.cloudfront.net
# ecr_repository_url = 123456789.dkr.ecr.us-east-1.amazonaws.com/multilingual-task-api
```

### AWS Infrastructure

| Resource | Configuration |
|----------|--------------|
| ECS Fargate | Auto-scaling 2–10 tasks, blue/green deploy |
| RDS PostgreSQL 16 | Multi-AZ, AES-256 encrypted, 7-day backups |
| ElastiCache Redis 7 | Cluster mode, automatic failover, encryption at rest |
| ALB | HTTPS/HTTP2, health checks, WAF integration |
| CloudFront | CDN + DDoS protection, origin shield |
| Secrets Manager | API keys + DB credentials with automatic rotation |

### CI/CD Pipeline (GitHub Actions)

Every push to `main` or `develop` triggers:

```
lint ──────────┐
               ├──▶ test (90% coverage gate) ──▶ security ──▶ build ECR ──▶ deploy ECS
security ──────┘
```

| Job | What it does |
|-----|-------------|
| `lint` | flake8, black, isort, mypy |
| `test` | pytest with PostgreSQL + Redis services; Codecov upload |
| `security` | bandit (medium+ severity) + pip-audit (CVE check) |
| `build` | Multi-stage Docker image → push to ECR |
| `deploy-staging` | ECS blue/green deployment on `develop` branch |
| `deploy-production` | ECS blue/green deployment on `main` branch |

---

## Architecture Decisions

| ADR | Decision | Rationale |
|-----|----------|-----------|
| [ADR-001](docs/adr/001-uuid-primary-keys.md) | UUID primary keys | Security (no enumeration), distributed system compatibility |
| [ADR-002](docs/adr/002-django-parler-over-jsonfield.md) | django-parler over JSONField | Proper query support, index on translations, automatic fallback |
| [ADR-003](docs/adr/003-redis-cache-strategy.md) | Per-language Redis keys | Prevents stale cross-language responses; enables selective invalidation |
| [ADR-004](docs/adr/004-function-views-for-ai.md) | Function views for AI endpoints | Independent rate limiting per endpoint without ViewSet overhead |

---

## Environment Variables

Key variables in `.env` (see `.env.example` for full list):

```env
# Django
SECRET_KEY=your-secret-key-min-50-chars
DEBUG=False
ALLOWED_HOSTS=your-domain.com

# Database
DATABASE_URL=postgres://user:pass@host:5432/dbname

# Redis
REDIS_URL=redis://localhost:6379/0
CELERY_BROKER_URL=redis://localhost:6379/1

# OpenAI
OPENAI_API_KEY=sk-proj-...
OPENAI_MODEL=gpt-4o-mini

# Logging
JSON_LOGS=True        # Enable structured JSON logs (recommended for production)
LOG_LEVEL=INFO
```

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">

Built with Django REST Framework · Redis · PostgreSQL · OpenAI · Terraform/AWS

**[Live Docs](https://your-domain.com/api/docs/)** · **[GitHub](https://github.com/MPadberg-svg/multilingual-task-api)** · **[LinkedIn](https://linkedin.com/in/matteo-padberg-43a3b5405)**

</div>
