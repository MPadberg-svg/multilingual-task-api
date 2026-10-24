# Multilingual Task API

[![CI](https://github.com/MPadberg-svg/multilingual-task-api/actions/workflows/ci.yml/badge.svg)](https://github.com/MPadberg-svg/multilingual-task-api/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.12-blue?logo=python&logoColor=white)](https://python.org)
[![Django](https://img.shields.io/badge/Django-5.2-092E20?logo=django&logoColor=white)](https://www.djangoproject.com/)
[![DRF](https://img.shields.io/badge/DRF-3.17.1-red)](https://www.django-rest-framework.org/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-336791?logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![Redis](https://img.shields.io/badge/Redis-7.0-DC382D?logo=redis&logoColor=white)](https://redis.io/)
[![OpenAI](https://img.shields.io/badge/OpenAI-GPT--4o--mini-412991?logo=openai&logoColor=white)](https://openai.com/)
[![Version](https://img.shields.io/badge/release-v1.11.0-blue)](https://github.com/MPadberg-svg/multilingual-task-api/releases)
[![Coverage](https://img.shields.io/badge/coverage-92%25-brightgreen)](https://codecov.io)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![AWS](https://img.shields.io/badge/AWS-ECS_Fargate-FF9900?logo=amazonaws&logoColor=white)](https://aws.amazon.com/ecs/)

**Production-grade multi-tenant RLHF & multilingual task orchestration API** for AI data platforms (Outlier AI, Scale AI, DataAnnotation, Mindrift/Toloka). Built with Django 5.2, PostgreSQL 16, Redis 7, Celery, Django Channels, Strawberry GraphQL, and OpenAI GPT-4o-mini. Deployed on AWS ECS Fargate via Terraform. Validated at **156 req/s with 96.3% cache hit rate**.

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

- **Multilingual RLHF Pipeline, Adaptive Active-Learning Routing & DPO Dataset Exports** — Atomic priority-, specialist- & uncertainty-ranked task leasing (`POST /api/v1/tasks/claim/` with blind gold-task injection, domain/difficulty routing, active-learning `-uncertainty_score` acquisition, and probation gating on `expert` tasks), LLM judge pairwise entropy triage (`POST /api/v1/ai/judge-pair/` & `POST /api/v1/tasks/{id}/triage-uncertainty/`) with empirically calibrated per-`(organization, domain)` thresholds (`DomainUncertaintyPolicy` + `/uncertainty-policies/`), structured preference & 1–5 rubric annotations (`POST /api/v1/tasks/{id}/annotations/`), multi-dimensional per-domain & per-language Bayesian skill-weighted Inter-Annotator Agreement with automatic split-vote `expert` escalation (`/annotators/calibration/?domain=...&language=...`), split-vote adjudication (`/adjudicate/`), batch ingestion (`/bulk/`), streaming NDJSON export (`/export/?format=jsonl`), and quality-gated DPO preference export (`/export-dpo/`) with PII scrubbing, deterministic train/eval splits, and Ed25519/KMS-signed RFC 9162 Merkle provenance manifests
- **Self-Serve Multi-Tenancy, OIDC SSO, SCIM 2.0, RFC 9162 Merkle Proofs & Ed25519/KMS WORM Audit Checkpointing** — Full `/api/v1/organizations/` CRUD, member seat-limit enforcement (`max_users`), 4-tier RBAC (`viewer` → `contributor` → `admin` → `owner`), enterprise OIDC `RS256`/`ES256` JWKS ID-token exchange (`POST /api/v1/auth/sso/oidc/exchange/`), RFC 7643/7644 SCIM 2.0 user lifecycle provisioning (`/scim/v2/Users`), per-tenant SHA-256 hash-chained `AuditLog` (`pg_advisory_xact_lock`) plus RFC 9162 binary Merkle roots, $O(\log N)$ single-event inclusion proofs (`/audit-logs/{entry_id}/inclusion-proof/`), append-only checkpoint consistency proofs (`/audit-logs/checkpoints/consistency-proof/`), and HMAC + asymmetric `Ed25519` / AWS KMS (`ECC_NIST_P256` `ECDSA_SHA_256`) + S3 Object Lock (`COMPLIANCE` mode) WORM `AuditChainCheckpoint` notarization (`/audit-logs/public-key/`, `/audit-logs/checkpoints/{id}/bundle/`, `/audit-logs/checkpoints/`, `/audit-logs/verify/`)
- **Enterprise M2M API Keys & Idempotency** — Prefix-indexed SHA-256 `OrganizationAPIKey` (`mlk_live_<prefix>_...`) with route scopes (`tasks:read`, `tasks:write`, `tasks:export`, `ai:write`) plus `Idempotency-Key` middleware (`24h` Redis replay, `409` in-flight lock, `422` payload-mismatch protection)
- **SSRF-Hardened Signed Webhooks & Transactional Outbox** — Outbound `WebhookEndpoint` delivery persisted atomically inside PostgreSQL via `OutboxEvent` (`SELECT ... FOR UPDATE SKIP LOCKED` Celery relay + 15s Beat sweep, dead-letter admin replay `/outbox/{id}/replay/`, CloudWatch metric-filter & Prometheus `mltask_outbox_dead_letter_events` gauges, bounded-chunk retention pruning, W3C `traceparent` continuity), self-serve circuit recovery (`/webhooks/{id}/recover/`) & delivery replay (`/deliveries/{id}/replay/`), signed with `X-MLTask-Signature-256: sha256=<hmac>`, non-redirecting TLS transport, and SSRF protection
- **PostgreSQL 16 Row-Level Security (RLS), Read-Replica Routing & `pg_trgm` Search** — Storage-engine `ENABLE`/`FORCE ROW LEVEL SECURITY` policies (`tasks_task`, `tasks_annotatorcalibration`, `core_auditchaincheckpoint`, `core_organizationapikey`, `core_webhookendpoint`, `core_outboxevent`, `core_organizationssoconfig`, `core_aiusagelog`) paired with `PostgresRLSMiddleware` and `mltask_rls_app` (`NOSUPERUSER NOBYPASSRLS`), RLS-aware `ReplicaDatabaseRouter` steering `/tasks/stats/`, `/tasks/export/`, `/usage/`, `/finops/`, `/audit-logs/verify/`, `/audit-logs/checkpoints/`, and `/annotators/calibration/` to `POSTGRES_REPLICA_HOST` (`X-Query-Target: replica`), plus `pg_trgm` GIN trigram indexes accelerating multilingual `?search=` `EXISTS (... ILIKE ...)` semi-joins and plan-tiered per-organization sliding-window rate limits (`X-RateLimit-*`)
- **Async Auto-Translation & Monthly AI FinOps Budget Governance** — `auto_translate=true` on task creation dispatches background OpenAI EN/ES/FR translation + live WebSocket notification while enforcing per-tenant monthly token & USD spend ceilings (`AIUsageLog` SQL ledger + Redis rollups, `/finops/`, `429 ai_budget_exceeded` cutoff, and deduplicated `ai.budget_threshold_reached` / `ai.budget_exceeded` outbox alerts) alongside Prometheus `/api/v1/metrics/`
- **1M+ Scale Keyset Cursor Pagination & W3C/OTLP Tracing** — Adaptive `$O(1)$` composite keyset cursor pagination (`?pagination=cursor`, ordered by `(-created_at, -id)`) alongside standard offset pagination, plus zero-dependency W3C `traceparent` & OpenTelemetry OTLP/HTTP JSON span export correlating HTTP requests, Celery workers, OpenAI spans, and outbound webhooks
- **Mounted CSP-Nonce Live Console** — Interactive `/explorer/` operations UI protected by per-request cryptographic CSP nonces (`'nonce-...'`, zero `'unsafe-inline'`) with live `/ws/tasks/` WebSocket streaming

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
| Framework | Django | 5.2.18 | Web framework + ORM |
| API | Django REST Framework | 3.17.1 | REST API + OpenAPI 3.0 |
| i18n | django-parler | 2.4.1 | Translatable models (EN / ES / FR) |
| Cache | Redis | 7.0 | Caching, rate limiting, pub/sub |
| Queue | Celery | 5.6.3 | Async task processing |
| Real-Time | Django Channels | 4.3.2 | WebSocket connections |
| GraphQL | Strawberry | 0.314.1 | Flexible client queries |
| Auth | djangorestframework-simplejwt | 5.5.1 | JWT (30min access / 7-day refresh) |
| Database | PostgreSQL | 16 | Primary data store |
| AI | OpenAI GPT-4o-mini | 2.31.0 | Translation, evaluation, RLHF |
| Schemas | Pydantic | 2.13.3 | Structured LLM output validation |
| Resilience | Circuit Breaker | custom | Single-flight OpenAI failure isolation |
| Docs | drf-spectacular | 0.29.0 | OpenAPI 3.0 / Swagger / ReDoc |
| Container | Docker | 24.x | Multi-stage builds |
| Orchestration | AWS ECS Fargate | — | Serverless API + Celery containers |
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
│   ├── core/                # Platform foundation, auth, tenancy, M2M & webhooks
│   │   ├── models.py        # CustomUser, Organization, Member, APIKey, Webhook, AuditLog
│   │   ├── authentication.py # Scoped SHA-256 OrganizationAPIKeyAuthentication
│   │   ├── idempotency.py   # Redis Idempotency-Key deduplication middleware (24h TTL)
│   │   ├── webhooks.py      # SSRF-hardened, HMAC-SHA256 outbound webhook engine
│   │   ├── tenant_views.py  # /auth/me, /auth/logout, /organizations/*, /explorer/
│   │   ├── serializers.py   # Auth, Organization, APIKey, Webhook & AuditLog serializers
│   │   ├── views.py         # LivenessView, HealthCheckView, ReadinessView, MetricsView
│   │   ├── middleware.py    # Language, correlation ID, nonce CSP, tenant & RBAC
│   │   ├── consumers.py     # WebSocket TaskUpdateConsumer (first-message JWT auth)
│   │   ├── events.py        # Redis pub/sub EventPublisher + Channels broadcaster
│   │   ├── security.py      # InputValidator — XSS/SQLi/code-execution guardrails
│   │   ├── throttling.py    # AIAssistRateThrottle (20/hr), BurstRateThrottle (5/min)
│   │   ├── performance.py   # QueryProfiler, optimized_task_queryset, batch updates
│   │   ├── graphql/schema.py # Strawberry Query + Mutation types
│   │   └── tests/           # Core, tenancy, security, M2M, webhook & GraphQL tests
│   ├── tasks/               # Multilingual RLHF workflow engine
│   │   ├── models.py        # Task (UUID, leasing, consensus) + TaskAnnotation
│   │   ├── consensus.py     # Inter-Annotator Agreement (IAA) & consensus evaluator
│   │   ├── serializers.py   # EN/ES/FR Task, Annotation, Claim & Adjudicate serializers
│   │   ├── views.py         # TaskViewSet — claim, annotations, adjudicate, bulk, export
│   │   ├── filters.py       # TaskFilter — multilingual search, status, priority, dates
│   │   ├── signals.py       # post_save/post_delete → Redis pub/sub & Channels
│   │   ├── tasks.py         # Celery: auto-translate, webhook retry, cache, audit, email
│   │   └── tests/           # CRUD, cache, RLHF leasing, consensus, bulk & JSONL tests
│   ├── ai_assist/           # LLM integration & FinOps accounting
│   │   ├── services.py      # AIService — Pydantic v2 schemas, caching, token telemetry
│   │   ├── circuit_breaker.py # OpenAI resilience (CLOSED/OPEN/HALF_OPEN)
│   │   ├── prompt_templates.py # PromptTemplateManager (versioned + system guardrails)
│   │   ├── views.py         # 3 throttled function-based views
│   │   └── tests/           # AI resilience, prompt-injection & FinOps tests
│   └── analytics/           # Observability
│       ├── middleware.py    # RequestTimingMiddleware (0 DB queries)
│       └── tests/           # Timing & header tests
├── config/
│   ├── settings/            # base.py, development.py, production.py, testing.py
│   ├── urls.py              # REST + Auth + Tenancy + Explorer + GraphQL + Docs routing
│   ├── asgi.py              # ASGI + Origin-validated WebSocket routing
│   └── celery.py            # Celery app + task routing
├── tests/
│   └── benchmarks/load_test.py # Locust performance & throughput suite
├── terraform/               # AWS infrastructure (ECS, RDS, ElastiCache, ALB, CF)
├── docs/
│   ├── adr/                 # Architecture Decision Records (4 ADRs)
│   ├── PERFORMANCE_BENCHMARK.md
│   └── api-explorer.html    # Interactive CSP-nonce-safe API & WebSocket console
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

- Docker + Docker Compose (for the full stack)
- Python 3.12+ (for local development without Docker)
- Git

### Option A — Full Docker stack (recommended)

```bash
git clone https://github.com/MPadberg-svg/multilingual-task-api.git
cd multilingual-task-api

# Configure environment
cp .env.example .env
# Required: set OPENAI_API_KEY and a strong SECRET_KEY in .env

# One-command setup: build → up → migrate → seed → admin → cache warm
make setup
```

### Option B — Local development (no Docker)

Use this when you want fast iteration without spinning up containers.
The test suite uses **SQLite in-memory** so no database is needed.

```bash
git clone https://github.com/MPadberg-svg/multilingual-task-api.git
cd multilingual-task-api

# Install all dependencies
pip install -r requirements.txt -r requirements-dev.txt

# Configure environment (SQLite is used automatically in tests)
cp .env.example .env

# Run the full test suite instantly — no infrastructure required
pytest
```

### 3. Verify (Docker)

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

### Make targets

```bash
make up              # Start Docker services (db, redis, api, celery)
make down            # Stop all services
make build           # Rebuild images (--no-cache)
make migrate         # Run database migrations inside container
make seed            # Create 3 demo users + 15 multilingual tasks
make create-admin    # Create superuser (idempotent)
make warm-cache      # Pre-warm Redis cache
make test            # Run full test suite with coverage (inside Docker)
make test-fast       # Fast run, no coverage report (inside Docker)
make test-local      # Run tests locally without Docker (uses SQLite)
make test-integration   # Run full suite + live PG16/Redis7 concurrency tests
make test-cov        # Generate HTML coverage report
make lint            # flake8 + mypy
make format          # black + isort (auto-fix)
make security        # bandit + pip-audit
make shell           # Django shell inside container
make cache-flush     # FLUSHDB on Redis
make locust-benchmark   # Load test UI at localhost:8089
make locust-headless    # Headless: 50 users, 60s, export CSV
make tf-fmt          # Check canonical Terraform HCL formatting
make tf-validate     # Initialize (-backend=false) & validate Terraform IaC
make sync-github-vars   # Sync Terraform outputs into GitHub Actions variables
make logs            # Tail API container logs
make docker-clean    # Remove volumes + images
```

---

## API Reference

- **Swagger UI:** `http://localhost:8000/api/docs/`
- **ReDoc:** `http://localhost:8000/api/redoc/`
- **OpenAPI Schema (JSON):** `http://localhost:8000/api/schema/`
- **Live RLHF Operations Console:** `http://localhost:8000/explorer/`

### Base URL

```
http://localhost:8000/api/v1/
```

### Endpoints

#### Infrastructure & Observability

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/v1/live/` | GET | None | Liveness probe — 200 if process is alive |
| `/api/v1/health/` | GET | None | Health check — DB + Redis status |
| `/api/v1/ready/` | GET | None | Readiness probe — 503 if any dependency down |
| `/api/v1/metrics/` | GET | `METRICS_TOKEN` / Staff | Prometheus metrics (HTTP, cache hit rate, OpenAI tokens & USD cost) |
| `/explorer/` | GET | None | CSP-nonce-hardened interactive API & live WebSocket console |

#### Authentication & Session Lifecycle

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/auth/token/` | POST | Obtain JWT access + refresh tokens (rate-limited) |
| `/api/v1/auth/token/refresh/` | POST | Rotate & refresh access token |
| `/api/v1/auth/token/verify/` | POST | Verify token validity |
| `/api/v1/auth/me/` | GET, PATCH | Inspect or update caller profile + active organization memberships |
| `/api/v1/auth/logout/` | POST | Blacklist caller-owned refresh token + persist `AuditLog` |
| `/api/v1/auth/sso/oidc/exchange/` | POST | Verify enterprise IdP `RS256`/`ES256` OIDC `id_token`, JIT-provision member, and mint SimpleJWT |

#### Multi-Tenant Organizations, RBAC, SSO/SCIM, FinOps, M2M API Keys & Webhooks

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/organizations/` | GET, POST | List caller's organizations or bootstrap a new tenant (`owner`) |
| `/api/v1/organizations/{org_id}/` | GET, PATCH | Retrieve or update organization settings (`admin`/`owner`) |
| `/api/v1/organizations/{org_id}/members/` | GET, POST | List members or invite user enforcing `max_users` seat quota |
| `/api/v1/organizations/{org_id}/members/{member_id}/` | PATCH, DELETE | Update role or remove member (protects last `owner`) |
| `/api/v1/organizations/{org_id}/sso/` | GET, PATCH | Inspect or update OIDC JWKS/PEM, allowed email domains, and group-to-role mapping (`admin`/`owner`) |
| `/api/v1/organizations/{org_id}/sso/scim-token/` | POST | Rotate SHA-256-hashed RFC 7644 SCIM 2.0 Bearer credential (`scim_live_...`) |
| `/api/v1/organizations/{org_id}/scim/v2/Users` | GET, POST | RFC 7643/7644 SCIM 2.0 directory listing (`filter=userName eq "..."`) & user provisioning |
| `/api/v1/organizations/{org_id}/scim/v2/Users/{member_id}` | GET, PUT, PATCH, DELETE | RFC 7644 SCIM `PatchOp` role/profile sync & `active=false` multi-tenant-safe offboarding |
| `/api/v1/organizations/{org_id}/audit-logs/` | GET | Paginated, filterable SHA-256 hash-chained security audit trail (read-replica routed) |
| `/api/v1/organizations/{org_id}/audit-logs/verify/` | GET | Verify cryptographic `AuditLog` hash chain + HMAC, Ed25519/KMS & WORM `AuditChainCheckpoint` signatures |
| `/api/v1/organizations/{org_id}/audit-logs/public-key/` | GET | Retrieve active Ed25519 / AWS KMS SubjectPublicKeyInfo PEM, SHA-256 fingerprint, and RFC 7517/8037 JWK |
| `/api/v1/organizations/{org_id}/audit-logs/checkpoints/` | GET, POST | List notarized WORM checkpoints (replica-routed) or mint an immediate HMAC + Ed25519/KMS + S3 WORM checkpoint |
| `/api/v1/organizations/{org_id}/audit-logs/checkpoints/consistency-proof/` | GET | Replica-routed RFC 9162 §2.1.4 append-only Merkle consistency proof across checkpoints (`?from_seq=&to_seq=`) |
| `/api/v1/organizations/{org_id}/audit-logs/checkpoints/{id}/bundle/` | GET | Replica-routed self-contained offline verification bundle (verifiable with public key alone) |
| `/api/v1/organizations/{org_id}/audit-logs/{entry_id}/inclusion-proof/` | GET | Replica-routed RFC 9162 $O(\log N)$ Merkle inclusion proof for a single `AuditLog` entry |
| `/api/v1/organizations/{org_id}/annotators/calibration/` | GET | Domain/language specialist accuracy & Bayesian `skill_weight` leaderboard (`?domain=...&language=...`) |
| `/api/v1/organizations/{org_id}/uncertainty-policies/` | GET, POST | Inspect, pin, or empirically calibrate per-domain active-learning thresholds (`DomainUncertaintyPolicy`) |
| `/api/v1/organizations/{org_id}/usage/` | GET | Real-time plan quotas + cumulative OpenAI token & USD telemetry (read-replica routed) |
| `/api/v1/organizations/{org_id}/finops/` | GET, PATCH | Monthly AI token/USD ceilings, per-operation `AIUsageLog` rollups (`X-Query-Target`), and alert thresholds |
| `/api/v1/organizations/{org_id}/api-keys/` | GET, POST | List or mint SHA-256 scoped M2M API keys (`mlk_live_<prefix>_...`) |
| `/api/v1/organizations/{org_id}/api-keys/{key_id}/` | DELETE | Immediately revoke an M2M API key |
| `/api/v1/organizations/{org_id}/webhooks/` | GET, POST | List or register SSRF-validated outbound HMAC webhook endpoints |
| `/api/v1/organizations/{org_id}/webhooks/{webhook_id}/` | DELETE | Delete a webhook endpoint |
| `/api/v1/organizations/{org_id}/webhooks/{webhook_id}/test/` | POST | Send signed `webhook.ping` event and inspect delivery receipt |
| `/api/v1/organizations/{org_id}/webhooks/{webhook_id}/recover/` | POST | Reset webhook failure circuit counter and re-activate endpoint |
| `/api/v1/organizations/{org_id}/webhooks/{webhook_id}/deliveries/` | GET | Paginated webhook delivery audit history |
| `/api/v1/organizations/{org_id}/webhooks/{webhook_id}/deliveries/{delivery_id}/replay/` | POST | Re-sign and replay a historical webhook delivery |
| `/api/v1/organizations/{org_id}/outbox/` | GET | Paginated Transactional Outbox event inspector (`status`, `topic`) |
| `/api/v1/organizations/{org_id}/outbox/{event_id}/replay/` | POST | Re-arm a `failed` dead-letter outbox event for immediate relay |

#### Multilingual Tasks & RLHF Annotation Pipeline

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/tasks/` | GET | List tasks (cached 5min, language- & query-scoped; filter by `status`, `priority`, `search`) |
| `/api/v1/tasks/` | POST | Create task (`auto_translate=true` queues async OpenAI EN/ES/FR translation) |
| `/api/v1/tasks/stats/` | GET | Tenant/user RLHF operational metrics (status, priority, consensus, active leases) via read replica |
| `/api/v1/tasks/bulk/` | POST | Atomic batch creation (up to 100 tasks, enforcing `Organization.max_tasks`) |
| `/api/v1/tasks/claim/` | POST | Atomically lease highest-priority unannotated task (`FOR UPDATE SKIP LOCKED`) |
| `/api/v1/tasks/export/?format=jsonl` | GET | Stream RLHF dataset (translations, rubric scores, consensus) as NDJSON via read replica |
| `/api/v1/tasks/export-dpo/` | GET | Stream quality-gated DPO preference pairs (`trl`/`chat`, PII-scrubbed, deterministic `train`/`eval` splits) or emit Ed25519/KMS-signed provenance manifest (`?export_format=manifest&archive_to_s3=true`) |
| `/api/v1/tasks/{id}/` | GET, PATCH, DELETE | Retrieve (cached 10min), update, or soft-delete (`is_active=False`) |
| `/api/v1/tasks/{id}/restore/` | POST | Restore a soft-deleted task (`admin`/`owner`) |
| `/api/v1/tasks/{id}/annotations/` | GET, POST | List or submit structured RLHF preference + 1–5 rubric scores & trigger IAA consensus |
| `/api/v1/tasks/{id}/triage-uncertainty/` | POST | Score response pair via LLM judge Shannon/margin entropy & auto-promote borderline tasks to `expert` |
| `/api/v1/tasks/{id}/adjudicate/` | POST | Resolve split-vote disagreement and finalize gold `consensus_choice` (`admin`/`owner`) |

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
| `/api/v1/ai/judge-pair/` | POST | 20/hr, 5/min burst | Score RLHF prompt/response pair with LLM judge probabilities & adaptive entropy threshold |

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

### POST `/api/v1/ai/judge-pair/`

Evaluates candidate RLHF responses (`response_a` vs `response_b`) and returns calibrated preference probabilities, Shannon entropy, margin uncertainty, and active-learning escalation decision (`should_escalate`).

```bash
curl -X POST http://localhost:8000/api/v1/ai/judge-pair/ \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"prompt": "Compare Rust vs C++ memory safety", "response_a": "...", "response_b": "...", "domain": "code"}'
```

---

## WebSocket Real-Time Updates

Connect to receive live task & auto-translation events using first-message JWT authentication (preventing token leakage in URL query logs):

```javascript
const token = "your-jwt-access-token";
const ws = new WebSocket("ws://localhost:8000/ws/tasks/");

ws.onopen = () => {
  ws.send(JSON.stringify({ type: "authenticate", token, organization_id: "optional-org-uuid" }));
};

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log(data);
};
```

**Events emitted:** `created` · `updated` · `deleted` · `translated`
**Auth:** First-message JSON frame `{"type": "authenticate", "token": "<jwt>"}` within 5s timeout + `AllowedHostsOriginValidator`
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

### Running tests

```bash
# ── Without Docker (uses SQLite + in-memory cache) ──────────────────────────
pytest                                      # full suite — 132 tests
pytest -x -q                               # fail-fast, quiet
pytest -k "test_cache"                     # filter by keyword
pytest apps/tasks/tests/test_api.py -xvs  # single module, verbose
pytest --cov=apps --cov-report=term-missing  # with coverage

# ── Inside Docker container ──────────────────────────────────────────────────
make test            # full suite with coverage gate
make test-fast       # fast run, no coverage
make test-cov        # generate HTML report → open htmlcov/index.html
docker-compose exec api pytest apps/tasks/tests/test_api.py -xvs
docker-compose exec api pytest -k "test_cache" -v

# ── Load testing ─────────────────────────────────────────────────────────────
make locust-benchmark   # Web UI at http://localhost:8089
make locust-headless    # Headless: 50 users, 60s run, CSV output
```

### Settings strategy

| Context | Settings module | Database | Cache |
|---------|----------------|----------|-------|
| Tests (`pytest`) | `config.settings.testing` | SQLite `:memory:` | LocMemCache |
| Development | `config.settings.development` | PostgreSQL | Redis |
| CI Integration | `config.settings.ci_integration` | PostgreSQL 16 | Redis 7 (`ZlibCompressor` + `channels-redis`) |
| Production | `config.settings.production` | PostgreSQL | Redis |

The `config.settings.testing` module is selected automatically via `pytest.ini` (`DJANGO_SETTINGS_MODULE`). This means the full test suite runs locally with **zero infrastructure** — while CI also executes the complete suite plus live multi-connection concurrency tests against real `postgres:16-alpine` and `redis:7-alpine` service containers.

### Test Suite (215 tests across SQLite & PostgreSQL 16 + Redis 7 · 92% coverage)

| Module | Covers |
|--------|--------|
| `tests/integration/test_postgres_redis_integration.py` | Live PostgreSQL 16 `FOR UPDATE SKIP LOCKED LIMIT 1` non-blocking lease & 8-thread stampede, Redis 7 `ZlibCompressor` + `INCRBY`, `EventPublisher` Pub/Sub, `channels-redis` WebSockets |
| `apps/core/tests/test_distributed_cb_and_claim_sql.py` | Cluster-wide Redis `CircuitBreaker` (`shared_cache=True`) single-flight probing & fallback, single-row `LIMIT 1` claim SQL contract |
| `apps/core/tests/test_edge_waf_and_container_security.py` | CloudFront WAFv2 (`us-east-1`, IP rate limit, OWASP rules + RLHF `SizeRestrictions_BODY` override), `X-Origin-Verify` ALB origin cloaking, hardened `Dockerfile` & `.dockerignore` `/explorer/` preservation, CI Docker smoke gate |
| `apps/core/tests/test_terraform_iac_and_deploy.py` | CloudFront header allowlist (`X-API-Key`, `Idempotency-Key`, `traceparent`), GitHub OIDC `iam:PassRole` scoping, singleton Celery Beat ECS rollout, N-before-migrate ordering, CI `terraform validate` gate |
| `apps/core/tests/test_v130_cursor_pagination_and_otel.py` | Composite keyset cursor pagination (`?pagination=cursor`), W3C `traceparent` validation, 4-boundary span correlation, OTLP/HTTP JSON export |
| `apps/core/tests/test_wave1_tenancy_auth_idempotency.py` | `/auth/me/`, `/auth/logout/` blacklisting, Organization CRUD/RBAC/quotas, AuditLogs, `Idempotency-Key` |
| `apps/tasks/tests/test_wave2_wave3_rlhf_bulk_export.py` | Atomic task leasing, rubric annotations, IAA consensus, split adjudication, `/bulk/`, `/export/?format=jsonl`, `auto_translate` |
| `apps/core/tests/test_wave4_apikeys_webhooks_explorer_finops.py` | SHA-256 M2M API keys & scopes, SSRF/DNS-rebinding webhook defense, HMAC-SHA256 signing, FinOps token/USD metrics, `/explorer/` nonce CSP |
| `apps/core/tests/test_tenancy_rbac_and_i18n.py` | 4-tier RBAC, plan quota enforcement, language header fallback |
| `apps/core/tests/test_graphql_and_websockets_security.py` | GraphQL auth/RBAC isolation, WebSocket origin & first-message JWT security |
| `apps/ai_assist/tests/test_hardening_and_resilience.py` | Single-flight circuit breaker, Pydantic v2 output schemas, prompt-injection defense |
| `apps/tasks/tests/test_multilingual_tenancy_and_celery.py` | Zero N+1 query guarantees, multi-language cache invalidation, Celery tasks |
| `apps/core/tests/test_views.py` · `test_security.py` · `test_throttling.py` | Health/readiness/metrics auth, XSS/SQLi `InputValidator`, burst & sustained rate limits |

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
| Authentication | SimpleJWT (`15m` access / `7d` rotating blacklisted refresh) + prefix-indexed SHA-256 `OrganizationAPIKey` (`hmac.compare_digest`) |
| Authorization | 4-tier tenant RBAC (`viewer` → `contributor` → `admin` → `owner`) + granular M2M scopes (`tasks:read`, `tasks:write`, `tasks:export`, `ai:write`) |
| Idempotency | Redis `Idempotency-Key` middleware (`24h` replay cache, `30s` atomic lock → `409`, SHA-256 payload mismatch → `422`) |
| Outbound SSRF & Webhooks | Scheme allowlist, literal IP + DNS-rebinding private/loopback/metadata (`169.254.169.254`) blocking, non-redirecting `http.client` TLS, `X-MLTask-Signature-256` HMAC-SHA256 |
| Input validation | `InputValidator` — XSS, SQLi, and dangerous code/shell pattern detection across REST, GraphQL, and AI prompts |
| Transport & CSP | HTTPS/HSTS (`1y` preload), locked `default-src 'none'` CSP on JSON APIs, cryptographic per-request `'nonce-...'` CSP on `/explorer/`, `AllowedHostsOriginValidator` on WebSockets |
| Observability auth | `/api/v1/metrics/` protected by constant-time `METRICS_TOKEN` Bearer check or authenticated staff session |
| Secrets | Environment & AWS Secrets Manager injection — zero secrets stored in repository |
| Audit trail | Immutable `AuditLog` — records actor, tenant, IP (`NUM_TRUSTED_PROXIES`-aware), user agent, and structured metadata |
| Rate limiting | Auth login/refresh/verify throttles + `20/hr` sustained & `5/min` burst throttles + per-tenant daily AI quotas |
| AI resilience | Cluster-wide Redis-coordinated single-flight `CircuitBreaker` (with local thread-safe fallback) + Pydantic v2 structured output schemas |
| Static & CVE scanning | `bandit -ll` (0 findings, 0 `#nosec` skips) + `pip-audit --strict` (0 production CVEs) |
| Edge WAF & origin cloaking | AWS WAFv2 (`RateLimitPerIP`, `AmazonIpReputationList`, `CommonRuleSet` tuned for >8 KB RLHF batches) + `X-Origin-Verify` ALB `403` cloaking |
| Container | Non-login UID `1000` `appuser`, `root:root` read-only `/app`, `/dev/shm` worker heartbeats, pinned `python:3.12-slim-bookworm` multi-stage build |

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
cp terraform.tfvars.example production.tfvars  # Populate secrets ARNs, domain, and RDS password

# Initialize providers
terraform init

# Validate configuration
terraform validate

# Preview changes
terraform plan -var-file="production.tfvars" -out=tfplan

# Apply (provisions ECS API + Celery Worker + singleton Celery Beat, GitHub OIDC IAM role, RDS, ElastiCache, ALB, CloudFront)
terraform apply tfplan

# Bind provisioned Terraform outputs directly to GitHub Actions repository variables
cd ..
make sync-github-vars
```

### AWS Infrastructure

| Resource | Configuration |
|----------|--------------|
| ECS Fargate | Auto-scaling 2–10 API tasks (`CPU` + `ALBRequestCountPerTarget`), 1–6 Celery workers (`CPU` + proactive `AsyncBacklogDepth` queue-depth scaling), singleton Beat, deployment circuit breaker + CloudWatch alarm auto-rollback |
| S3 Object Lock WORM, DPO Archive & KMS | AES-256 encrypted, public-blocked `COMPLIANCE` Object Lock bucket (`audit_worm_retention_days`), `GLACIER_IR`-lifecycle DPO dataset export bucket (`dataset_export_retention_days`), and asymmetric AWS KMS `ECC_NIST_P256` `SIGN_VERIFY` key notarizing checkpoints & dataset manifests |
| GitHub OIDC IAM | Keyless `AssumeRoleWithWebIdentity` scoped to `repo:MPadberg-svg/multilingual-task-api:*` + restricted `iam:PassRole` |
| RDS PostgreSQL 16 | Multi-AZ primary + optional encrypted read replica (`enable_read_replica`, wired to `POSTGRES_REPLICA_HOST`), 7-day backups |
| CloudWatch Alarms | Metric + Composite canary alarms (`canary_rollout_guard`) across Outbox DLQ, RDS `ReplicaLag`/`CPUUtilization`, and ALB `HTTPCode_Target_5XX_Count` |
| ElastiCache Redis 7 | Cluster mode, automatic failover, encryption in transit (`rediss://`) & at rest |
| ALB | HTTPS/HTTP2 (`TLS 1.3`), HTTP→HTTPS `301`, `X-Origin-Verify` origin cloaking (`403` on direct-to-ALB bypass), `/api/v1/health/` checks |
| CloudFront + WAFv2 | `0` TTL dynamic origin forwarding auth/tenant/idempotency/trace headers + `us-east-1` WAFv2 WebACL (`RateLimitPerIP`, `AmazonIpReputationList`, `CommonRuleSet`) |
| Secrets Manager | API keys + DB credentials with least-privilege ECS execution role injection |

### CI/CD Pipeline (GitHub Actions)

Every push or pull request to `main` or `develop` triggers `ci.yml`, and manual/environment rollouts run via `deploy.yml`:

| Job | What it does |
|-----|-------------|
| `lint` | `flake8`, `black --check`, `isort --check-only`, `mypy` (`69` source files) |
| `test` | Migration-drift check + `pytest` (`90%` minimum coverage gate) + Codecov upload |
| `security` | `bandit -ll` (medium+ severity) + `pip-audit --strict` (production CVE check) |
| `terraform` | `terraform fmt -check -recursive` + `terraform init -backend=false` + `terraform validate` |
| `docker` | Multi-stage `docker build` + UID `1000` / read-only `/app` check + live `/api/v1/live/` & `/explorer/` CSP-nonce smoke test |
| `integration` | Live `postgres:16-alpine` + `redis:7-alpine` service containers running `migrate` + full `262`-test suite (`FOR UPDATE SKIP LOCKED LIMIT 1`, `pg_advisory_xact_lock`, RFC 9162 Merkle & DPO RLS replica routing, `ZlibCompressor`, `channels-redis`) |
| `build` (`deploy.yml`) | Keyless AWS OIDC auth → immutable SHA Docker image → push to ECR |
| `deploy` (`deploy.yml`) | Register new API revision → synchronous Fargate `migrate --noinput` gate → rolling ECS update (`api`, `celery-worker`, `celery-beat`) → `warm_cache` → CloudFront/ALB healthcheck |

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
