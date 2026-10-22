# Changelog

All notable changes to this project will be documented in this file.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html)

---

## [1.5.0] — 2026-10-22

### Added
- **Transactional Outbox Pattern for Webhooks & Pub/Sub (`apps/core/models.py`, `apps/core/outbox.py`, `apps/tasks/tasks.py`, `apps/tasks/views.py`, `apps/tasks/consensus.py`, `config/settings/base.py`)**:
  - Added indexed `OutboxEvent` model (`core_outbox_pending_idx`) written atomically inside business `transaction.atomic()` blocks across task creation, bulk ingestion, status completion, IAA consensus auto-completion, adjudication, and async translation—guaranteeing zero phantom webhooks on rollback and zero lost events during Redis/Celery broker blips.
  - Added `drain_outbox_batch` / `drain_outbox_events` (`SELECT ... FOR UPDATE SKIP LOCKED` concurrent worker relay, stale `processing` reclamation, exponential retry backoff up to `MAX_OUTBOX_ATTEMPTS = 10`, preserved W3C `traceparent` distributed trace linkage) plus a 15-second `CELERY_BEAT_SCHEDULE` sweep.
- **PostgreSQL 16 Row-Level Security (RLS) Defense-in-Depth (`apps/core/rls.py`, `apps/tasks/migrations/0005_postgres_rls_policies.py`, `tests/integration/test_postgres_redis_integration.py`)**:
  - Enabled `ENABLE ROW LEVEL SECURITY` + `FORCE ROW LEVEL SECURITY` policies (`USING` & `WITH CHECK`) across `tasks_task`, `core_organizationapikey`, `core_webhookendpoint`, and `core_outboxevent`, alongside a dedicated `mltask_rls_app` (`NOSUPERUSER NOBYPASSRLS`) runtime role.
  - Added `PostgresRLSMiddleware`, `rls_context`, and `rls_bypass` synchronizing `app.rls_enforced`, `app.current_organization_id`, `app.current_user_id`, and `app.rls_bypass` lazily via memoized PostgreSQL session `set_config` calls with automatic connection-pool reset on exit.
- **Single-Query JWT Request Memoization & Node 24 GitHub Actions Modernization (`apps/core/authentication.py`, `apps/core/middleware.py`, `.github/workflows/ci.yml`, `.github/workflows/deploy.yml`)**:
  - Added `CachedJWTAuthentication` (`CachedJWTScheme`) and request-scoped principal memoization eliminating duplicate `SELECT core_user` queries per JWT request (`GET /api/v1/tasks/` reduced from 5 to 4 SQL queries).
  - Upgraded CI and ECS deploy workflows to native Node 24 actions (`actions/checkout@v6`, `actions/setup-python@v6`, `actions/upload-artifact@v6`, `hashicorp/setup-terraform@v4`, `codecov/codecov-action@v6`, `aws-actions/configure-aws-credentials@v6`).

---

## [1.4.0] — 2026-10-22

### Added
- **Live PostgreSQL 16 & Redis 7 CI Service-Container Integration Matrix (`config/settings/ci_integration.py`, `.github/workflows/ci.yml`, `tests/integration/test_postgres_redis_integration.py`, `Makefile`)**:
  - Added `integration` job in `.github/workflows/ci.yml` (`postgres:16-alpine` + `redis:7-alpine`) and `make test-integration` executing `manage.py migrate` plus all `215` tests against real PostgreSQL 16, `django-redis` (`ZlibCompressor` + `JSONSerializer` + atomic `INCRBY`), Redis Pub/Sub (`EventPublisher`), and `channels_redis.core.RedisChannelLayer` WebSockets.
  - Added multi-connection `SELECT ... FOR UPDATE SKIP LOCKED LIMIT 1` contention & 8-annotator `Barrier` stampede tests verifying non-blocking, zero-duplicate RLHF task leasing on PostgreSQL 16.
- **Cluster-Wide Redis-Coordinated Single-Flight `CircuitBreaker` (`apps/ai_assist/circuit_breaker.py`, `apps/core/tests/test_distributed_cb_and_claim_sql.py`)**:
  - Upgraded `CircuitBreaker` (`shared_cache=True` on `openai_circuit_breaker`) to synchronize failure counters, `OPEN` windows, and atomic `cache.add` single-flight `HALF_OPEN` recovery probes across all Gunicorn/Celery worker processes via Redis with automatic thread-safe in-memory fallback.

### Fixed
- **Single-Row `LIMIT 1 FOR UPDATE SKIP LOCKED` Task Leasing (`apps/tasks/views.py`)**:
  - Updated `TaskViewSet.claim` to lock `LIMIT 1` ordered by `(-priority_rank, created_at)` instead of locking the entire candidate batch at once, eliminating false `204 No Content` starvation under concurrent annotator contention and removing a redundant candidate queryset evaluation.

---

## [1.3.2] — 2026-10-22

### Added
- **CloudFront AWS WAFv2 Edge Protection (`terraform/main.tf`, `terraform/variables.tf`, `terraform/outputs.tf`)**:
  - Provisioned `aws_wafv2_web_acl.cdn` via an explicit `aws.us_east_1` provider alias (`enable_waf = true`, `waf_rate_limit_per_5m = 2000`) combining `RateLimitPerIP`, `AWSManagedRulesAmazonIpReputationList`, and `AWSManagedRulesCommonRuleSet` with `SizeRestrictions_BODY` overridden to `count` so >8 KB RLHF prompts and `/api/v1/tasks/bulk/` batches are never false-positively blocked at the CDN edge.
- **CloudFront-to-ALB Origin Cloaking (`terraform/main.tf`, `terraform/variables.tf`, `.github/workflows/deploy.yml`, `Makefile`)**:
  - Added sensitive `origin_verify_secret` injecting `X-Origin-Verify` on CloudFront's ALB origin while switching ALB default listener actions to `403 Forbidden` unless `X-Origin-Verify` matches, eliminating direct-to-ALB WAF bypasses; updated `make sync-github-vars` and `deploy.yml` to support `CLOUDFRONT_DOMAIN` edge healthchecks.
- **CI Production Container Build & Live Smoke Gate (`.github/workflows/ci.yml`, `apps/core/tests/test_edge_waf_and_container_security.py`)**:
  - Added `docker` CI job building the production multi-stage image and verifying UID `1000`, read-only `/app`, bundled `docs/api-explorer.html` & `staticfiles/admin`, live `GET /api/v1/live/` (`200`), and `GET /explorer/` CSP `'nonce-...'` header (`207` pytest tests passing).

### Fixed
- **Production Container `/explorer/` Asset Packaging & Runtime Hardening (`.dockerignore`, `Dockerfile`)**:
  - Excluded `.git/` and replaced bare `docs/` in `.dockerignore` with `docs/*` + `!docs/api-explorer.html` so `GET /explorer/` never raises `FileNotFoundError` in standalone ECR/ECS containers without host volume mounts.
  - Hardened `Dockerfile` with pinned `python:3.12-slim-bookworm`, `--shell /usr/sbin/nologin` `appuser`, `root:root` read-only `/app`, build-time `collectstatic --noinput`, and `--worker-tmp-dir /dev/shm`.

---

## [1.3.1] — 2026-10-22

### Added
- **Terraform GitHub OIDC Federation (`terraform/main.tf`, `terraform/variables.tf`, `terraform/outputs.tf`)**:
  - Provisioned `aws_iam_openid_connect_provider.github` (with `create_github_oidc_provider` / `existing_github_oidc_provider_arn` toggle for multi-repo AWS accounts) and `aws_iam_role.github_actions_deploy` (`github_actions_role_arn` output -> `AWS_ROLE_ARN`) scoped to `repo:MPadberg-svg/multilingual-task-api:*` with `iam:PassRole` strictly restricted to the ECS execution & task roles (`iam:PassedToService = ecs-tasks.amazonaws.com`).
- **Singleton ECS Fargate Celery Beat Service & Telemetry Wiring (`terraform/main.tf`, `terraform/outputs.tf`)**:
  - Provisioned `aws_ecs_task_definition.celery_beat` (`django_celery_beat.schedulers:DatabaseScheduler`) and `aws_ecs_service.celery_beat` (`desired_count = 1`, `deployment_minimum_healthy_percent = 0`, `deployment_maximum_percent = 100`) plus `ecs_celery_beat_service_name` / `ecs_celery_beat_task_family` outputs and `OTEL_EXPORTER_OTLP_ENDPOINT` / `METRICS_TOKEN` environment & secret wiring.
- **CI Terraform Validation & GitHub Variable Sync (`Makefile`, `.github/workflows/ci.yml`, `apps/core/tests/test_terraform_iac_and_deploy.py`)**:
  - Added `terraform` CI job (`hashicorp/setup-terraform@v3`: `terraform fmt -check`, `terraform init -backend=false`, `terraform validate`), `make tf-fmt` / `make tf-validate` / `make sync-github-vars`, and IaC/deployment contract tests.

### Fixed
- **CloudFront Edge Header Forwarding (`terraform/main.tf`)**:
  - Added `X-API-Key`, `Idempotency-Key`, and `traceparent` to `aws_cloudfront_distribution.cdn`'s `forwarded_values.headers` so M2M authentication, idempotent mutations, and W3C distributed trace propagation are never stripped at the CDN edge.
- **Zero-Downtime ECS Migration Ordering (`.github/workflows/deploy.yml`)**:
  - Registered the new `$IMAGE` API task definition revision (`NEW_API_TASK_DEF_ARN`) *before* executing the synchronous `manage.py migrate --noinput` Fargate task so newly shipped migrations in commit `N` execute prior to updating live ECS services while still aborting cleanly before service rollout if migration fails.

---

## [1.3.0] — 2026-10-22

### Added
- **Composite Keyset Cursor Pagination (`apps/core/pagination.py`)**:
  - Added `KeysetCursorPagination` (`ordering = ("-created_at", "-id")`) integrated into `StandardResultsSetPagination` so `/api/v1/tasks/` and `/api/v1/organizations/{id}/audit-logs/` transparently switch to `$O(1)$` keyset index seeks when `?pagination=cursor` or `?cursor=...` is supplied, emitting `X-Pagination-Mode: cursor|offset` while preserving 100% backward compatibility with standard offset pagination.
- **W3C Trace Context & OpenTelemetry OTLP/HTTP Exporter (`apps/core/tracing.py`)**:
  - Implemented spec-compliant W3C `traceparent` parsing/generation and vendor-neutral OTLP/HTTP JSON span export (`OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_EXPORTER_OTLP_HEADERS`, `OTEL_SERVICE_NAME`) with zero external protobuf/gRPC dependencies.
  - Propagated `trace_id` and parent/child `span_id` across Django HTTP requests (`CorrelationIdMiddleware` + `X-Trace-ID` / `traceparent` headers + structured JSON logs), Celery producer/worker tasks (`config/celery.py` signals), OpenAI completions (`gen_ai.usage.*` attributes), and outbound signed webhook HTTP POSTs.
- **AWS ECS OIDC Keyless Deployment & CI Modernization (`.github/workflows/deploy.yml`, `.github/workflows/ci.yml`)**:
  - Added GitHub OIDC role federation (`AWS_ROLE_ARN` + `id-token: write`) with automatic fallback to static IAM credentials, added rolling deployment support for `ECS_CELERY_BEAT_SERVICE`, and opted workflows into Node 24 (`FORCE_JAVASCRIPT_ACTIONS_TO_NODE24=true`).

---

## [1.2.0] — 2026-10-22

### Added
- **Wave 1 — Self-Serve Multi-Tenancy, Auth Lifecycle & Idempotency**:
  - `GET/PATCH /api/v1/auth/me/` returning user profile and active organization memberships.
  - `POST /api/v1/auth/logout/` enforcing caller ownership check, SimpleJWT refresh-token blacklisting, and `AuditLog` persistence.
  - `/api/v1/organizations/` CRUD, `/members/` invite/role-update/removal with `Organization.max_users` seat enforcement, last-owner protection, privilege-escalation blocks, and filterable `/audit-logs/`.
  - `IdempotencyKeyMiddleware` (`24h` Redis TTL, `30s` atomic in-flight lock returning `409 Conflict`, and SHA-256 body-hash verification returning `422 Unprocessable Entity`).
- **Wave 2 — RLHF Task Leasing, Structured Annotations, IAA Consensus, Bulk & Streaming Export**:
  - `POST /api/v1/tasks/claim/` atomic priority-ordered task leasing (`SELECT ... FOR UPDATE SKIP LOCKED` on PostgreSQL) localized via `Accept-Language`.
  - `TaskAnnotation` model + `GET/POST /api/v1/tasks/{id}/annotations/` with preference choices (`response_a`, `response_b`, `tie`), `1–5` rubric validation, and automatic Inter-Annotator Agreement (`evaluate_task_consensus`) completion vs. split-vote detection.
  - `POST /api/v1/tasks/{id}/adjudicate/` allowing organization `admin`/`owner` roles to resolve split votes.
  - `POST /api/v1/tasks/bulk/` atomic batch ingestion (up to 100 tasks, enforcing `Organization.max_tasks`) and `GET /api/v1/tasks/export/?format=jsonl` (`StreamingHttpResponse` NDJSON dataset stream).
- **Wave 3 — Async Auto-Translation & AI FinOps Telemetry**:
  - `auto_translate=true` flag on task creation scheduling `generate_task_translations.delay(...)` via `transaction.on_commit` and broadcasting real-time `translated` WebSocket & webhook events.
  - Per-tenant and global OpenAI `prompt_tokens`, `completion_tokens`, and estimated USD cost accounting exposed at `/api/v1/organizations/{id}/usage/` and `/api/v1/metrics/`.
- **Wave 4 — Scoped M2M API Keys, SSRF-Hardened HMAC Webhooks & Live `/explorer/` Console**:
  - Prefix-indexed, SHA-256-hashed `OrganizationAPIKey` (`mlk_live_<prefix>_...`) supporting `X-API-Key` / `Authorization: Api-Key`, expiration, immediate revocation, and granular scopes (`tasks:read`, `tasks:write`, `tasks:export`, `ai:write`).
  - `WebhookEndpoint` & `WebhookDelivery` with literal IP + DNS-rebinding SSRF protection, non-redirecting TLS transport, `X-MLTask-Signature-256: sha256=<hmac>` signing, automatic circuit-breaking after 10 failures, and Celery exponential-backoff retries.
  - Mounted `/explorer/` live operations console protected by per-request cryptographic CSP nonces (`'nonce-...'`) and live `/ws/tasks/` WebSocket streaming.

### Removed
- Deleted unused orphaned `tests/conftest.py` and `tests/factories.py`, replacing unused `factory-boy` with explicit `Faker` in `requirements-dev.txt`.

---

## [1.1.0] — 2026-10-22

### Added & Hardened
- Upgraded runtime stack to Django `5.2.18` LTS, DRF `3.17.1`, Celery `5.6.3`, Strawberry `0.314.1`, OpenAI `2.31.0`, and Pydantic `2.13.3` with zero production CVEs (`pip-audit --strict`).
- Hardened JWT blacklisting, constant-time `METRICS_TOKEN` protection on `/api/v1/metrics/`, first-message WebSocket JWT authentication with `AllowedHostsOriginValidator`, single-flight OpenAI circuit breaker, and Pydantic v2 structured LLM output schemas.
- Provisioned ECS Celery worker/beat infrastructure in Terraform and validated GitHub Actions CI/CD (`178` tests, `91.56%` coverage).

---

## [1.0.0] — 2026-05-21

### Added
- Initial release with `CustomUser` (UUID), `Organization`, `django-parler` EN/ES/FR `Task` CRUD, Redis caching, Celery tasks, Channels WebSocket consumer, Strawberry GraphQL, OpenAI integration, and AWS ECS Terraform IaC.
