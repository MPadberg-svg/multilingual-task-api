# Changelog

All notable changes to this project will be documented in this file.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html)

---

## [1.9.0] — 2026-10-24

### Added
- **External Anchoring & S3 Object-Lock WORM Audit Checkpointing (`apps/core/audit_chain.py`, `apps/core/models.py`, `apps/core/tenant_views.py`, `apps/tasks/tasks.py`, `apps/tasks/migrations/0011_postgres_rls_v190_checkpoints.py`)**:
  - Added `AuditChainCheckpoint` (`FORCE ROW LEVEL SECURITY` + ORM immutability guards) notarizing periodic snapshots of each tenant's `AuditLog` hash chain with domain-separated `HMAC-SHA256` signatures (`AUDIT_ANCHOR_SIGNING_KEY`), `audit.checkpoint_anchored` Outbox events, and zero-dependency AWS Signature Version 4 HTTPS `PUT` archival to Amazon S3 Object Lock (`COMPLIANCE` mode, `Content-MD5` + `x-amz-object-lock-retain-until-date`).
  - Added `GET/POST /api/v1/organizations/{org_id}/audit-logs/checkpoints/`, hourly Celery Beat sweep `anchor_audit_chain_checkpoints`, and upgraded `/audit-logs/verify/` to cross-check checkpoint signatures and historical prefix hashes (`checkpoint_anchor_divergence`, `checkpoint_signature_mismatch`)—detecting even privileged DB full-chain rewrite or tail-truncation attacks.
- **Adaptive Difficulty & Multi-Dimensional Domain/Language Skill Vectors (`apps/tasks/models.py`, `apps/tasks/calibration.py`, `apps/tasks/consensus.py`, `apps/tasks/filters.py`, `apps/tasks/views.py`)**:
  - Added `Task.domain` (`general`, `code`, `math`, `medical`, `legal`, `creative`, `safety`) and `Task.difficulty` (`standard`, `hard`, `expert`) plus per-language and per-domain Bayesian calibration vectors (`language_skill_vectors`, `domain_skill_vectors`) on `AnnotatorCalibration`.
  - Upgraded `POST /api/v1/tasks/claim/` with automatic `specialist_rank` routing for calibrated domain specialists and probation gating (`skill_weight < 0.70`) on `difficulty="expert"` production tasks, blended specialist + baseline weights in `evaluate_task_consensus`, and added `?domain=...&language=...` specialist filtering on `/annotators/calibration/`.
- **Terraform S3 WORM Bucket, Multi-Metric Autoscaling & CloudWatch-Gated Canary Rollouts (`terraform/main.tf`, `terraform/variables.tf`, `terraform/outputs.tf`)**:
  - Provisioned AES-256 encrypted, public-blocked `aws_s3_bucket.audit_worm` with `COMPLIANCE` Object Lock (`enable_audit_worm_bucket`, `audit_worm_retention_days`) and least-privilege `ecs_task` IAM policy wired to `AUDIT_WORM_S3_BUCKET`.
  - Added `ALBRequestCountPerTarget` autoscaling (`aws_appautoscaling_policy.alb_requests`), Celery worker autoscaling (`aws_appautoscaling_target.celery_worker` + `celery_cpu`), ECS `deployment_circuit_breaker` + CloudWatch `alarms` automatic canary rollback on `aws_ecs_service.api`, and `aws_cloudwatch_composite_alarm.canary_rollout_guard`.

---

## [1.8.0] — 2026-10-24

### Added
- **Cryptographic Audit Log Hash-Chaining & Tamper Verification (`apps/core/audit_chain.py`, `apps/core/models.py`, `apps/core/tenant_views.py`, `apps/core/migrations/0006_v180_audit_chain_and_gold_calibration.py`)**:
  - Sealed every `AuditLog` record at insert time with a strictly monotonic per-tenant `chain_seq`, `prev_hash` (`"0" * 64` at genesis), and canonical SHA-256 `entry_hash`, serialized under concurrent PostgreSQL 16 writers via `pg_advisory_xact_lock(hashtext(...))`, enforced `ValidationError` immutability on `save()`/`delete()`, and added an automatic migration backfill for pre-existing audit rows.
  - Added replica-routed `GET /api/v1/organizations/{org_id}/audit-logs/verify/` returning `valid`, `verified_entries`, `head_hash`, `manifest_digest`, and detailed tamper diagnostics (`entry_hash_mismatch`, `prev_hash_mismatch`, `sequence_gap`) for SOC 2 Type II / ISO 27001 evidence exports.
- **Annotator Calibration Gold-Tasks & Dynamic Skill-Weighted Consensus (`apps/tasks/calibration.py`, `apps/tasks/consensus.py`, `apps/tasks/models.py`, `apps/tasks/serializers.py`, `apps/tasks/views.py`, `apps/tasks/migrations/0009_postgres_rls_v180_calibration.py`)**:
  - Added `is_gold` and `gold_choice` on `Task` (`admin`/`owner` RBAC write guard, zero-query blind redaction + separate `adm:` Redis cache namespace so non-admin annotators never observe gold metadata, and default gold exclusion from `/tasks/export/`) plus PostgreSQL 16 `FORCE ROW LEVEL SECURITY`-protected `AnnotatorCalibration`.
  - Integrated automatic blind gold-task injection into `POST /api/v1/tasks/claim/` (prioritized for uncalibrated annotators and periodic 5-task spot checks), reusable lease release + immediate Jeffreys `Beta(0.5, 0.5)` Bayesian `skill_weight` scoring (`annotator.calibrated` Outbox event + `gold_task_evaluated` audit log), empirical skill-weighted consensus in `evaluate_task_consensus`, and replica-routed `GET /api/v1/organizations/{org_id}/annotators/calibration/`.
- **Terraform RDS Read-Replica, Outbox Dead-Letter Telemetry & CloudWatch Alarms (`terraform/main.tf`, `terraform/variables.tf`, `terraform/outputs.tf`, `apps/core/outbox.py`, `apps/core/views.py`)**:
  - Added optional encrypted `aws_db_instance.postgres_replica` (`enable_read_replica`, `db_replica_instance_class`) wired into ECS `POSTGRES_REPLICA_HOST` and exported as `rds_replica_endpoint`.
  - Added structured `"Outbox event moved to dead-letter"` logging + Prometheus `mltask_outbox_pending_events` / `mltask_outbox_dead_letter_events` gauges on `/api/v1/metrics/`, plus CloudWatch Log Metric Filter and Alarms (`OutboxDeadLetterCount`, RDS `ReplicaLag`, primary RDS `CPUUtilization`, and ALB `HTTPCode_Target_5XX_Count`) wired to optional `alert_sns_topic_arn`.

---

## [1.7.0] — 2026-10-22

### Added
- **Enterprise OIDC SSO Token Exchange & RFC 7643/7644 SCIM 2.0 Provisioning (`apps/core/sso.py`, `apps/core/models.py`, `apps/core/tenant_views.py`, `config/urls.py`)**:
  - Added `OrganizationSSOConfig` (`FORCE ROW LEVEL SECURITY` protected) with HTTPS issuer enforcement, pinned JWKS/PEM asymmetric `RS256`/`ES256` signature verification (blocking `alg=none` and `HS256` key-confusion payloads), domain allowlists, and IdP group-to-RBAC role mapping (`viewer`, `contributor` / `annotator` / `reviewer`, `admin`, preserving existing `owner` roles).
  - Added `POST /api/v1/auth/sso/oidc/exchange/`, `GET/PATCH /api/v1/organizations/{org_id}/sso/`, `POST /api/v1/organizations/{org_id}/sso/scim-token/`, and RFC 7643/7644 SCIM 2.0 `/api/v1/organizations/{org_id}/scim/v2/Users` & `/Users/{member_id}` supporting `userName`/`externalId` filtering, `PatchOp` updates, multi-tenant-safe `active=false` offboarding with automatic tenant API key revocation, and `scim.user_provisioned` / `scim.user_deprovisioned` Transactional Outbox events.
- **Per-Tenant AI Token Budget Quotas & Spend Alerts (`apps/core/finops.py`, `apps/core/models.py`, `apps/ai_assist/services.py`, `apps/ai_assist/views.py`, `apps/tasks/tasks.py`)**:
  - Added `AIUsageLog` (`FORCE ROW LEVEL SECURITY` protected) and per-organization `monthly_ai_token_budget`, `monthly_ai_cost_budget_microusd`, and `ai_budget_alert_threshold_pct` overrides backed by plan-tier defaults (`AI_PLAN_MONTHLY_TOKEN_BUDGETS`, `AI_PLAN_MONTHLY_COST_MICROUSD`) and Redis-cached SQL rollups.
  - Enforced pre-call `AIBudgetExceededError` (`429 Too Many Requests`, `code="ai_budget_exceeded"`) on uncached AI Assist calls, graceful skip in Celery `generate_task_translations`, deduplicated once-per-period `ai.budget_threshold_reached` and `ai.budget_exceeded` Transactional Outbox alerts, and `GET/PATCH /api/v1/organizations/{org_id}/finops/`.
- **RLS-Aware Read-Replica Query Routing for Analytics & Exports (`apps/core/db_router.py`, `apps/core/rls.py`, `apps/tasks/views.py`, `config/settings/`)**:
  - Added `ReplicaDatabaseRouter` and `use_read_replica()` steering `GET /api/v1/tasks/stats/`, streaming `GET /api/v1/tasks/export/`, `GET /api/v1/organizations/{org_id}/usage/`, and `GET /api/v1/organizations/{org_id}/finops/` to `DATABASES["replica"]` (`POSTGRES_REPLICA_HOST`, emitting `X-Query-Target: replica | primary`) while pinning writes and `in_atomic_block` read-your-own-writes transactions to `default`.
  - Extended `PostgresRLSMiddleware`, `rls_context`, and `rls_bypass` (plus lazy NDJSON export streaming) to synchronize PostgreSQL 16 RLS session GUCs onto `connections["replica"]` with deterministic connection-pool scrub on exit.

---

## [1.6.0] — 2026-10-22

### Added
- **Outbox Dead-Letter Admin Replay & Bounded-Chunk Retention Pruning (`apps/core/outbox.py`, `apps/core/tenant_views.py`, `apps/tasks/tasks.py`, `config/urls.py`)**:
  - Added `GET /api/v1/organizations/{org_id}/outbox/` (filterable by `status` and `topic`) and `POST /api/v1/organizations/{org_id}/outbox/{event_id}/replay/` resetting `failed` dead-letter outbox events for immediate relay with immutable `AuditLog` tracking (`outbox_replayed`).
  - Added `prune_outbox_and_webhook_history` / `prune_telemetry_and_outbox_history` (`OUTBOX_RETENTION_DAYS = 14`, `WEBHOOK_DELIVERY_RETENTION_DAYS = 30`) scheduled daily in `CELERY_BEAT_SCHEDULE`, deleting aged `dispatched` outbox rows and webhook delivery records in bounded primary-key batches while preserving all `pending`, `processing`, and `failed` rows.
- **PostgreSQL 16 `pg_trgm` GIN Trigram Search Acceleration (`apps/tasks/filters.py`, `apps/tasks/migrations/0006_postgres_pg_trgm_search_indexes.py`)**:
  - Installed PostgreSQL `pg_trgm` extension and GIN trigram indexes (`tasks_trans_title_trgm_idx`, `tasks_trans_desc_trgm_idx`) on `tasks_task_translation`.
  - Refactored `TaskFilter.filter_search` to a parameterized `EXISTS` semi-join with custom `TrigramILike` (`ILIKE` on PostgreSQL, `LIKE ... ESCAPE` on SQLite), eliminating 32-column `SELECT DISTINCT` cartesian fan-out and enabling `Bitmap Index Scan` execution plans verified via `EXPLAIN (FORMAT JSON)` on live PostgreSQL 16.
- **Plan-Tiered Organization Rate Limiting & Self-Serve Webhook Ops (`apps/core/throttling.py`, `apps/core/middleware.py`, `apps/core/tenant_views.py`)**:
  - Added `OrganizationPlanRateThrottle` enforcing dynamic per-tenant sliding-window quotas mapped from `organization.plan` (`free` `60/min`, `starter` `300/min`, `professional` `1200/min`, `enterprise` `6000/min`) and emitting `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`, and `X-RateLimit-Plan` headers.
  - Added `POST .../webhooks/{id}/recover/`, `GET .../webhooks/{id}/deliveries/`, and `POST .../webhooks/{id}/deliveries/{delivery_id}/replay/` with fresh HMAC signing and `AuditLog` trails.

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
