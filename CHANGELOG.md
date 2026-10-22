# Changelog

All notable changes to this project will be documented in this file.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html)

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
