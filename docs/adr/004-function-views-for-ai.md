ADR-004: Function Views for AI Endpoints
Status: Accepted
Date: 2024-05-15
Context
AI endpoints (suggest-task, evaluate-quality, generate-test-cases) have unique rate limiting needs (per-user AI quotas) and distinct request/response contracts that do not map cleanly to standard REST resource semantics.
Decision
Use function-based views with explicit @api_view decorators instead of DRF ViewSet for AI endpoints.
Consequences
Positive:
Independent throttling: Each endpoint can declare its own throttle_classes (AIAssistRateThrottle, BurstRateThrottle).
Clear contracts: Explicit request/response schemas per endpoint via drf-spectacular @extend_schema.
No DRF serializer overhead: Direct service-layer calls avoid unnecessary serializer instantiation for simple string inputs.
Negative:
Less DRY: Repetitive auth/throttle/permission boilerplate across three endpoints.
Manual OpenAPI docs: Must explicitly decorate each view for Swagger generation.
URL routing: Manual path() entries in urls.py instead of DefaultRouter auto-registration.