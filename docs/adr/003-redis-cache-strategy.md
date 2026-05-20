ADR-003: Redis Cache Strategy
Status: Accepted
Date: 2024-05-15
Context
Need sub-100ms response times for task list and detail endpoints under 50+ concurrent users. Evaluated cache-aside vs write-through vs read-through patterns.
Decision
Cache-aside pattern with language-specific keys and explicit TTLs.
Key convention: mltask:{prefix}:{user_id}:{lang}:{params}
TTLs:
task_list: 300s (5 min)
task_detail: 600s (10 min)
translations: 1800s (30 min)
ai_suggestions: 3600s (1 hour)
Consequences
Positive:
Simplicity: Straightforward invalidation in perform_create/update/destroy.
Django-native: Uses django-redis with standard cache.set/cache.get API.
Fine-grained invalidation: Per-user, per-language cache isolation prevents cross-tenant leakage.
Negative:
Stale data risk: TTL-based expiry means up to 10 minutes of stale detail data; acceptable for this domain.
Cold start on deploy: Empty cache after deployment; mitigated by warm_cache management command.
Thundering herd: High-traffic keys may see concurrent DB hits; mitigated by short TTLs and cache warming.