ADR-001: UUID Primary Keys
Status: Accepted
Date: 2024-05-15
Context
Need to prevent ID enumeration attacks and support distributed systems where multiple services may create records independently without a central sequence coordinator.
Decision
Use UUID v4 as the primary key for all models (Task, Organization, OrganizationMember, AuditLog).
Consequences
Positive:
Security: No sequential enumeration possible; attackers cannot guess valid IDs.
Distributed: No central coordination required for ID generation across services.
Future-proof: Supports sharding and multi-region deployments natively.
Negative:
Index size: UUIDs consume 16 bytes vs 4–8 bytes for integers, slightly increasing index size.
Readability: Not human-readable; debugging requires copy-paste.
Sortability: UUID v4 is non-sequential; consider UUID v7 for time-sortable needs in future iterations.