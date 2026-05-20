ADR-002: django-parler over JSONField for Translations
Status: Accepted
Date: 2024-05-15
Context
Need to store multilingual content with query performance requirements. Evaluated three approaches: JSONField (Django native), separate translation tables (manual), and django-parler (abstraction over separate tables).
Decision
Use django-parler TranslatableModel with a separate TaskTranslation table managed by the library.
Consequences
Positive:
Query performance: Database indexes on translated fields (title, description) via the separate table.
Referential integrity: Foreign key constraints between Task and TaskTranslation.
Django ORM compatibility: Standard queryset methods work with .filter(translations__title__icontains=...).
Admin integration: Built-in language tabs in Django admin.
Negative:
Migration complexity: Parler generates its own migrations; care needed when altering translation fields.
Additional JOINs: Every translated field access requires a JOIN; mitigated by prefetch_related('translations').
Learning curve: Team must understand parler's set_current_language() / safe_translation_getter() patterns.