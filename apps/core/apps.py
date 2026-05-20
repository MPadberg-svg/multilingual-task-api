"""App configuration for the core platform application."""

from django.apps import AppConfig


class CoreConfig(AppConfig):
    """Configuration class for the core Django application.

    Attributes:
        default_auto_field: Default primary key field type.
        name: Full Python path to the application.
        verbose_name: Human-readable name for the admin interface.
    """

    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.core"
    verbose_name = "Core Platform"