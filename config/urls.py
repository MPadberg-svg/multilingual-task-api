"""Root URL configuration for the multilingual task API."""

from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/v1/", include("apps.core.urls")),
    path("api/v1/tasks/", include("apps.tasks.urls")),
    path("api/v1/ai/", include("apps.ai_assist.urls")),
]
