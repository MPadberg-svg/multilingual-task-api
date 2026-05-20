"""URL routing for the AI Assistance API endpoints."""

from django.urls import path

from apps.ai_assist import views

urlpatterns = [
    path("suggest-task/", views.suggest_task, name="suggest-task"),
    path("evaluate-quality/", views.evaluate_quality, name="evaluate-quality"),
    path("generate-test-cases/", views.generate_test_cases, name="generate-test-cases"),
]