"""URL routing for the Task API.

Registers ``TaskViewSet`` with DefaultRouter to provide:
    - ``/api/v1/tasks/`` — list & create
    - ``/api/v1/tasks/{id}/`` — retrieve, update, delete
    - ``/api/v1/tasks/{id}/restore/`` — restore soft-deleted task
"""

from rest_framework.routers import DefaultRouter

from apps.tasks.views import TaskViewSet

router = DefaultRouter()
router.register(r"", TaskViewSet, basename="task")

urlpatterns = router.urls