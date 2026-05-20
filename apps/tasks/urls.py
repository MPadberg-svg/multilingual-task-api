"""URL routing for the Task API."""

from rest_framework.routers import DefaultRouter

from apps.tasks.views import TaskViewSet

router = DefaultRouter()
router.register("", TaskViewSet, basename="task")

urlpatterns = router.urls
