"""Django signals for task lifecycle events.

Automatically publishes Redis events on ``post_save`` and ``post_delete``
for the ``Task`` model.
"""

from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver

from apps.core.events import EventPublisher
from apps.tasks.models import Task


@receiver(post_save, sender=Task)
def task_post_save(sender, instance, created, **kwargs):
    """Publish a task created/updated event after save.

    Args:
        sender: ``Task`` model class.
        instance: Saved task instance.
        created: True if the instance was created.
        **kwargs: Signal kwargs.
    """
    publisher = EventPublisher()
    action = "created" if created else "updated"
    org_id = str(instance.organization.id) if instance.organization else "global"
    publisher.publish_task_event(
        org_id,
        action,
        {
            "id": str(instance.id),
            "status": instance.status,
            "user_id": str(instance.user.id),
        },
    )


@receiver(post_delete, sender=Task)
def task_post_delete(sender, instance, **kwargs):
    """Publish a task deleted event after hard delete.

    Note:
        Soft deletes (``instance.delete()``) trigger ``post_save`` with
        ``is_active=False`` rather than ``post_delete``. This receiver
        handles true hard-deletion scenarios.

    Args:
        sender: ``Task`` model class.
        instance: Deleted task instance.
        **kwargs: Signal kwargs.
    """
    publisher = EventPublisher()
    org_id = str(instance.organization.id) if instance.organization else "global"
    publisher.publish_task_event(
        org_id,
        "deleted",
        {
            "id": str(instance.id),
            "status": instance.status,
            "user_id": str(instance.user.id),
        },
    )