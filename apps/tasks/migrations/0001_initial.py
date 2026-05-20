# Generated migration for tasks app

import django.db.models.deletion
import django.db.models.manager
import parler.fields
import parler.models
import uuid
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    """Initial migration for the tasks app.

    Creates the Task model with UUID primary key, soft-delete support,
    and the auto-generated TaskTranslation model via django-parler.
    """

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="Task",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("draft", "Draft"),
                            ("pending", "Pending"),
                            ("completed", "Completed"),
                            ("archived", "Archived"),
                        ],
                        db_index=True,
                        default="draft",
                        max_length=20,
                    ),
                ),
                (
                    "is_active",
                    models.BooleanField(db_index=True, default=True),
                ),
                (
                    "created_at",
                    models.DateTimeField(auto_now_add=True),
                ),
                (
                    "updated_at",
                    models.DateTimeField(auto_now=True),
                ),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="tasks",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "ordering": ["-created_at"],
                "verbose_name": "Task",
                "verbose_name_plural": "Tasks",
            },
            bases=(parler.models.TranslatableModelMixin, models.Model),
        ),
        migrations.CreateModel(
            name="TaskTranslation",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "language_code",
                    models.CharField(
                        db_index=True,
                        max_length=15,
                        verbose_name="Language",
                    ),
                ),
                (
                    "title",
                    models.CharField(
                        help_text="Localized title of the task.",
                        max_length=255,
                    ),
                ),
                (
                    "description",
                    models.TextField(
                        blank=True,
                        help_text="Localized description of the task.",
                    ),
                ),
                (
                    "master",
                    parler.fields.TranslationsForeignKey(
                        editable=False,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="translations",
                        to="tasks.task",
                    ),
                ),
            ],
            options={
                "verbose_name": "task Translation",
                "verbose_name_plural": "task Translations",
                "db_table": "tasks_task_translation",
                "managed": True,
                "abstract": False,
                "default_permissions": (),
            },
            bases=(parler.models.TranslatedFieldsModelMixin, models.Model),
        ),
        migrations.AddField(
            model_name="task",
            name="translations",
            field=parler.fields.TranslatedFields(
                to="tasks.tasktranslation",
            ),
        ),
        migrations.AddIndex(
            model_name="task",
            index=models.Index(
                fields=["user", "is_active", "status"],
                name="task_user_active_status_idx",
            ),
        ),
        migrations.AddIndex(
            model_name="task",
            index=models.Index(
                fields=["is_active", "created_at"],
                name="task_active_created_idx",
            ),
        ),
        migrations.AddConstraint(
            model_name="tasktranslation",
            constraint=models.UniqueConstraint(
                fields=["language_code", "master"],
                name="tasks_tasktranslation_language_code_master_",
            ),
        ),
    ]