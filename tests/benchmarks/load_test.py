"""Locust load-test suite for the multilingual task API.

Defines two user classes:

* ``TaskAPIUser`` (weight=3) — simulates standard CRUD traffic with
  multilingual headers. 70 % list, 20 % create, 10 % delete.
* ``AIAssistUser`` (weight=1) — simulates AI endpoint traffic at a
  deliberately slow pace (3–6 min wait) to respect the 20/hour throttle.

Run with::

    locust -f tests/benchmarks/load_test.py --host=http://localhost:8000

"""

import random

from locust import HttpUser, between, task


class TaskAPIUser(HttpUser):
    """Simulates a typical task-management API consumer."""

    wait_time = between(1, 3)
    weight = 3

    def on_start(self):
        """Authenticate before the user begins issuing requests."""
        self.client.post(
            "/api/v1/auth/token/",
            json={"username": "loadtest", "password": "testpass123"},
        )

    @task(70)
    def list_tasks(self):
        """List tasks with a random language header."""
        lang = random.choice(["en", "es", "fr"])
        self.client.get(
            "/api/v1/tasks/",
            headers={"Accept-Language": lang},
            name="/api/v1/tasks/",
        )

    @task(20)
    def create_task(self):
        """Create a task with a random active language."""
        lang = random.choice(["en", "es", "fr"])
        self.client.post(
            "/api/v1/tasks/",
            json={
                "translations": {
                    lang: {
                        "title": "Load Test",
                        "description": "Benchmark task",
                    }
                },
                "status": "pending",
            },
            headers={"Accept-Language": lang},
            name="/api/v1/tasks/",
        )

    @task(10)
    def delete_task(self):
        """Delete the first task returned by a list call."""
        response = self.client.get(
            "/api/v1/tasks/",
            headers={"Accept-Language": "en"},
            name="/api/v1/tasks/",
        )
        if response.status_code == 200:
            data = response.json()
            if isinstance(data, list) and len(data) > 0:
                task_id = data[0]["id"]
                self.client.delete(
                    f"/api/v1/tasks/{task_id}/",
                    name="/api/v1/tasks/{id}/",
                )


class AIAssistUser(HttpUser):
    """Simulates an AI-assistance API consumer.

    The long ``wait_time`` (3–6 minutes) ensures the 20/hour throttle is
    not triggered under normal load.
    """

    wait_time = between(180, 360)  # 3–6 minutes to respect 20/hour
    weight = 1

    def on_start(self):
        """Authenticate before the user begins issuing requests."""
        self.client.post(
            "/api/v1/auth/token/",
            json={"username": "loadtest", "password": "testpass123"},
        )

    @task(50)
    def suggest_task(self):
        """Request AI-generated task translations."""
        self.client.post(
            "/api/v1/ai/suggest-task/",
            json={
                "description": (
                    "Generate a task about machine learning data " "annotation with edge cases"
                )
            },
            name="/api/v1/ai/suggest-task/",
        )

    @task(50)
    def evaluate_quality(self):
        """Request a prompt-quality evaluation."""
        self.client.post(
            "/api/v1/ai/evaluate-quality/",
            json={"prompt_text": "Explain quantum computing to a 5-year-old"},
            name="/api/v1/ai/evaluate-quality/",
        )
