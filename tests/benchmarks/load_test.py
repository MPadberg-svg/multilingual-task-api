"""Locust load-test suite for the multilingual task API.

Authenticates via ``email`` + ``password`` against ``/api/v1/auth/token/``,
attaches the returned SimpleJWT ``Bearer`` access token to subsequent requests,
and parses paginated DRF list responses.

Run with::

    locust -f tests/benchmarks/load_test.py --host=http://localhost:8000
"""

from __future__ import annotations

import os
import random

from locust import HttpUser, between, task

LOADTEST_EMAIL = os.environ.get("LOADTEST_EMAIL", "demo0@example.com")
LOADTEST_PASSWORD = os.environ.get("LOADTEST_PASSWORD", "demo123")  # noqa: S105


def _authenticate(client: object) -> dict[str, str]:
    """Obtain JWT Bearer header for a Locust HttpUser client."""
    http_client: Any = client
    resp = http_client.post(
        "/api/v1/auth/token/",
        json={"email": LOADTEST_EMAIL, "password": LOADTEST_PASSWORD},
        name="/api/v1/auth/token/",
    )
    if resp.status_code == 200:
        token = resp.json().get("access", "")
        if token:
            return {"Authorization": f"Bearer {token}"}
    return {}


from typing import Any  # noqa: E402


class TaskAPIUser(HttpUser):
    """Simulates a typical task-management API consumer."""

    wait_time = between(1, 3)
    weight = 3
    auth_headers: dict[str, str] = {}

    def on_start(self) -> None:
        """Authenticate before the user begins issuing requests."""
        self.auth_headers = _authenticate(self.client)

    @task(70)
    def list_tasks(self) -> None:
        """List tasks with a random language header."""
        lang = random.choice(["en", "es", "fr"])
        self.client.get(
            "/api/v1/tasks/",
            headers={**self.auth_headers, "Accept-Language": lang},
            name="/api/v1/tasks/",
        )

    @task(20)
    def create_task(self) -> None:
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
            headers={**self.auth_headers, "Accept-Language": lang},
            name="/api/v1/tasks/",
        )

    @task(10)
    def delete_task(self) -> None:
        """Soft-delete the first task returned by a paginated list call."""
        response = self.client.get(
            "/api/v1/tasks/",
            headers={**self.auth_headers, "Accept-Language": "en"},
            name="/api/v1/tasks/",
        )
        if response.status_code == 200:
            data = response.json()
            results = data.get("results", []) if isinstance(data, dict) else []
            if results:
                task_id = results[0]["id"]
                self.client.delete(
                    f"/api/v1/tasks/{task_id}/",
                    headers=self.auth_headers,
                    name="/api/v1/tasks/{id}/",
                )


class AIAssistUser(HttpUser):
    """Simulates an AI-assistance API consumer respecting 20/hour throttle."""

    wait_time = between(180, 360)
    weight = 1
    auth_headers: dict[str, str] = {}

    def on_start(self) -> None:
        """Authenticate before the user begins issuing requests."""
        self.auth_headers = _authenticate(self.client)

    @task(50)
    def suggest_task(self) -> None:
        """Request AI-generated task translations."""
        self.client.post(
            "/api/v1/ai/suggest-task/",
            json={"description": "Generate a task about ML data annotation with edge cases"},
            headers=self.auth_headers,
            name="/api/v1/ai/suggest-task/",
        )

    @task(50)
    def evaluate_quality(self) -> None:
        """Request a prompt-quality evaluation."""
        self.client.post(
            "/api/v1/ai/evaluate-quality/",
            json={"prompt_text": "Explain quantum computing to a 5-year-old"},
            headers=self.auth_headers,
            name="/api/v1/ai/evaluate-quality/",
        )
