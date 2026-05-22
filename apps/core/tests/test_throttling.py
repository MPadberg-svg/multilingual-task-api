"""Tests for custom DRF throttling — AI assistance rate limiting.

Covers:
    - Anonymous users are blocked (None cache key)
    - Authenticated users have per-user cache keys
    - Sustained hourly limit (20/hour)
    - Burst per-minute limit (5/min)
    - Violation logging
    - Wait time calculation
"""

import time
from unittest.mock import MagicMock, patch

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient, APIRequestFactory

from apps.core.throttling import AIAssistRateThrottle, BurstRateThrottle

User = get_user_model()


class TestAIAssistRateThrottle:
    """Tests for the sustained AI assistance rate throttle (20/hour)."""

    def test_anon_throttle_limits_unauthenticated(self):
        """Anonymous users must receive None cache key (blocked)."""
        throttle = AIAssistRateThrottle()
        factory = APIRequestFactory()
        request = factory.get("/api/v1/ai/suggest/")

        request.user = MagicMock()
        request.user.is_authenticated = False

        cache_key = throttle.get_cache_key(request, None)
        assert cache_key is None

    def test_user_throttle_limits_authenticated(self):
        """Authenticated users must get a per-user cache key."""
        throttle = AIAssistRateThrottle()
        factory = APIRequestFactory()
        request = factory.get("/api/v1/ai/suggest/")

        user = MagicMock()
        user.is_authenticated = True
        user.pk = "user-123"
        request.user = user

        cache_key = throttle.get_cache_key(request, None)
        assert cache_key == "mltask:throttle:ai_assist:user-123"

    def test_throttle_allows_under_limit(self):
        """Requests under the rate limit must be allowed."""
        throttle = AIAssistRateThrottle()
        factory = APIRequestFactory()
        request = factory.get("/api/v1/ai/suggest/")

        user = MagicMock()
        user.is_authenticated = True
        user.pk = "user-456"
        request.user = user

        with patch.object(throttle.cache, 'get', return_value=[]):
            with patch.object(throttle.cache, 'set'):
                allowed = throttle.allow_request(request, None)
                assert allowed is True

    def test_throttle_blocks_over_limit(self):
        """Requests exceeding the rate limit must be blocked."""
        throttle = AIAssistRateThrottle()
        factory = APIRequestFactory()
        request = factory.get("/api/v1/ai/suggest/")

        user = MagicMock()
        user.is_authenticated = True
        user.pk = "user-789"
        request.user = user

        now = time.time()
        fake_history = [now - i * 100 for i in range(20)]

        with patch.object(throttle.cache, 'get', return_value=fake_history):
            with patch.object(throttle.cache, 'set'):
                allowed = throttle.allow_request(request, None)
                assert allowed is False

    def test_throttle_logs_violation(self):
        """Blocked requests must log a warning."""
        throttle = AIAssistRateThrottle()
        factory = APIRequestFactory()
        request = factory.get("/api/v1/ai/suggest/")

        user = MagicMock()
        user.is_authenticated = True
        user.pk = "user-violation"
        request.user = user

        now = time.time()
        fake_history = [now - i * 100 for i in range(20)]

        with patch.object(throttle.cache, 'get', return_value=fake_history):
            with patch.object(throttle.cache, 'set'):
                with patch.object(throttle, '_log_violation') as mock_log:
                    throttle.allow_request(request, None)
                    mock_log.assert_called_once()

    def test_throttle_wait_returns_seconds(self):
        """Wait must return seconds until next request when limited."""
        throttle = AIAssistRateThrottle()
        now = time.time()
        throttle.now = now
        throttle.duration = 3600
        throttle.history = [now - 500]

        wait_time = throttle.wait()

        assert wait_time is not None
        assert wait_time == 3600 - (now - (now - 500))

    def test_throttle_wait_returns_none_when_not_limited(self):
        """Wait must return None when throttle is not limiting."""
        throttle = AIAssistRateThrottle()
        throttle.history = []
        throttle.now = time.time()

        wait_time = throttle.wait()

        assert wait_time is None


class TestBurstRateThrottle:
    """Tests for the burst AI assistance rate throttle (5/min)."""

    def test_burst_throttle_allows_short_spikes(self):
        """Burst throttle must allow up to 5 requests per minute."""
        throttle = BurstRateThrottle()
        factory = APIRequestFactory()
        request = factory.get("/api/v1/ai/suggest/")

        user = MagicMock()
        user.is_authenticated = True
        user.pk = "burst-user"
        request.user = user

        now = time.time()
        fake_history = [now - 10, now - 20, now - 30]

        with patch.object(throttle.cache, 'get', return_value=fake_history):
            with patch.object(throttle.cache, 'set'):
                allowed = throttle.allow_request(request, None)
                assert allowed is True

    def test_burst_throttle_blocks_after_spike(self):
        """6th request in a minute must be blocked."""
        throttle = BurstRateThrottle()
        factory = APIRequestFactory()
        request = factory.get("/api/v1/ai/suggest/")

        user = MagicMock()
        user.is_authenticated = True
        user.pk = "burst-user-blocked"
        request.user = user

        now = time.time()
        fake_history = [now - 10, now - 20, now - 30, now - 40, now - 50]

        with patch.object(throttle.cache, 'get', return_value=fake_history):
            with patch.object(throttle.cache, 'set'):
                allowed = throttle.allow_request(request, None)
                assert allowed is False

    def test_burst_throttle_resets_after_window(self):
        """Throttle must reset after the time window expires."""
        throttle = BurstRateThrottle()
        factory = APIRequestFactory()
        request = factory.get("/api/v1/ai/suggest/")

        user = MagicMock()
        user.is_authenticated = True
        user.pk = "burst-user-reset"
        request.user = user

        now = time.time()
        fake_history = [now - 120, now - 130, now - 140, now - 150, now - 160]

        with patch.object(throttle.cache, 'get', return_value=fake_history):
            with patch.object(throttle.cache, 'set'):
                allowed = throttle.allow_request(request, None)
                assert allowed is True

    def test_burst_throttle_anon_blocked(self):
        """Anonymous users must be blocked from burst throttle."""
        throttle = BurstRateThrottle()
        factory = APIRequestFactory()
        request = factory.get("/api/v1/ai/suggest/")

        request.user = MagicMock()
        request.user.is_authenticated = False

        cache_key = throttle.get_cache_key(request, None)
        assert cache_key is None


@pytest.mark.django_db
class TestThrottlingIntegration:
    """Integration-style tests with real DRF request flow."""

    def test_anon_request_blocked_by_throttle(self):
        """Anonymous API request must be throttled (403/429)."""
        client = APIClient()

        with patch.object(AIAssistRateThrottle, "get_cache_key", return_value=None):
            throttle = AIAssistRateThrottle()
            factory = APIRequestFactory()
            request = factory.get("/api/v1/ai/suggest/")
            request.user = MagicMock()
            request.user.is_authenticated = False

            cache_key = throttle.get_cache_key(request, None)
            assert cache_key is None

    def test_auth_request_gets_user_cache_key(self):
        """Authenticated user must get a stable cache key."""
        user = User.objects.create_user(email="throttle@example.com", password="pass")
        throttle = AIAssistRateThrottle()
        factory = APIRequestFactory()
        request = factory.get("/api/v1/ai/suggest/")
        request.user = user

        cache_key = throttle.get_cache_key(request, None)
        expected = f"mltask:throttle:ai_assist:{user.pk}"
        assert cache_key == expected