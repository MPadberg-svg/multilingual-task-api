"""Tests for InputValidator — XSS and SQLi detection."""

from apps.core.security import InputValidator


class TestInputValidator:
    """Unit tests for security input validation."""

    def test_sanitize_strips_control_characters(self):
        """sanitize_string must remove null bytes and control chars."""
        result = InputValidator.sanitize_string("Hello\x00\x01\x02World")
        assert "\x00" not in result
        assert "Hello" in result
        assert "World" in result

    def test_sanitize_normal_string_unchanged(self):
        """Normal alphanumeric strings must pass through unchanged."""
        result = InputValidator.sanitize_string("Review quarterly metrics")
        assert result == "Review quarterly metrics"

    def test_sanitize_empty_string(self):
        """Empty string must return empty string without error."""
        result = InputValidator.sanitize_string("")
        assert result == ""

    def test_sanitize_html_tags_preserved(self):
        """sanitize_string does NOT strip HTML — it only removes control chars."""
        result = InputValidator.sanitize_string("<script>alert('xss')</script>Hello")
        # sanitize_string is for plain text, not HTML escaping
        assert "<script>" in result
        assert "Hello" in result

    def test_sanitize_html_escapes_entities(self):
        """sanitize_html properly escapes HTML entities."""
        result = InputValidator.sanitize_html("<script>alert('xss')</script>Hello")
        assert "<script>" not in result
        assert "&lt;script&gt;" in result
        assert "Hello" in result

    def test_detect_sql_injection_pattern(self):
        """SQL injection patterns must be flagged as dangerous."""
        is_dangerous, reason = InputValidator.detect_injection(
            "SELECT * FROM users WHERE 1=1; DROP TABLE tasks;--"
        )
        assert is_dangerous is True
        assert reason is not None
        assert len(reason) > 0

    def test_detect_xss_pattern(self):
        """XSS/script patterns must be flagged as dangerous."""
        is_dangerous, reason = InputValidator.detect_injection(
            "<script>document.cookie='stolen'</script>"
        )
        assert is_dangerous is True
        assert reason is not None
        assert len(reason) > 0

    def test_detect_safe_input_not_flagged(self):
        """Benign plain text must NOT be flagged as dangerous."""
        is_dangerous, reason = InputValidator.detect_injection(
            "Annotate the image of a dog in the park"
        )
        assert is_dangerous is False
        assert reason == ""

    def test_detect_script_tag(self):
        """Standalone <script> tags must trigger XSS detection."""
        is_dangerous, _ = InputValidator.detect_injection("<script>alert(1)</script>")
        assert is_dangerous is True

    def test_detect_union_select(self):
        """UNION SELECT SQL patterns must trigger SQLi detection."""
        is_dangerous, reason = InputValidator.detect_injection(
            "' UNION SELECT username, password FROM users--"
        )
        assert is_dangerous is True
        assert "UNION" in reason or "SELECT" in reason
