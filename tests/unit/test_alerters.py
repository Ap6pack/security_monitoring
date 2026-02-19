"""Unit tests for alerters."""

from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from security_scanner.alerters import EmailAlerter, SlackAlerter


class MockFinding:
    """Mock finding for testing."""

    def __init__(self, severity: str = "HIGH") -> None:
        self.severity = severity
        self.domain = "test.example.com"
        self.title = "Test Finding"
        self.description = "Test description"
        self.remediation = "Test remediation"
        self.cvss_score = 7.5
        self.detected_at = datetime.now()


@pytest.fixture
def sample_findings() -> list[MockFinding]:
    """Create sample findings for testing."""
    return [
        MockFinding("CRITICAL"),
        MockFinding("HIGH"),
        MockFinding("MEDIUM"),
        MockFinding("LOW"),
    ]


class TestEmailAlerter:
    """Test email alerter."""

    def test_should_alert_critical(self) -> None:
        """Test alert threshold for CRITICAL findings."""
        alerter = EmailAlerter(
            smtp_host="smtp.example.com",
            smtp_port=587,
            smtp_user="user",
            smtp_password="pass",
            from_email="from@example.com",
            to_emails=["to@example.com"],
        )

        critical_finding = MockFinding("CRITICAL")
        assert alerter.should_alert(critical_finding, "HIGH")
        assert alerter.should_alert(critical_finding, "CRITICAL")

    def test_should_alert_threshold(self) -> None:
        """Test alert threshold filtering."""
        alerter = EmailAlerter(
            smtp_host="smtp.example.com",
            smtp_port=587,
            smtp_user="user",
            smtp_password="pass",
            from_email="from@example.com",
            to_emails=["to@example.com"],
        )

        low_finding = MockFinding("LOW")
        assert not alerter.should_alert(low_finding, "HIGH")
        assert alerter.should_alert(low_finding, "LOW")

    @pytest.mark.asyncio
    async def test_send_no_findings_above_threshold(
        self, sample_findings: list[MockFinding]
    ) -> None:
        """Test sending with no findings meeting threshold."""
        alerter = EmailAlerter(
            smtp_host="smtp.example.com",
            smtp_port=587,
            smtp_user="user",
            smtp_password="pass",
            from_email="from@example.com",
            to_emails=["to@example.com"],
        )

        # No findings are CRITICAL level
        result = await alerter.send(
            [MockFinding("LOW")],
            "test-scan-1",
            severity_threshold="CRITICAL",
        )

        assert result is False

    @pytest.mark.asyncio
    async def test_send_with_smtp_mock(self, sample_findings: list[MockFinding]) -> None:
        """Test sending email with mocked SMTP."""
        alerter = EmailAlerter(
            smtp_host="smtp.example.com",
            smtp_port=587,
            smtp_user="user",
            smtp_password="pass",
            from_email="from@example.com",
            to_emails=["to@example.com"],
        )

        with patch("smtplib.SMTP") as mock_smtp:
            mock_server = MagicMock()
            mock_smtp.return_value = mock_server

            result = await alerter.send(
                sample_findings,
                "test-scan-1",
                severity_threshold="HIGH",
            )

            assert result is True
            mock_server.starttls.assert_called_once()
            mock_server.login.assert_called_once()
            mock_server.sendmail.assert_called_once()
            mock_server.quit.assert_called_once()

    def test_generate_html(self, sample_findings: list[MockFinding]) -> None:
        """Test HTML generation."""
        alerter = EmailAlerter(
            smtp_host="smtp.example.com",
            smtp_port=587,
            smtp_user="user",
            smtp_password="pass",
            from_email="from@example.com",
            to_emails=["to@example.com"],
        )

        html = alerter._generate_html(sample_findings, "test-scan-1")

        assert "<!DOCTYPE html>" in html
        assert "Security Alert" in html
        assert "CRITICAL" in html
        assert "test.example.com" in html


class TestSlackAlerter:
    """Test Slack alerter."""

    def test_should_alert_high(self) -> None:
        """Test alert threshold for HIGH findings."""
        mock_http = MagicMock()
        alerter = SlackAlerter(
            webhook_url="https://hooks.slack.com/test", http_client=mock_http
        )

        high_finding = MockFinding("HIGH")
        assert alerter.should_alert(high_finding, "HIGH")
        assert alerter.should_alert(high_finding, "MEDIUM")

    def test_should_alert_threshold(self) -> None:
        """Test alert threshold filtering."""
        mock_http = MagicMock()
        alerter = SlackAlerter(
            webhook_url="https://hooks.slack.com/test", http_client=mock_http
        )

        medium_finding = MockFinding("MEDIUM")
        assert not alerter.should_alert(medium_finding, "HIGH")
        assert alerter.should_alert(medium_finding, "MEDIUM")

    @pytest.mark.asyncio
    async def test_send_no_findings_above_threshold(
        self, sample_findings: list[MockFinding]
    ) -> None:
        """Test sending with no findings meeting threshold."""
        mock_http = AsyncMock()
        alerter = SlackAlerter(
            webhook_url="https://hooks.slack.com/test",
            http_client=mock_http,
        )

        result = await alerter.send(
            [MockFinding("LOW")],
            "test-scan-1",
            severity_threshold="CRITICAL",
        )

        assert result is False
        mock_http.post.assert_not_called()

    @pytest.mark.asyncio
    async def test_send_with_http_mock(self, sample_findings: list[MockFinding]) -> None:
        """Test sending Slack alert with mocked HTTP client."""
        mock_http = AsyncMock()
        mock_http.post = AsyncMock()

        alerter = SlackAlerter(
            webhook_url="https://hooks.slack.com/test",
            http_client=mock_http,
        )

        result = await alerter.send(
            sample_findings,
            "test-scan-1",
            severity_threshold="HIGH",
        )

        assert result is True
        mock_http.post.assert_called_once()

        # Check the payload structure
        call_args = mock_http.post.call_args
        payload = call_args.kwargs["json"]
        assert "blocks" in payload
        assert len(payload["blocks"]) > 0

    def test_create_payload(self, sample_findings: list[MockFinding]) -> None:
        """Test Slack payload creation."""
        mock_http = MagicMock()
        alerter = SlackAlerter(
            webhook_url="https://hooks.slack.com/test", http_client=mock_http
        )

        payload = alerter._create_payload(sample_findings, "test-scan-1")

        assert "blocks" in payload
        assert isinstance(payload["blocks"], list)
        assert len(payload["blocks"]) > 0

        # Check for header block
        assert payload["blocks"][0]["type"] == "header"
        assert "Security Alert" in payload["blocks"][0]["text"]["text"]
