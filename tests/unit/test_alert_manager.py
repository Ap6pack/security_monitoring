"""Unit tests for AlertManager, WebhookAlerter, and alerting integration."""

from datetime import datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from security_scanner.alerters.manager import AlertManager
from security_scanner.alerters.webhook_alerter import WebhookAlerter
from security_scanner.config import Settings
from security_scanner.storage.models import AlertHistory


class MockFinding:
    """Mock finding for testing."""

    def __init__(
        self,
        severity: str = "HIGH",
        finding_id: str = "finding-1",
        alerted: bool = False,
    ) -> None:
        self.id = finding_id
        self.severity = severity
        self.domain = "test.example.com"
        self.type = "dangling_dns"
        self.title = "Test Finding"
        self.description = "Test description"
        self.remediation = "Test remediation"
        self.cvss_score = 7.5
        self.detected_at = datetime.now()
        self.alerted = alerted


def make_settings(**overrides: Any) -> Settings:
    """Create Settings with alert-related overrides."""
    defaults: dict[str, Any] = {
        "enable_email_alerts": False,
        "enable_slack_alerts": False,
        "enable_webhook_alerts": False,
        "alert_on_critical": True,
        "alert_on_high": True,
        "alert_min_findings": 1,
    }
    defaults.update(overrides)
    return Settings(**defaults)


# ---------------------------------------------------------------------------
# WebhookAlerter tests
# ---------------------------------------------------------------------------


class TestWebhookAlerter:
    """Test generic webhook alerter."""

    def test_should_alert_high(self) -> None:
        mock_http = MagicMock()
        alerter = WebhookAlerter(
            webhook_url="https://hooks.example.com/test", http_client=mock_http
        )
        assert alerter.should_alert(MockFinding("HIGH"), "HIGH")
        assert alerter.should_alert(MockFinding("CRITICAL"), "HIGH")

    def test_should_alert_threshold_reject(self) -> None:
        mock_http = MagicMock()
        alerter = WebhookAlerter(
            webhook_url="https://hooks.example.com/test", http_client=mock_http
        )
        assert not alerter.should_alert(MockFinding("MEDIUM"), "HIGH")
        assert not alerter.should_alert(MockFinding("LOW"), "CRITICAL")

    @pytest.mark.asyncio
    async def test_send_no_findings_above_threshold(self) -> None:
        mock_http = AsyncMock()
        alerter = WebhookAlerter(
            webhook_url="https://hooks.example.com/test",
            http_client=mock_http,
        )
        result = await alerter.send(
            [MockFinding("LOW")],
            "scan-1",
            severity_threshold="CRITICAL",
        )
        assert result is False
        mock_http.post.assert_not_called()

    @pytest.mark.asyncio
    async def test_send_success(self) -> None:
        mock_http = AsyncMock()
        mock_http.post = AsyncMock()
        alerter = WebhookAlerter(
            webhook_url="https://hooks.example.com/test",
            http_client=mock_http,
        )
        findings = [MockFinding("CRITICAL"), MockFinding("HIGH")]
        result = await alerter.send(findings, "scan-1", severity_threshold="HIGH")
        assert result is True
        mock_http.post.assert_called_once()

        call_kwargs = mock_http.post.call_args.kwargs
        payload = call_kwargs["json"]
        assert payload["scan_id"] == "scan-1"
        assert payload["findings_count"] == 2
        assert "timestamp" in payload
        assert payload["severity_summary"]["CRITICAL"] == 1
        assert payload["severity_summary"]["HIGH"] == 1
        assert len(payload["findings"]) == 2

    @pytest.mark.asyncio
    async def test_send_raises_alerter_error(self) -> None:
        mock_http = AsyncMock()
        mock_http.post = AsyncMock(side_effect=RuntimeError("connection failed"))
        alerter = WebhookAlerter(
            webhook_url="https://hooks.example.com/test",
            http_client=mock_http,
        )
        from security_scanner.utils.exceptions import AlerterError

        with pytest.raises(AlerterError, match="Webhook alert failed"):
            await alerter.send([MockFinding("HIGH")], "scan-1")

    def test_create_payload_structure(self) -> None:
        mock_http = MagicMock()
        alerter = WebhookAlerter(
            webhook_url="https://hooks.example.com/test", http_client=mock_http
        )
        findings = [MockFinding("CRITICAL"), MockFinding("MEDIUM")]
        payload = alerter._create_payload(findings, "scan-1")

        assert payload["scan_id"] == "scan-1"
        assert payload["findings_count"] == 2
        assert payload["severity_summary"]["CRITICAL"] == 1
        assert payload["severity_summary"]["MEDIUM"] == 1
        assert payload["severity_summary"]["HIGH"] == 0
        assert len(payload["findings"]) == 2
        assert payload["findings"][0]["domain"] == "test.example.com"


# ---------------------------------------------------------------------------
# AlertManager tests
# ---------------------------------------------------------------------------


class TestAlertManagerInit:
    """Test AlertManager initialization and channel building."""

    def test_no_channels_by_default(self) -> None:
        settings = make_settings()
        db = AsyncMock()
        mgr = AlertManager(settings=settings, db=db)
        assert mgr.enabled_channels == []
        assert mgr.has_channels is False

    def test_email_channel_enabled(self) -> None:
        settings = make_settings(
            enable_email_alerts=True,
            smtp_host="smtp.example.com",
            smtp_port=587,
            smtp_username="user",
            smtp_password="pass",
            smtp_from="from@example.com",
            smtp_to="to@example.com",
        )
        db = AsyncMock()
        mgr = AlertManager(settings=settings, db=db)
        assert "email" in mgr.enabled_channels
        assert mgr.has_channels is True

    @pytest.mark.asyncio
    async def test_slack_channel_enabled(self) -> None:
        settings = make_settings(
            enable_slack_alerts=True,
            slack_webhook_url="https://hooks.slack.com/test",
        )
        db = AsyncMock()
        mgr = AlertManager(settings=settings, db=db)
        assert "slack" in mgr.enabled_channels

    @pytest.mark.asyncio
    async def test_webhook_channel_enabled(self) -> None:
        settings = make_settings(
            enable_webhook_alerts=True,
            webhook_url="https://hooks.example.com/test",
        )
        db = AsyncMock()
        mgr = AlertManager(settings=settings, db=db)
        assert "webhook" in mgr.enabled_channels

    def test_slack_not_enabled_without_url(self) -> None:
        settings = make_settings(enable_slack_alerts=True, slack_webhook_url="")
        db = AsyncMock()
        mgr = AlertManager(settings=settings, db=db)
        assert "slack" not in mgr.enabled_channels

    def test_webhook_not_enabled_without_url(self) -> None:
        settings = make_settings(enable_webhook_alerts=True, webhook_url="")
        db = AsyncMock()
        mgr = AlertManager(settings=settings, db=db)
        assert "webhook" not in mgr.enabled_channels

    @pytest.mark.asyncio
    async def test_multiple_channels(self) -> None:
        settings = make_settings(
            enable_slack_alerts=True,
            slack_webhook_url="https://hooks.slack.com/test",
            enable_webhook_alerts=True,
            webhook_url="https://hooks.example.com/test",
        )
        db = AsyncMock()
        mgr = AlertManager(settings=settings, db=db)
        assert len(mgr.enabled_channels) == 2
        assert "slack" in mgr.enabled_channels
        assert "webhook" in mgr.enabled_channels


class TestAlertManagerSeverityThreshold:
    """Test severity threshold determination."""

    def test_default_threshold_high(self) -> None:
        settings = make_settings(alert_on_critical=True, alert_on_high=True)
        db = AsyncMock()
        mgr = AlertManager(settings=settings, db=db)
        assert mgr._get_severity_threshold() == "HIGH"

    def test_critical_only(self) -> None:
        settings = make_settings(alert_on_critical=True, alert_on_high=False)
        db = AsyncMock()
        mgr = AlertManager(settings=settings, db=db)
        assert mgr._get_severity_threshold() == "CRITICAL"


class TestAlertManagerFiltering:
    """Test finding filtering logic."""

    def test_filter_unalerted(self) -> None:
        settings = make_settings()
        db = AsyncMock()
        mgr = AlertManager(settings=settings, db=db)

        findings = [
            MockFinding("HIGH", "f1", alerted=False),
            MockFinding("HIGH", "f2", alerted=True),
            MockFinding("CRITICAL", "f3", alerted=False),
        ]
        result = mgr._filter_unalerted(findings)
        assert len(result) == 2
        assert all(not f.alerted for f in result)

    def test_filter_by_severity(self) -> None:
        settings = make_settings()
        db = AsyncMock()
        mgr = AlertManager(settings=settings, db=db)

        findings = [
            MockFinding("CRITICAL", "f1"),
            MockFinding("HIGH", "f2"),
            MockFinding("MEDIUM", "f3"),
            MockFinding("LOW", "f4"),
        ]
        result = mgr._filter_by_severity(findings, "HIGH")
        assert len(result) == 2
        severities = {f.severity for f in result}
        assert severities == {"CRITICAL", "HIGH"}


class TestAlertManagerProcessFindings:
    """Test the core process_findings method."""

    @pytest.mark.asyncio
    async def test_no_channels_skips(self) -> None:
        settings = make_settings()
        db = AsyncMock()
        mgr = AlertManager(settings=settings, db=db)

        result = await mgr.process_findings([MockFinding("HIGH")], "scan-1")
        assert result["channels_notified"] == []
        assert result["findings_alerted"] == 0

    @pytest.mark.asyncio
    async def test_all_alerted_skips(self) -> None:
        settings = make_settings(
            enable_webhook_alerts=True,
            webhook_url="https://hooks.example.com/test",
        )
        db = AsyncMock()
        mgr = AlertManager(settings=settings, db=db)

        findings = [MockFinding("HIGH", "f1", alerted=True)]
        result = await mgr.process_findings(findings, "scan-1")
        assert result["findings_alerted"] == 0

    @pytest.mark.asyncio
    async def test_below_severity_threshold_skips(self) -> None:
        settings = make_settings(
            enable_webhook_alerts=True,
            webhook_url="https://hooks.example.com/test",
            alert_on_critical=True,
            alert_on_high=False,
        )
        db = AsyncMock()
        mgr = AlertManager(settings=settings, db=db)

        findings = [MockFinding("MEDIUM", "f1")]
        result = await mgr.process_findings(findings, "scan-1")
        assert result["findings_alerted"] == 0

    @pytest.mark.asyncio
    async def test_below_min_findings_skips(self) -> None:
        settings = make_settings(
            enable_webhook_alerts=True,
            webhook_url="https://hooks.example.com/test",
            alert_min_findings=5,
        )
        db = AsyncMock()
        mgr = AlertManager(settings=settings, db=db)

        findings = [MockFinding("HIGH", "f1")]
        result = await mgr.process_findings(findings, "scan-1")
        assert result["findings_alerted"] == 0

    @pytest.mark.asyncio
    async def test_successful_dispatch(self) -> None:
        settings = make_settings(
            enable_webhook_alerts=True,
            webhook_url="https://hooks.example.com/test",
        )
        db = AsyncMock()
        db.create_alert_history = AsyncMock()
        db.mark_finding_alerted = AsyncMock()
        mgr = AlertManager(settings=settings, db=db)

        # Mock the webhook alerter's send method
        mock_send = AsyncMock(return_value=True)
        mgr._channels["webhook"].send = mock_send  # type: ignore[assignment]

        findings = [MockFinding("HIGH", "f1"), MockFinding("CRITICAL", "f2")]
        result = await mgr.process_findings(findings, "scan-1")

        assert "webhook" in result["channels_notified"]
        assert result["findings_alerted"] == 2
        assert result["failures"] == []
        mock_send.assert_called_once()
        assert db.mark_finding_alerted.call_count == 2
        assert db.create_alert_history.call_count == 2

    @pytest.mark.asyncio
    async def test_channel_failure_fault_isolation(self) -> None:
        settings = make_settings(
            enable_slack_alerts=True,
            slack_webhook_url="https://hooks.slack.com/test",
            enable_webhook_alerts=True,
            webhook_url="https://hooks.example.com/test",
        )
        db = AsyncMock()
        db.create_alert_history = AsyncMock()
        db.mark_finding_alerted = AsyncMock()
        mgr = AlertManager(settings=settings, db=db)

        # Slack fails, webhook succeeds
        mgr._channels["slack"].send = AsyncMock(  # type: ignore[assignment]
            side_effect=RuntimeError("slack down")
        )
        mgr._channels["webhook"].send = AsyncMock(return_value=True)  # type: ignore[assignment]

        findings = [MockFinding("HIGH", "f1")]
        result = await mgr.process_findings(findings, "scan-1")

        assert "webhook" in result["channels_notified"]
        assert "slack" not in result["channels_notified"]
        assert len(result["failures"]) == 1
        assert result["failures"][0]["channel"] == "slack"
        # Finding should still be marked alerted because webhook succeeded
        assert result["findings_alerted"] == 1
        db.mark_finding_alerted.assert_called_once_with("f1")

    @pytest.mark.asyncio
    async def test_all_channels_fail(self) -> None:
        settings = make_settings(
            enable_webhook_alerts=True,
            webhook_url="https://hooks.example.com/test",
        )
        db = AsyncMock()
        db.create_alert_history = AsyncMock()
        db.mark_finding_alerted = AsyncMock()
        mgr = AlertManager(settings=settings, db=db)

        mgr._channels["webhook"].send = AsyncMock(  # type: ignore[assignment]
            side_effect=RuntimeError("down")
        )

        findings = [MockFinding("HIGH", "f1")]
        result = await mgr.process_findings(findings, "scan-1")

        assert result["channels_notified"] == []
        assert result["findings_alerted"] == 0
        assert len(result["failures"]) == 1
        # Finding should NOT be marked alerted
        db.mark_finding_alerted.assert_not_called()
        # History should still be recorded (with success=False)
        db.create_alert_history.assert_called_once()

    @pytest.mark.asyncio
    async def test_history_recorded_for_each_finding_and_channel(self) -> None:
        settings = make_settings(
            enable_slack_alerts=True,
            slack_webhook_url="https://hooks.slack.com/test",
            enable_webhook_alerts=True,
            webhook_url="https://hooks.example.com/test",
        )
        db = AsyncMock()
        db.create_alert_history = AsyncMock()
        db.mark_finding_alerted = AsyncMock()
        mgr = AlertManager(settings=settings, db=db)

        mgr._channels["slack"].send = AsyncMock(return_value=True)  # type: ignore[assignment]
        mgr._channels["webhook"].send = AsyncMock(return_value=True)  # type: ignore[assignment]

        findings = [MockFinding("HIGH", "f1"), MockFinding("CRITICAL", "f2")]
        await mgr.process_findings(findings, "scan-1")

        # 2 channels * 2 findings = 4 history records
        assert db.create_alert_history.call_count == 4

    @pytest.mark.asyncio
    async def test_history_records_failure_error(self) -> None:
        settings = make_settings(
            enable_webhook_alerts=True,
            webhook_url="https://hooks.example.com/test",
        )
        db = AsyncMock()
        db.create_alert_history = AsyncMock()
        db.mark_finding_alerted = AsyncMock()
        mgr = AlertManager(settings=settings, db=db)

        mgr._channels["webhook"].send = AsyncMock(  # type: ignore[assignment]
            side_effect=RuntimeError("timeout")
        )

        findings = [MockFinding("HIGH", "f1")]
        await mgr.process_findings(findings, "scan-1")

        call_args = db.create_alert_history.call_args
        alert: AlertHistory = call_args[0][0]
        assert alert.success is False
        assert alert.error_message == "timeout"
        assert alert.channel == "webhook"

    @pytest.mark.asyncio
    async def test_mark_finding_alerted_failure_does_not_crash(self) -> None:
        settings = make_settings(
            enable_webhook_alerts=True,
            webhook_url="https://hooks.example.com/test",
        )
        db = AsyncMock()
        db.create_alert_history = AsyncMock()
        db.mark_finding_alerted = AsyncMock(side_effect=RuntimeError("db error"))
        mgr = AlertManager(settings=settings, db=db)

        mgr._channels["webhook"].send = AsyncMock(return_value=True)  # type: ignore[assignment]

        findings = [MockFinding("HIGH", "f1")]
        # Should not raise
        result = await mgr.process_findings(findings, "scan-1")
        assert "webhook" in result["channels_notified"]

    @pytest.mark.asyncio
    async def test_empty_findings_list(self) -> None:
        settings = make_settings(
            enable_webhook_alerts=True,
            webhook_url="https://hooks.example.com/test",
        )
        db = AsyncMock()
        mgr = AlertManager(settings=settings, db=db)

        result = await mgr.process_findings([], "scan-1")
        assert result["findings_alerted"] == 0
        assert result["channels_notified"] == []


# ---------------------------------------------------------------------------
# Scheduler integration tests
# ---------------------------------------------------------------------------


class TestSchedulerAlertIntegration:
    """Test AlertManager integration with ScanScheduler."""

    @pytest.mark.asyncio
    async def test_scheduler_calls_alert_manager_on_new_findings(self) -> None:
        from security_scanner.scheduler import ScanScheduler

        settings = make_settings()
        db = AsyncMock()
        db.get_similar_findings = AsyncMock(return_value=[])

        mock_alert_manager = AsyncMock()
        mock_alert_manager.process_findings = AsyncMock(
            return_value={"channels_notified": [], "findings_alerted": 0, "failures": []}
        )

        scheduler = ScanScheduler(
            settings=settings,
            db=db,
            domains=["example.com"],
            alert_manager=mock_alert_manager,
        )

        finding = MockFinding("HIGH", "f1")
        mock_result = {
            "scan_id": "scan-1",
            "findings": [finding],
            "summary": {"critical": 0, "high": 1, "medium": 0, "low": 0},
        }

        mock_orchestrator = AsyncMock()
        mock_orchestrator.scan = AsyncMock(return_value=mock_result)
        scheduler._orchestrator = mock_orchestrator

        await scheduler._run_scan()

        mock_alert_manager.process_findings.assert_called_once()
        call_args = mock_alert_manager.process_findings.call_args
        assert call_args[0][1] == "scan-1"  # scan_id

    @pytest.mark.asyncio
    async def test_scheduler_no_alert_when_no_new_findings(self) -> None:
        from security_scanner.scheduler import ScanScheduler

        settings = make_settings()
        db = AsyncMock()
        # All findings are old (multiple similar findings exist)
        db.get_similar_findings = AsyncMock(return_value=["existing1", "existing2"])

        mock_alert_manager = AsyncMock()
        mock_alert_manager.process_findings = AsyncMock()

        scheduler = ScanScheduler(
            settings=settings,
            db=db,
            domains=["example.com"],
            alert_manager=mock_alert_manager,
        )

        mock_result = {
            "scan_id": "scan-1",
            "findings": [MockFinding("HIGH", "f1")],
            "summary": {"critical": 0, "high": 1, "medium": 0, "low": 0},
        }

        mock_orchestrator = AsyncMock()
        mock_orchestrator.scan = AsyncMock(return_value=mock_result)
        scheduler._orchestrator = mock_orchestrator

        await scheduler._run_scan()

        # No new findings detected, so no alert dispatch
        mock_alert_manager.process_findings.assert_not_called()

    @pytest.mark.asyncio
    async def test_scheduler_handles_alert_failure_gracefully(self) -> None:
        from security_scanner.scheduler import ScanScheduler

        settings = make_settings()
        db = AsyncMock()
        db.get_similar_findings = AsyncMock(return_value=[])

        mock_alert_manager = AsyncMock()
        mock_alert_manager.process_findings = AsyncMock(
            side_effect=RuntimeError("alert system down")
        )

        scheduler = ScanScheduler(
            settings=settings,
            db=db,
            domains=["example.com"],
            alert_manager=mock_alert_manager,
        )

        mock_result = {
            "scan_id": "scan-1",
            "findings": [MockFinding("HIGH", "f1")],
            "summary": {"critical": 0, "high": 1, "medium": 0, "low": 0},
        }

        mock_orchestrator = AsyncMock()
        mock_orchestrator.scan = AsyncMock(return_value=mock_result)
        scheduler._orchestrator = mock_orchestrator

        # Should not raise — alert failure is caught
        result = await scheduler._run_scan()
        assert result is not None
        assert result["scan_id"] == "scan-1"

    @pytest.mark.asyncio
    async def test_scheduler_works_without_alert_manager(self) -> None:
        from security_scanner.scheduler import ScanScheduler

        settings = make_settings()
        db = AsyncMock()
        db.get_similar_findings = AsyncMock(return_value=[])

        scheduler = ScanScheduler(
            settings=settings,
            db=db,
            domains=["example.com"],
            # No alert_manager
        )

        mock_result = {
            "scan_id": "scan-1",
            "findings": [MockFinding("HIGH", "f1")],
            "summary": {"critical": 0, "high": 1, "medium": 0, "low": 0},
        }

        mock_orchestrator = AsyncMock()
        mock_orchestrator.scan = AsyncMock(return_value=mock_result)
        scheduler._orchestrator = mock_orchestrator

        result = await scheduler._run_scan()
        assert result is not None


# ---------------------------------------------------------------------------
# MonitorDaemon integration test
# ---------------------------------------------------------------------------


class TestMonitorDaemonAlertIntegration:
    """Test AlertManager creation in MonitorDaemon."""

    @pytest.mark.asyncio
    async def test_daemon_creates_alert_manager_for_scheduler(self) -> None:
        settings = make_settings(
            enable_webhook_alerts=True,
            webhook_url="https://hooks.example.com/test",
        )
        db = AsyncMock()

        from security_scanner.monitor import MonitorDaemon

        daemon = MonitorDaemon(
            settings=settings,
            db=db,
            domains=["example.com"],
        )

        assert daemon.scheduler.alert_manager is not None

    def test_daemon_no_alert_manager_when_no_channels(self) -> None:
        settings = make_settings()
        db = AsyncMock()

        from security_scanner.monitor import MonitorDaemon

        daemon = MonitorDaemon(
            settings=settings,
            db=db,
            domains=["example.com"],
        )

        assert daemon.scheduler.alert_manager is None
