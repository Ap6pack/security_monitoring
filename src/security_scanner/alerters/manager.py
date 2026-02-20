"""Alert manager coordinating dispatch across all alert channels."""

from typing import Any

from security_scanner.alerters.email_alerter import EmailAlerter
from security_scanner.alerters.slack_alerter import SlackAlerter
from security_scanner.alerters.webhook_alerter import WebhookAlerter
from security_scanner.config import Settings
from security_scanner.storage.database import DatabaseManager
from security_scanner.storage.models import AlertHistory
from security_scanner.utils.logger import get_logger

logger = get_logger(__name__)


class AlertManager:
    """Central coordinator for dispatching alerts across all enabled channels.

    Handles:
    - Building the active alerter list from config
    - Filtering un-alerted findings
    - Threshold checks (severity + min count)
    - Dispatching to all enabled channels with fault isolation
    - Recording AlertHistory per channel per finding
    - Marking findings as alerted after successful dispatch
    """

    SEVERITY_LEVELS = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
    }

    def __init__(self, settings: Settings, db: DatabaseManager) -> None:
        self.settings = settings
        self.db = db
        self._channels: dict[str, EmailAlerter | SlackAlerter | WebhookAlerter] = {}
        self._build_channels()

    def _build_channels(self) -> None:
        """Build the active alerter list from config settings."""
        if self.settings.enable_email_alerts:
            to_emails = [e.strip() for e in self.settings.smtp_to.split(",") if e.strip()]
            self._channels["email"] = EmailAlerter(
                smtp_host=self.settings.smtp_host,
                smtp_port=self.settings.smtp_port,
                smtp_user=self.settings.smtp_username,
                smtp_password=self.settings.smtp_password,
                from_email=self.settings.smtp_from,
                to_emails=to_emails,
                use_tls=self.settings.smtp_use_tls,
            )
            logger.info("Email alerter enabled")

        if self.settings.enable_slack_alerts and self.settings.slack_webhook_url:
            self._channels["slack"] = SlackAlerter(
                webhook_url=self.settings.slack_webhook_url,
            )
            logger.info("Slack alerter enabled")

        if self.settings.enable_webhook_alerts and self.settings.webhook_url:
            self._channels["webhook"] = WebhookAlerter(
                webhook_url=self.settings.webhook_url,
            )
            logger.info("Webhook alerter enabled")

    @property
    def enabled_channels(self) -> list[str]:
        """Return names of enabled alert channels."""
        return list(self._channels.keys())

    @property
    def has_channels(self) -> bool:
        """Whether any alert channels are configured."""
        return len(self._channels) > 0

    def _get_severity_threshold(self) -> str:
        """Determine severity threshold from config flags."""
        if self.settings.alert_on_critical and not self.settings.alert_on_high:
            return "CRITICAL"
        if self.settings.alert_on_high:
            return "HIGH"
        return "CRITICAL"

    def _filter_unalerted(self, findings: list[Any]) -> list[Any]:
        """Filter out findings that have already been alerted."""
        return [f for f in findings if not getattr(f, "alerted", False)]

    def _filter_by_severity(self, findings: list[Any], threshold: str) -> list[Any]:
        """Filter findings that meet the severity threshold."""
        min_level = self.SEVERITY_LEVELS.get(threshold, 0)
        return [
            f
            for f in findings
            if self.SEVERITY_LEVELS.get(getattr(f, "severity", "LOW"), 0) >= min_level
        ]

    async def process_findings(self, findings: list[Any], scan_id: str) -> dict[str, Any]:
        """Process findings and dispatch alerts to all enabled channels.

        Args:
            findings: List of security findings from a scan
            scan_id: The scan identifier

        Returns:
            Summary dict with channels_notified, findings_alerted, failures
        """
        result: dict[str, Any] = {
            "channels_notified": [],
            "findings_alerted": 0,
            "failures": [],
        }

        if not self._channels:
            logger.debug("No alert channels configured, skipping")
            return result

        # Filter to un-alerted findings only
        unalerted = self._filter_unalerted(findings)
        if not unalerted:
            logger.debug("No un-alerted findings to process")
            return result

        # Apply severity threshold
        severity_threshold = self._get_severity_threshold()
        eligible = self._filter_by_severity(unalerted, severity_threshold)
        if not eligible:
            logger.debug(
                "No findings meet severity threshold",
                threshold=severity_threshold,
                unalerted_count=len(unalerted),
            )
            return result

        # Check minimum findings threshold
        if len(eligible) < self.settings.alert_min_findings:
            logger.debug(
                "Below minimum findings threshold",
                eligible=len(eligible),
                minimum=self.settings.alert_min_findings,
            )
            return result

        logger.info(
            "Processing alerts",
            scan_id=scan_id,
            eligible_findings=len(eligible),
            channels=list(self._channels.keys()),
        )

        # Track which findings were successfully alerted on any channel
        alerted_finding_ids: set[str] = set()

        # Dispatch to each channel with fault isolation
        for channel_name, alerter in self._channels.items():
            success = False
            error_message: str | None = None

            try:
                success = await alerter.send(
                    findings=eligible,
                    scan_id=scan_id,
                    severity_threshold=severity_threshold,
                )
                if success:
                    result["channels_notified"].append(channel_name)
                    alerted_finding_ids.update(
                        getattr(f, "id", "") for f in eligible if getattr(f, "id", "")
                    )
            except Exception as e:
                error_message = str(e)
                result["failures"].append({"channel": channel_name, "error": error_message})
                logger.error(
                    "Alert channel failed",
                    channel=channel_name,
                    error=error_message,
                )

            # Record history for each finding on this channel
            await self._record_history(eligible, channel_name, success, error_message)

        # Mark successfully alerted findings in the database
        for finding_id in alerted_finding_ids:
            try:
                await self.db.mark_finding_alerted(finding_id)
            except Exception:
                logger.exception("Failed to mark finding as alerted", finding_id=finding_id)

        result["findings_alerted"] = len(alerted_finding_ids)

        logger.info(
            "Alert processing complete",
            scan_id=scan_id,
            channels_notified=result["channels_notified"],
            findings_alerted=result["findings_alerted"],
            failures=len(result["failures"]),
        )

        return result

    async def _record_history(
        self,
        findings: list[Any],
        channel: str,
        success: bool,
        error_message: str | None,
    ) -> None:
        """Record alert history for each finding on a channel."""
        for finding in findings:
            finding_id = getattr(finding, "id", "")
            if not finding_id:
                continue
            try:
                alert = AlertHistory(
                    finding_id=finding_id,
                    channel=channel,
                    success=success,
                    error_message=error_message,
                )
                await self.db.create_alert_history(alert)
            except Exception:
                logger.exception(
                    "Failed to record alert history",
                    finding_id=finding_id,
                    channel=channel,
                )
