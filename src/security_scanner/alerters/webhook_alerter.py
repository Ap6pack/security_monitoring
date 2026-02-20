"""Generic webhook alerter for HTTP POST notifications."""

from datetime import datetime
from typing import Any

from security_scanner.utils.exceptions import AlerterError
from security_scanner.utils.http_client import HTTPClient
from security_scanner.utils.logger import get_logger

logger = get_logger(__name__)


class WebhookAlerter:
    """
    Send alert notifications via generic HTTP POST webhook.

    Supports any endpoint that accepts JSON payloads (PagerDuty, Teams, custom).

    Supports:
    - JSON payload with findings summary
    - Severity-based filtering
    - Configurable webhook URL
    """

    SEVERITY_LEVELS = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
    }

    def __init__(self, webhook_url: str, http_client: HTTPClient | None = None) -> None:
        """
        Initialize the webhook alerter.

        Args:
            webhook_url: HTTP endpoint to POST alerts to
            http_client: Optional HTTP client instance
        """
        self.webhook_url = webhook_url
        self.http_client = http_client or HTTPClient()

    async def send(
        self,
        findings: list[Any],
        scan_id: str,
        severity_threshold: str = "HIGH",
    ) -> bool:
        """
        Send webhook alert for findings.

        Args:
            findings: List of security findings
            scan_id: Scan identifier
            severity_threshold: Minimum severity to include

        Returns:
            True if alert was sent successfully

        Raises:
            AlerterError: If alert sending fails
        """
        try:
            filtered_findings = [f for f in findings if self.should_alert(f, severity_threshold)]

            if not filtered_findings:
                logger.info(
                    "No findings meet alert threshold",
                    threshold=severity_threshold,
                    total_findings=len(findings),
                )
                return False

            logger.info(
                "Sending webhook alert",
                scan_id=scan_id,
                findings_count=len(filtered_findings),
            )

            payload = self._create_payload(filtered_findings, scan_id)

            await self.http_client.post(
                self.webhook_url,
                json=payload,
                rate_limit=False,
            )

            logger.info(
                "Webhook alert sent successfully",
                scan_id=scan_id,
                findings_count=len(filtered_findings),
            )

            return True

        except Exception as e:
            logger.error("Failed to send webhook alert", error=str(e))
            raise AlerterError(f"Webhook alert failed: {e}") from e

    def should_alert(self, finding: Any, severity_threshold: str) -> bool:
        """Check if finding meets alert threshold."""
        finding_severity = getattr(finding, "severity", "LOW")
        return self.SEVERITY_LEVELS.get(finding_severity, 0) >= self.SEVERITY_LEVELS.get(
            severity_threshold, 0
        )

    def _create_payload(self, findings: list[Any], scan_id: str) -> dict[str, Any]:
        """Create JSON payload for webhook POST."""
        severity_summary: dict[str, int] = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
        }

        findings_data: list[dict[str, Any]] = []

        for finding in findings:
            severity = getattr(finding, "severity", "LOW")
            if severity in severity_summary:
                severity_summary[severity] += 1

            findings_data.append(
                {
                    "domain": getattr(finding, "domain", "N/A"),
                    "title": getattr(finding, "title", getattr(finding, "type", "Untitled")),
                    "severity": severity,
                    "description": getattr(finding, "description", "No description"),
                    "cvss_score": getattr(finding, "cvss_score", 0.0),
                    "remediation": getattr(finding, "remediation", "No remediation"),
                }
            )

        return {
            "scan_id": scan_id,
            "timestamp": datetime.now().isoformat(),
            "findings_count": len(findings),
            "severity_summary": severity_summary,
            "findings": findings_data,
        }
