"""Slack alerter using webhook integration."""

from datetime import datetime
from typing import Any

from security_scanner.utils.exceptions import AlerterError
from security_scanner.utils.http_client import HTTPClient
from security_scanner.utils.logger import get_logger

logger = get_logger(__name__)


class SlackAlerter:
    """
    Send alert notifications to Slack via webhooks.

    Supports:
    - Rich message formatting with blocks
    - Color-coded severity levels
    - Severity-based filtering
    - Multiple findings in single message
    """

    # Severity hierarchy for filtering
    SEVERITY_LEVELS = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
    }

    # Slack color codes for severity
    SEVERITY_COLORS = {
        "CRITICAL": "#dc2626",  # Red
        "HIGH": "#ea580c",  # Orange
        "MEDIUM": "#ca8a04",  # Yellow
        "LOW": "#16a34a",  # Green
    }

    def __init__(self, webhook_url: str, http_client: HTTPClient | None = None) -> None:
        """
        Initialize the Slack alerter.

        Args:
            webhook_url: Slack incoming webhook URL
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
        Send Slack alert for findings.

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
            # Filter findings by severity
            filtered_findings = [
                f for f in findings if self.should_alert(f, severity_threshold)
            ]

            if not filtered_findings:
                logger.info(
                    "No findings meet alert threshold",
                    threshold=severity_threshold,
                    total_findings=len(findings),
                )
                return False

            logger.info(
                "Sending Slack alert",
                scan_id=scan_id,
                findings_count=len(filtered_findings),
            )

            # Create Slack message payload
            payload = self._create_payload(filtered_findings, scan_id)

            # Send to Slack webhook
            await self.http_client.post(
                self.webhook_url,
                json=payload,
                rate_limit=False,
            )

            logger.info(
                "Slack alert sent successfully",
                scan_id=scan_id,
                findings_count=len(filtered_findings),
            )

            return True

        except Exception as e:
            logger.error("Failed to send Slack alert", error=str(e))
            raise AlerterError(f"Slack alert failed: {e}") from e

    def should_alert(self, finding: Any, severity_threshold: str) -> bool:
        """Check if finding meets alert threshold."""
        finding_severity = getattr(finding, "severity", "LOW")
        return self.SEVERITY_LEVELS.get(
            finding_severity, 0
        ) >= self.SEVERITY_LEVELS.get(severity_threshold, 0)

    def _create_payload(self, findings: list[Any], scan_id: str) -> dict[str, Any]:
        """Create Slack message payload with blocks."""
        # Group by severity
        by_severity: dict[str, list[Any]] = {
            "CRITICAL": [],
            "HIGH": [],
            "MEDIUM": [],
            "LOW": [],
        }

        for finding in findings:
            severity = getattr(finding, "severity", "LOW")
            if severity in by_severity:
                by_severity[severity].append(finding)

        # Build blocks
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"🚨 Security Alert: {len(findings)} Finding(s)",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Scan ID:*\n`{scan_id}`"},
                    {
                        "type": "mrkdwn",
                        "text": f"*Generated:*\n{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                    },
                ],
            },
            {"type": "divider"},
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": "*Summary by Severity:*"},
            },
        ]

        # Add summary
        summary_lines = []
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = len(by_severity[severity])
            if count > 0:
                emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(
                    severity, "⚪"
                )
                summary_lines.append(f"{emoji} *{severity}:* {count}")

        blocks.append(
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": "\n".join(summary_lines)},
            }
        )

        blocks.append({"type": "divider"})

        # Add findings (limit to prevent message size issues)
        max_findings = 5
        findings_shown = 0

        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            severity_findings = by_severity[severity]
            if not severity_findings or findings_shown >= max_findings:
                continue

            for finding in severity_findings[:max_findings - findings_shown]:
                domain = getattr(finding, "domain", "N/A")
                title = getattr(finding, "title", "Untitled")
                description = getattr(finding, "description", "No description")[:200]
                cvss = getattr(finding, "cvss_score", 0.0)

                emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(
                    severity, "⚪"
                )

                blocks.append(
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": (
                                f"{emoji} *{title}*\n"
                                f"*Domain:* `{domain}`\n"
                                f"*CVSS:* {cvss}\n"
                                f"{description}"
                            ),
                        },
                    }
                )

                findings_shown += 1
                if findings_shown >= max_findings:
                    break

        # Add note if there are more findings
        if len(findings) > max_findings:
            blocks.append(
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": f"_...and {len(findings) - max_findings} more finding(s)_",
                        }
                    ],
                }
            )

        blocks.append({"type": "divider"})
        blocks.append(
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": "Generated by Security Scanner v0.1.0"}
                ],
            }
        )

        return {"blocks": blocks}
