"""Email alerter using SMTP."""

import smtplib
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

from security_scanner.utils.exceptions import AlerterError
from security_scanner.utils.logger import get_logger

logger = get_logger(__name__)


class EmailAlerter:
    """
    Send alert notifications via email using SMTP.

    Supports:
    - HTML formatted emails
    - Multiple recipients
    - Severity-based filtering
    - TLS/SSL encryption
    """

    # Severity hierarchy for filtering
    SEVERITY_LEVELS = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
    }

    def __init__(
        self,
        smtp_host: str,
        smtp_port: int,
        smtp_user: str,
        smtp_password: str,
        from_email: str,
        to_emails: list[str],
        use_tls: bool = True,
    ) -> None:
        """
        Initialize the email alerter.

        Args:
            smtp_host: SMTP server hostname
            smtp_port: SMTP server port
            smtp_user: SMTP username
            smtp_password: SMTP password
            from_email: Sender email address
            to_emails: List of recipient email addresses
            use_tls: Whether to use TLS encryption
        """
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.smtp_user = smtp_user
        self.smtp_password = smtp_password
        self.from_email = from_email
        self.to_emails = to_emails
        self.use_tls = use_tls

    async def send(
        self,
        findings: list[Any],
        scan_id: str,
        severity_threshold: str = "HIGH",
    ) -> bool:
        """
        Send email alert for findings.

        Args:
            findings: List of security findings
            scan_id: Scan identifier
            severity_threshold: Minimum severity to include

        Returns:
            True if email was sent successfully

        Raises:
            AlerterError: If email sending fails
        """
        try:
            # Filter findings by severity
            filtered_findings = [f for f in findings if self.should_alert(f, severity_threshold)]

            if not filtered_findings:
                logger.info(
                    "No findings meet alert threshold",
                    threshold=severity_threshold,
                    total_findings=len(findings),
                )
                return False

            logger.info(
                "Sending email alert",
                scan_id=scan_id,
                findings_count=len(filtered_findings),
                recipients=len(self.to_emails),
            )

            # Create email message
            msg = self._create_message(filtered_findings, scan_id)

            # Send email
            self._send_smtp(msg)

            logger.info(
                "Email alert sent successfully",
                scan_id=scan_id,
                recipients=len(self.to_emails),
            )

            return True

        except Exception as e:
            logger.error("Failed to send email alert", error=str(e))
            raise AlerterError(f"Email alert failed: {e}") from e

    def should_alert(self, finding: Any, severity_threshold: str) -> bool:
        """Check if finding meets alert threshold."""
        finding_severity = getattr(finding, "severity", "LOW")
        return self.SEVERITY_LEVELS.get(finding_severity, 0) >= self.SEVERITY_LEVELS.get(
            severity_threshold, 0
        )

    def _create_message(self, findings: list[Any], scan_id: str) -> MIMEMultipart:
        """Create email message with HTML content."""
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"🚨 Security Alert: {len(findings)} Finding(s) - Scan {scan_id[:8]}"
        msg["From"] = self.from_email
        msg["To"] = ", ".join(self.to_emails)

        # Create HTML content
        html_content = self._generate_html(findings, scan_id)

        # Attach HTML part
        html_part = MIMEText(html_content, "html")
        msg.attach(html_part)

        return msg

    def _generate_html(self, findings: list[Any], scan_id: str) -> str:
        """Generate HTML email content."""
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

        # Build HTML
        html_parts = [
            "<!DOCTYPE html>",
            "<html>",
            "<head>",
            "<style>",
            "body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }",
            ".header { background: #dc2626; color: white; padding: 20px; border-radius: 5px; }",
            ".summary { background: #f3f4f6; padding: 15px; margin: 20px 0; border-radius: 5px; }",
            ".finding { margin: 15px 0; padding: 15px; border-left: 4px solid; border-radius: 4px; }",
            ".critical { background: #fef2f2; border-color: #dc2626; }",
            ".high { background: #fff7ed; border-color: #ea580c; }",
            ".medium { background: #fefce8; border-color: #ca8a04; }",
            ".low { background: #f0fdf4; border-color: #16a34a; }",
            ".badge { padding: 4px 8px; border-radius: 3px; font-size: 12px; font-weight: bold; }",
            ".badge.critical { background: #dc2626; color: white; }",
            ".badge.high { background: #ea580c; color: white; }",
            ".badge.medium { background: #ca8a04; color: white; }",
            ".badge.low { background: #16a34a; color: white; }",
            "</style>",
            "</head>",
            "<body>",
            '<div class="header">',
            "<h1>🚨 Security Alert</h1>",
            f"<p>Scan ID: {scan_id}</p>",
            f"<p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>",
            "</div>",
            '<div class="summary">',
            f"<h2>Summary: {len(findings)} Finding(s)</h2>",
            "<ul>",
        ]

        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = len(by_severity[severity])
            if count > 0:
                emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(
                    severity, "⚪"
                )
                html_parts.append(f"<li>{emoji} {severity}: {count}</li>")

        html_parts.append("</ul></div>")

        # Add findings by severity
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            severity_findings = by_severity[severity]
            if not severity_findings:
                continue

            html_parts.append(f"<h3>{severity} Severity</h3>")

            for finding in severity_findings:
                domain = getattr(finding, "domain", "N/A")
                title = getattr(finding, "title", "Untitled")
                description = getattr(finding, "description", "No description")
                remediation = getattr(finding, "remediation", "No remediation")

                html_parts.extend(
                    [
                        f'<div class="finding {severity.lower()}">',
                        f'<span class="badge {severity.lower()}">{severity}</span>',
                        f"<h4>{title}</h4>",
                        f"<p><strong>Domain:</strong> <code>{domain}</code></p>",
                        f"<p><strong>Description:</strong> {description}</p>",
                        f"<p><strong>Remediation:</strong> {remediation}</p>",
                        "</div>",
                    ]
                )

        html_parts.extend(
            [
                "<hr>",
                "<p><small>Generated by Security Scanner v0.1.0</small></p>",
                "</body>",
                "</html>",
            ]
        )

        return "\n".join(html_parts)

    def _send_smtp(self, msg: MIMEMultipart) -> None:
        """Send email via SMTP."""
        try:
            if self.use_tls:
                server = smtplib.SMTP(self.smtp_host, self.smtp_port)
                server.starttls()
            else:
                server = smtplib.SMTP(self.smtp_host, self.smtp_port)

            server.login(self.smtp_user, self.smtp_password)
            server.sendmail(self.from_email, self.to_emails, msg.as_string())
            server.quit()

        except smtplib.SMTPException as e:
            raise AlerterError(f"SMTP error: {e}") from e
