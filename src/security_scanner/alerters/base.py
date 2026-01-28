"""Base alerter protocol."""

from typing import Any, Protocol


class BaseAlerter(Protocol):
    """
    Protocol for alert notification systems.

    All alerters must implement the send method that takes
    findings and sends notifications through their channel.
    """

    async def send(
        self,
        findings: list[Any],
        scan_id: str,
        severity_threshold: str = "HIGH",
    ) -> bool:
        """
        Send alert notification for findings.

        Args:
            findings: List of security findings to alert on
            scan_id: Unique scan identifier
            severity_threshold: Minimum severity to alert (CRITICAL, HIGH, MEDIUM, LOW)

        Returns:
            True if alert was sent successfully, False otherwise

        Raises:
            AlerterError: If alert sending fails
        """
        ...

    def should_alert(self, finding: Any, severity_threshold: str) -> bool:
        """
        Determine if a finding meets the alert criteria.

        Args:
            finding: Security finding to check
            severity_threshold: Minimum severity threshold

        Returns:
            True if finding should trigger an alert
        """
        ...
