"""Base protocol for detectors."""

from typing import Any, Protocol

from security_scanner.storage.models import Finding


class BaseDetectorProtocol(Protocol):
    """Protocol defining the detector interface."""

    async def detect(self, data: dict[str, Any]) -> list[Finding]:
        """
        Analyze data and detect security issues.

        Args:
            data: Data to analyze

        Returns:
            List of findings
        """
        ...
