"""Base protocol for scanner modules."""

from typing import Any, Protocol


class BaseScannerProtocol(Protocol):
    """Protocol defining the scanner interface."""

    async def scan(self, target: str) -> dict[str, Any]:
        """
        Perform a scan on the target.

        Args:
            target: Target to scan (domain, URL, etc.)

        Returns:
            Dictionary with scan results
        """
        ...

    async def close(self) -> None:
        """Close any resources and cleanup."""
        ...
