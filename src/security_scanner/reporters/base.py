"""Base reporter protocol."""

from pathlib import Path
from typing import Any, Protocol


class BaseReporter(Protocol):
    """
    Protocol for report generators.

    All reporters must implement the generate method that takes
    scan results and produces output in their specific format.
    """

    def generate(
        self,
        scan_results: dict[str, Any],
        output_path: Path,
    ) -> None:
        """
        Generate a report from scan results.

        Args:
            scan_results: Dictionary containing scan results with keys:
                - scan_id: Unique scan identifier
                - domains: List of scanned domains
                - findings: List of security findings
                - summary: Findings summary by severity
            output_path: Path where the report should be saved

        Raises:
            ReporterError: If report generation fails
        """
        ...

    def get_file_extension(self) -> str:
        """
        Get the file extension for this report format.

        Returns:
            File extension (e.g., '.json', '.html', '.md', '.csv')
        """
        ...
