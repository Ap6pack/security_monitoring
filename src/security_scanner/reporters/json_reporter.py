"""JSON report generator."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from security_scanner.utils.exceptions import ReporterError
from security_scanner.utils.logger import get_logger

logger = get_logger(__name__)


class JSONReporter:
    """
    Generate detailed JSON reports.

    Produces a comprehensive JSON file containing all scan results,
    findings, and metadata in a structured format suitable for:
    - Automated processing
    - Integration with other tools
    - Long-term storage and archival
    """

    def get_file_extension(self) -> str:
        """Get the file extension for JSON reports."""
        return ".json"

    def generate(
        self,
        scan_results: dict[str, Any],
        output_path: Path,
    ) -> None:
        """
        Generate a JSON report.

        Args:
            scan_results: Scan results dictionary
            output_path: Output file path

        Raises:
            ReporterError: If report generation fails
        """
        try:
            logger.info("Generating JSON report", output=str(output_path))

            # Ensure parent directory exists
            output_path.parent.mkdir(parents=True, exist_ok=True)

            # Prepare report data
            report_data = {
                "scan_metadata": {
                    "scan_id": scan_results.get("scan_id"),
                    "generated_at": datetime.now().isoformat(),
                    "scanner_version": "0.1.0",
                    "domains_scanned": scan_results.get("domains", []),
                },
                "summary": {
                    "total_findings": len(scan_results.get("findings", [])),
                    "by_severity": scan_results.get("summary", {}),
                },
                "findings": [
                    self._format_finding(finding) for finding in scan_results.get("findings", [])
                ],
            }

            # Write JSON with pretty formatting
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False, default=str)

            logger.info(
                "JSON report generated successfully",
                output=str(output_path),
                findings_count=len(scan_results.get("findings", [])),
            )

        except Exception as e:
            logger.error("Failed to generate JSON report", error=str(e))
            raise ReporterError(f"JSON report generation failed: {e}") from e

    def _format_finding(self, finding: Any) -> dict[str, Any]:
        """
        Format a finding for JSON output.

        Args:
            finding: Finding object

        Returns:
            Dictionary representation of the finding
        """
        return {
            "id": getattr(finding, "id", None),
            "severity": getattr(finding, "severity", "UNKNOWN"),
            "type": getattr(finding, "type", "UNKNOWN"),
            "domain": getattr(finding, "domain", ""),
            "title": getattr(finding, "title", ""),
            "description": getattr(finding, "description", ""),
            "cvss_score": getattr(finding, "cvss_score", 0.0),
            "remediation": getattr(finding, "remediation", ""),
            "detected_at": str(getattr(finding, "detected_at", "")),
            "metadata": getattr(finding, "raw_data", {}),
        }
