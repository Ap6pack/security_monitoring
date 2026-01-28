"""CSV report generator."""

import csv
from pathlib import Path
from typing import Any

from security_scanner.utils.exceptions import ReporterError
from security_scanner.utils.logger import get_logger

logger = get_logger(__name__)


class CSVReporter:
    """
    Generate CSV reports for spreadsheet analysis.

    Produces a CSV file with findings in a tabular format suitable for:
    - Excel/Google Sheets import
    - Data analysis and filtering
    - Sharing with non-technical stakeholders
    """

    def get_file_extension(self) -> str:
        """Get the file extension for CSV reports."""
        return ".csv"

    def generate(
        self,
        scan_results: dict[str, Any],
        output_path: Path,
    ) -> None:
        """
        Generate a CSV report.

        Args:
            scan_results: Scan results dictionary
            output_path: Output file path

        Raises:
            ReporterError: If report generation fails
        """
        try:
            logger.info("Generating CSV report", output=str(output_path))

            # Ensure parent directory exists
            output_path.parent.mkdir(parents=True, exist_ok=True)

            findings = scan_results.get("findings", [])

            # Define CSV columns
            fieldnames = [
                "Severity",
                "Type",
                "Domain",
                "Title",
                "CVSS Score",
                "Description",
                "Remediation",
                "Detected At",
            ]

            # Write CSV
            with open(output_path, "w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()

                for finding in findings:
                    writer.writerow(
                        {
                            "Severity": getattr(finding, "severity", "UNKNOWN"),
                            "Type": getattr(finding, "type", "UNKNOWN"),
                            "Domain": getattr(finding, "domain", ""),
                            "Title": getattr(finding, "title", ""),
                            "CVSS Score": getattr(finding, "cvss_score", 0.0),
                            "Description": getattr(finding, "description", "")[:200],
                            "Remediation": getattr(finding, "remediation", "")[:200],
                            "Detected At": str(getattr(finding, "detected_at", "")),
                        }
                    )

            logger.info(
                "CSV report generated successfully",
                output=str(output_path),
                findings_count=len(findings),
            )

        except Exception as e:
            logger.error("Failed to generate CSV report", error=str(e))
            raise ReporterError(f"CSV report generation failed: {e}") from e
