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
                    domain = getattr(finding, "domain", "")
                    finding_type = getattr(finding, "type", "UNKNOWN")

                    writer.writerow(
                        {
                            "Severity": getattr(finding, "severity", "UNKNOWN"),
                            "Type": finding_type,
                            "Domain": domain,
                            "Title": self._generate_title(finding_type, domain),
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

    def _generate_title(self, finding_type: str, domain: str) -> str:
        """
        Generate a descriptive title for a finding.

        Args:
            finding_type: Type of finding
            domain: Affected domain

        Returns:
            Descriptive title string
        """
        type_titles = {
            "dangling_cname": "Dangling CNAME Record",
            "dangling_dns": "Dangling DNS Record",
            "subdomain_takeover": "Potential Subdomain Takeover",
            "takeover_heroku": "Heroku Subdomain Takeover Risk",
            "takeover_github": "GitHub Pages Takeover Risk",
            "takeover_aws_s3": "AWS S3 Bucket Takeover Risk",
            "takeover_aws_eb": "AWS Elastic Beanstalk Takeover Risk",
            "takeover_azure": "Azure Service Takeover Risk",
            "takeover_gcp": "Google Cloud Platform Takeover Risk",
            "takeover_netlify": "Netlify Takeover Risk",
            "takeover_vercel": "Vercel Takeover Risk",
            "certificate_expiring": "Certificate Expiring Soon",
            "certificate_expired": "Expired Certificate",
            "certificate_shared": "Shared Certificate Risk",
            "dns_misconfiguration": "DNS Misconfiguration",
        }

        title = type_titles.get(finding_type, finding_type.replace("_", " ").title())
        return f"{title} - {domain}"
