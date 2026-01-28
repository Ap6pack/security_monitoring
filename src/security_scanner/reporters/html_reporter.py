"""HTML report generator using Jinja2 templates."""

from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, TemplateNotFound

from security_scanner.utils.exceptions import ReporterError
from security_scanner.utils.logger import get_logger

logger = get_logger(__name__)


class HTMLReporter:
    """
    Generate HTML reports with Jinja2 templates.

    Produces a professional HTML report with:
    - Executive summary dashboard
    - Interactive severity filtering
    - Detailed finding cards
    - Print-friendly styling
    """

    def __init__(self) -> None:
        """Initialize the HTML reporter with Jinja2 environment."""
        template_dir = Path(__file__).parent / "templates"
        self.env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=True,
        )

    def get_file_extension(self) -> str:
        """Get the file extension for HTML reports."""
        return ".html"

    def generate(
        self,
        scan_results: dict[str, Any],
        output_path: Path,
    ) -> None:
        """
        Generate an HTML report.

        Args:
            scan_results: Scan results dictionary
            output_path: Output file path

        Raises:
            ReporterError: If report generation fails
        """
        try:
            logger.info("Generating HTML report", output=str(output_path))

            # Ensure parent directory exists
            output_path.parent.mkdir(parents=True, exist_ok=True)

            # Load template
            try:
                template = self.env.get_template("report.html")
            except TemplateNotFound as e:
                raise ReporterError(f"Template not found: {e}") from e

            # Prepare template data
            findings = scan_results.get("findings", [])
            template_data = {
                "scan_id": scan_results.get("scan_id", "N/A"),
                "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "scanner_version": "0.1.0",
                "domains": scan_results.get("domains", []),
                "total_findings": len(findings),
                "summary": scan_results.get("summary", {}),
                "findings_by_severity": self._group_findings_by_severity(findings),
            }

            # Render template
            html_content = template.render(**template_data)

            # Write HTML file
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(html_content)

            logger.info(
                "HTML report generated successfully",
                output=str(output_path),
                findings_count=len(findings),
            )

        except ReporterError:
            raise
        except Exception as e:
            logger.error("Failed to generate HTML report", error=str(e))
            raise ReporterError(f"HTML report generation failed: {e}") from e

    def _group_findings_by_severity(self, findings: list[Any]) -> dict[str, list[dict[str, Any]]]:
        """
        Group findings by severity level.

        Args:
            findings: List of finding objects

        Returns:
            Dictionary mapping severity to list of formatted findings
        """
        grouped: dict[str, list[dict[str, Any]]] = {
            "CRITICAL": [],
            "HIGH": [],
            "MEDIUM": [],
            "LOW": [],
        }

        for finding in findings:
            severity = getattr(finding, "severity", "UNKNOWN")
            if severity in grouped:
                domain = getattr(finding, "domain", "N/A")
                finding_type = getattr(finding, "type", "UNKNOWN")

                formatted = {
                    "title": self._generate_title(finding_type, domain),
                    "domain": domain,
                    "type": finding_type,
                    "cvss_score": getattr(finding, "cvss_score", 0.0),
                    "description": getattr(finding, "description", "No description"),
                    "remediation": getattr(finding, "remediation", "No remediation"),
                    "detected_at": str(getattr(finding, "detected_at", "N/A")),
                }
                grouped[severity].append(formatted)

        return grouped

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
