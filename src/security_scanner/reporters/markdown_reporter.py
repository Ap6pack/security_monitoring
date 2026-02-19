"""Markdown report generator."""

from datetime import datetime
from pathlib import Path
from typing import Any

from security_scanner.utils.exceptions import ReporterError
from security_scanner.utils.logger import get_logger

logger = get_logger(__name__)


class MarkdownReporter:
    """
    Generate executive summary reports in Markdown format.

    Produces a human-readable Markdown report suitable for:
    - Executive briefings
    - Documentation
    - README files
    - GitHub/GitLab issue reporting
    """

    def get_file_extension(self) -> str:
        """Get the file extension for Markdown reports."""
        return ".md"

    def generate(
        self,
        scan_results: dict[str, Any],
        output_path: Path,
    ) -> None:
        """
        Generate a Markdown report.

        Args:
            scan_results: Scan results dictionary
            output_path: Output file path

        Raises:
            ReporterError: If report generation fails
        """
        try:
            logger.info("Generating Markdown report", output=str(output_path))

            # Ensure parent directory exists
            output_path.parent.mkdir(parents=True, exist_ok=True)

            findings = scan_results.get("findings", [])
            summary = scan_results.get("summary", {})
            domains = scan_results.get("domains", [])

            # Generate markdown content
            content = self._generate_content(
                scan_results.get("scan_id", "N/A"),
                domains,
                findings,
                summary,
            )

            # Write markdown file
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(content)

            logger.info(
                "Markdown report generated successfully",
                output=str(output_path),
                findings_count=len(findings),
            )

        except Exception as e:
            logger.error("Failed to generate Markdown report", error=str(e))
            raise ReporterError(f"Markdown report generation failed: {e}") from e

    def _generate_content(
        self,
        scan_id: str,
        domains: list[str],
        findings: list[Any],
        summary: dict[str, int],
    ) -> str:
        """Generate the markdown content."""
        lines = [
            "# Security Scan Report",
            "",
            f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"**Scan ID:** `{scan_id}`",
            "**Scanner Version:** 0.1.0",
            "",
            "## Executive Summary",
            "",
            f"Scanned **{len(domains)}** domain(s) and discovered **{len(findings)}** security finding(s).",
            "",
            "### Domains Scanned",
            "",
        ]

        for domain in domains:
            lines.append(f"- `{domain}`")

        lines.extend(
            [
                "",
                "### Findings by Severity",
                "",
                "| Severity | Count |",
                "| -------- | ----- |",
            ]
        )

        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = summary.get(severity, 0)
            emoji = {
                "CRITICAL": "🔴",
                "HIGH": "🟠",
                "MEDIUM": "🟡",
                "LOW": "🟢",
            }.get(severity, "⚪")
            lines.append(f"| {emoji} {severity} | {count} |")

        lines.extend(["", f"**Total Findings:** {len(findings)}", ""])

        # Group findings by severity
        by_severity: dict[str, list[Any]] = {
            "CRITICAL": [],
            "HIGH": [],
            "MEDIUM": [],
            "LOW": [],
        }

        for finding in findings:
            severity = getattr(finding, "severity", "UNKNOWN")
            if severity in by_severity:
                by_severity[severity].append(finding)

        # Add detailed findings
        lines.append("## Detailed Findings")
        lines.append("")

        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            severity_findings = by_severity[severity]
            if not severity_findings:
                continue

            emoji = {
                "CRITICAL": "🔴",
                "HIGH": "🟠",
                "MEDIUM": "🟡",
                "LOW": "🟢",
            }.get(severity, "⚪")

            lines.append(f"### {emoji} {severity} Severity ({len(severity_findings)})")
            lines.append("")

            for i, finding in enumerate(severity_findings, 1):
                domain = getattr(finding, "domain", "N/A")
                finding_type = getattr(finding, "type", "UNKNOWN")
                cvss = getattr(finding, "cvss_score", 0.0)
                description = getattr(finding, "description", "No description")
                remediation = getattr(finding, "remediation", "No remediation provided")

                # Generate title from type
                title = self._generate_title(finding_type, domain)

                lines.extend(
                    [
                        f"#### {i}. {title}",
                        "",
                        f"**Domain:** `{domain}`",
                        f"**Type:** {finding_type}",
                        f"**CVSS Score:** {cvss}",
                        "",
                        "**Description:**",
                        "",
                        description,
                        "",
                        "**Remediation:**",
                        "",
                        remediation,
                        "",
                        "---",
                        "",
                    ]
                )

        # Add footer
        lines.extend(
            [
                "## Recommendations",
                "",
                "1. **Prioritize CRITICAL and HIGH severity findings** for immediate remediation",
                "2. **Review DNS configurations** for all flagged domains",
                "3. **Remove or reclaim** dangling DNS records",
                "4. **Implement monitoring** for subdomain takeover attempts",
                "5. **Conduct regular scans** to detect new vulnerabilities",
                "",
                "---",
                "",
                "*Report generated by Security Scanner v0.1.0*",
                "",
            ]
        )

        return "\n".join(lines)

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
