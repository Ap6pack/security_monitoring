"""Example of generating reports from scan results."""

import asyncio
from datetime import datetime
from pathlib import Path

from security_scanner.reporters import (
    CSVReporter,
    HTMLReporter,
    JSONReporter,
    MarkdownReporter,
)


class ExampleFinding:
    """Example finding for demonstration."""

    def __init__(
        self,
        severity: str,
        domain: str,
        title: str,
        description: str,
    ) -> None:
        self.id = f"finding-{domain}"
        self.severity = severity
        self.type = "DANGLING_DNS"
        self.domain = domain
        self.title = title
        self.description = description
        self.cvss_score = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.0}.get(
            severity, 5.0
        )
        self.remediation = f"Remove the dangling DNS record for {domain}"
        self.detected_at = datetime.now()
        self.raw_data = {"target": "deleted-service.example.com"}


def create_sample_results() -> dict:
    """Create sample scan results."""
    return {
        "scan_id": "example-scan-2026-01-28",
        "domains": ["example.com", "test.com", "api.example.com"],
        "findings": [
            ExampleFinding(
                "CRITICAL",
                "old.example.com",
                "Dangling DNS Record - Critical Risk",
                "DNS CNAME record points to a deleted cloud service, allowing complete subdomain takeover.",
            ),
            ExampleFinding(
                "HIGH",
                "api.example.com",
                "Potential Subdomain Takeover",
                "Subdomain appears vulnerable to takeover attack via unclaimed cloud resource.",
            ),
            ExampleFinding(
                "MEDIUM",
                "dev.test.com",
                "Unresponsive Subdomain",
                "Subdomain does not respond to HTTP requests but DNS resolves.",
            ),
            ExampleFinding(
                "LOW",
                "legacy.test.com",
                "Deprecated Configuration",
                "Subdomain uses deprecated DNS configuration pattern.",
            ),
        ],
        "summary": {
            "CRITICAL": 1,
            "HIGH": 1,
            "MEDIUM": 1,
            "LOW": 1,
        },
    }


async def main() -> None:
    """Generate example reports in all formats."""
    # Create output directory
    output_dir = Path("reports/examples")
    output_dir.mkdir(parents=True, exist_ok=True)

    # Get sample results
    results = create_sample_results()

    # Generate JSON report
    print("Generating JSON report...")
    json_reporter = JSONReporter()
    json_reporter.generate(results, output_dir / "report.json")
    print(f"✓ JSON report: {output_dir / 'report.json'}")

    # Generate HTML report
    print("Generating HTML report...")
    html_reporter = HTMLReporter()
    html_reporter.generate(results, output_dir / "report.html")
    print(f"✓ HTML report: {output_dir / 'report.html'}")

    # Generate Markdown report
    print("Generating Markdown report...")
    md_reporter = MarkdownReporter()
    md_reporter.generate(results, output_dir / "report.md")
    print(f"✓ Markdown report: {output_dir / 'report.md'}")

    # Generate CSV report
    print("Generating CSV report...")
    csv_reporter = CSVReporter()
    csv_reporter.generate(results, output_dir / "report.csv")
    print(f"✓ CSV report: {output_dir / 'report.csv'}")

    print(f"\n✅ All reports generated successfully in {output_dir}")
    print(f"\nOpen the HTML report in your browser:")
    print(f"  file://{output_dir.absolute()}/report.html")


if __name__ == "__main__":
    asyncio.run(main())
