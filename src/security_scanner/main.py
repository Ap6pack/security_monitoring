"""CLI interface for the security scanner."""

import asyncio
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from security_scanner import __version__
from security_scanner.config import Settings, load_settings
from security_scanner.orchestrator import ScanOrchestrator
from security_scanner.storage.database import DatabaseManager
from security_scanner.utils.logger import get_logger, setup_logging

app = typer.Typer(
    name="security-scanner",
    help="Professional security scanning tool for cross-origin web attack vulnerabilities",
    add_completion=False,
)
console = Console()


def version_callback(value: bool) -> None:
    """Show version and exit."""
    if value:
        console.print(f"Security Scanner v{__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-v",
        callback=version_callback,
        is_eager=True,
        help="Show version and exit",
    ),
) -> None:
    """Security Scanner CLI."""
    pass


@app.command()
def scan(
    domains: Optional[list[str]] = typer.Option(
        None,
        "--domain",
        "-d",
        help="Domain to scan (can be specified multiple times)",
    ),
    domains_file: Optional[Path] = typer.Option(
        None,
        "--domains-file",
        "-f",
        help="File containing domains to scan (one per line)",
    ),
    config_file: Optional[Path] = typer.Option(
        None,
        "--config",
        "-c",
        help="Configuration file path",
    ),
    output_dir: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output directory for reports",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-V",
        help="Enable verbose logging",
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet",
        "-q",
        help="Minimal output",
    ),
) -> None:
    """
    Scan domains for security vulnerabilities.

    Examples:
        # Scan a single domain
        security-scanner scan -d example.com

        # Scan multiple domains
        security-scanner scan -d example.com -d test.com

        # Scan domains from file
        security-scanner scan -f domains.txt
    """
    # Load settings
    settings = load_settings()

    # Setup logging
    log_level = "DEBUG" if verbose else "WARNING" if quiet else settings.log_level
    setup_logging(
        log_level=log_level,
        log_file=settings.log_file,
        log_format=settings.log_format,
        debug=settings.debug or verbose,
    )

    logger = get_logger(__name__)

    # Load domains
    target_domains: list[str] = []

    if domains:
        target_domains.extend(domains)

    if domains_file:
        if not domains_file.exists():
            console.print(f"[red]Error: Domains file not found: {domains_file}[/red]")
            raise typer.Exit(1)

        with open(domains_file) as f:
            file_domains = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            target_domains.extend(file_domains)

    if not target_domains:
        console.print("[red]Error: No domains specified. Use --domain or --domains-file[/red]")
        raise typer.Exit(1)

    console.print(f"\n[bold]Security Scanner v{__version__}[/bold]\n")
    console.print(f"Scanning {len(target_domains)} domain(s)...\n")

    # Run scan
    try:
        asyncio.run(_run_scan(settings, target_domains))
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        raise typer.Exit(130)
    except Exception as e:
        logger.error("Scan failed", error=str(e))
        console.print(f"\n[red]Error: {e}[/red]")
        raise typer.Exit(1)


async def _run_scan(settings: Settings, domains: list[str]) -> None:
    """Run the scan asynchronously."""
    # Initialize database
    db = DatabaseManager(settings.database_path)
    await db.initialize()

    # Run scan
    async with ScanOrchestrator(settings, db) as orchestrator:
        result = await orchestrator.scan(domains)

        # Display results
        console.print("\n[bold green]Scan Complete![/bold green]\n")
        console.print(f"Scan ID: {result['scan_id']}")
        console.print(f"Domains: {', '.join(result['domains'])}\n")

        # Summary table
        summary = result["summary"]
        table = Table(title="Findings Summary")
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")

        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = summary.get(severity, 0)
            color = {
                "CRITICAL": "red",
                "HIGH": "orange1",
                "MEDIUM": "yellow",
                "LOW": "blue",
            }[severity]
            table.add_row(f"[{color}]{severity}[/{color}]", str(count))

        console.print(table)
        console.print(f"\nTotal findings: {len(result['findings'])}\n")

        # Show critical findings
        critical_findings = [f for f in result["findings"] if f.severity == "CRITICAL"]
        if critical_findings:
            console.print("[bold red]Critical Findings:[/bold red]\n")
            for finding in critical_findings[:5]:
                console.print(f"  • {finding.domain}: {finding.description[:80]}...")


@app.command()
def init_db() -> None:
    """Initialize the database."""
    settings = load_settings()
    console.print("Initializing database...")

    try:
        db = DatabaseManager(settings.database_path)
        asyncio.run(db.initialize())
        console.print(f"[green]Database initialized: {settings.database_path}[/green]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def list_scans(
    limit: int = typer.Option(10, "--limit", "-l", help="Number of scans to show"),
) -> None:
    """List recent scans."""
    settings = load_settings()
    db = DatabaseManager(settings.database_path)

    try:
        scans = asyncio.run(db.list_scans(limit))

        if not scans:
            console.print("No scans found.")
            return

        table = Table(title=f"Recent Scans (Last {limit})")
        table.add_column("Scan ID", style="cyan")
        table.add_column("Start Time")
        table.add_column("Status")
        table.add_column("Domains")
        table.add_column("Findings", justify="right")

        for scan in scans:
            status_color = "green" if scan.status == "completed" else "yellow"
            table.add_row(
                scan.id[:8] + "...",
                scan.start_time.strftime("%Y-%m-%d %H:%M"),
                f"[{status_color}]{scan.status}[/{status_color}]",
                str(len(scan.domains_scanned)),
                str(scan.total_findings),
            )

        console.print(table)

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def report(
    scan_id: str = typer.Option(..., "--scan-id", "-s", help="Scan ID to generate report for"),
    format: str = typer.Option(
        "html,json",
        "--format",
        "-f",
        help="Report formats (comma-separated: html,json,markdown,csv)",
    ),
    output_dir: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output directory for reports",
    ),
) -> None:
    """
    Generate reports from a previous scan.

    Examples:
        # Generate HTML report
        security-scanner report --scan-id <SCAN_ID> --format html

        # Generate multiple formats
        security-scanner report --scan-id <SCAN_ID> --format html,json,markdown
    """
    settings = load_settings()

    # Use provided output dir or default from settings
    report_dir = output_dir if output_dir else settings.report_output_dir
    report_dir.mkdir(parents=True, exist_ok=True)

    # Parse formats
    formats = [f.strip().lower() for f in format.split(",")]
    valid_formats = {"html", "json", "markdown", "csv"}
    invalid = set(formats) - valid_formats
    if invalid:
        console.print(f"[red]Error: Invalid format(s): {', '.join(invalid)}[/red]")
        console.print(f"Valid formats: {', '.join(valid_formats)}")
        raise typer.Exit(1)

    try:
        asyncio.run(_generate_report(settings, scan_id, formats, report_dir))
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


async def _generate_report(
    settings: Settings,
    scan_id: str,
    formats: list[str],
    output_dir: Path,
) -> None:
    """Generate reports asynchronously."""
    from security_scanner.reporters.csv_reporter import CSVReporter
    from security_scanner.reporters.html_reporter import HTMLReporter
    from security_scanner.reporters.json_reporter import JSONReporter
    from security_scanner.reporters.markdown_reporter import MarkdownReporter

    db = DatabaseManager(settings.database_path)

    # Get scan data
    scan = await db.get_scan(scan_id)
    if not scan:
        console.print(f"[red]Error: Scan not found: {scan_id}[/red]")
        raise typer.Exit(1)

    # Get findings
    findings = await db.get_scan_findings(scan_id)

    console.print(f"\nGenerating reports for scan {scan_id[:8]}...")
    console.print(f"Found {len(findings)} findings\n")

    # Build scan results dictionary
    findings_by_severity = {
        "CRITICAL": sum(1 for f in findings if f.severity == "CRITICAL"),
        "HIGH": sum(1 for f in findings if f.severity == "HIGH"),
        "MEDIUM": sum(1 for f in findings if f.severity == "MEDIUM"),
        "LOW": sum(1 for f in findings if f.severity == "LOW"),
    }

    scan_results = {
        "scan_id": scan.id,
        "start_time": scan.start_time,
        "end_time": scan.end_time,
        "duration_seconds": scan.duration_seconds,
        "domains": scan.domains_scanned,
        "status": scan.status,
        "scanner_version": scan.scanner_version,
        "findings": findings,
        "summary": findings_by_severity,
    }

    # Generate reports
    reporters = {
        "json": JSONReporter(),
        "html": HTMLReporter(),
        "markdown": MarkdownReporter(),
        "csv": CSVReporter(),
    }

    generated = []
    for fmt in formats:
        reporter = reporters[fmt]
        filename = f"scan_{scan_id[:8]}_report.{fmt if fmt != 'markdown' else 'md'}"
        output_path = output_dir / filename

        reporter.generate(
            scan_results=scan_results,
            output_path=output_path,
        )

        generated.append(output_path)
        console.print(f"[green]✓[/green] {fmt.upper()} report: {output_path}")

    console.print(f"\n[bold green]Reports generated successfully![/bold green]")


@app.command()
def validate_config(
    config_file: Optional[Path] = typer.Option(
        None,
        "--config",
        "-c",
        help="Configuration file to validate",
    ),
) -> None:
    """Validate configuration."""
    try:
        settings = load_settings()
        console.print("[green]✓ Configuration is valid[/green]")
        console.print(f"\nDatabase: {settings.database_path}")
        console.print(f"Log level: {settings.log_level}")
        console.print(f"DNS nameservers: {', '.join(settings.dns_nameservers)}")
        console.print(f"Subdomain sources: {', '.join(settings.subdomain_sources)}")
    except Exception as e:
        console.print(f"[red]✗ Configuration error: {e}[/red]")
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
