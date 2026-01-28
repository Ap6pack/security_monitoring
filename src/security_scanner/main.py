"""CLI interface for the security scanner."""

import asyncio
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from security_scanner import __version__
from security_scanner.config import load_settings
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


async def _run_scan(settings, domains: list[str]) -> None:
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
        summary = result['summary']
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
        critical_findings = [f for f in result['findings'] if f.severity == "CRITICAL"]
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
