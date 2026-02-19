"""Report generation endpoints."""

import re

from fastapi import APIRouter, Depends, HTTPException, status

from security_scanner.api.auth import verify_api_key
from security_scanner.api.dependencies import get_db, get_settings
from security_scanner.api.models import ErrorResponse, ReportGeneratedResponse, ReportRequest
from security_scanner.config import Settings
from security_scanner.reporters.base import BaseReporter
from security_scanner.reporters.csv_reporter import CSVReporter
from security_scanner.reporters.html_reporter import HTMLReporter
from security_scanner.reporters.json_reporter import JSONReporter
from security_scanner.reporters.markdown_reporter import MarkdownReporter
from security_scanner.storage.database import DatabaseManager

router = APIRouter(
    tags=["reports"],
    dependencies=[Depends(verify_api_key)],
)

VALID_FORMATS = {"json", "html", "markdown", "csv"}

_UUID_PATTERN = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def _build_reporters() -> dict[str, BaseReporter]:
    """Create reporter instances per request to avoid shared state."""
    return {
        "json": JSONReporter(),
        "html": HTMLReporter(),
        "markdown": MarkdownReporter(),
        "csv": CSVReporter(),
    }


@router.post(
    "/scans/{scan_id}/reports",
    response_model=ReportGeneratedResponse,
    responses={404: {"model": ErrorResponse}, 400: {"model": ErrorResponse}},
)
async def generate_reports(
    scan_id: str,
    request: ReportRequest | None = None,
    settings: Settings = Depends(get_settings),
    db: DatabaseManager = Depends(get_db),
) -> ReportGeneratedResponse:
    """Generate reports for a completed scan."""
    # Validate scan_id format to prevent path traversal
    if not _UUID_PATTERN.match(scan_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid scan_id format (expected UUID)",
        )

    formats = (request.formats if request else None) or ["json"]
    invalid = set(formats) - VALID_FORMATS
    if invalid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid format(s): {', '.join(sorted(invalid))}. "
            f"Valid: {', '.join(sorted(VALID_FORMATS))}",
        )

    scan = await db.get_scan(scan_id)
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan not found: {scan_id}",
        )

    findings = await db.get_scan_findings(scan_id)

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

    output_dir = settings.report_output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    reporters = _build_reporters()
    generated: list[str] = []
    for fmt in formats:
        reporter = reporters[fmt]
        ext = "md" if fmt == "markdown" else fmt
        filename = f"scan_{scan_id[:8]}_report.{ext}"
        output_path = output_dir / filename

        reporter.generate(scan_results=scan_results, output_path=output_path)
        generated.append(str(output_path))

    return ReportGeneratedResponse(
        scan_id=scan_id,
        reports=generated,
    )
