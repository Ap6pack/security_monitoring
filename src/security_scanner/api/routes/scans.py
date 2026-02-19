"""Scan endpoints."""

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status

from security_scanner.api.auth import verify_api_key
from security_scanner.api.dependencies import get_db, get_orchestrator
from security_scanner.api.models import (
    ErrorResponse,
    FindingResponse,
    ScanCreatedResponse,
    ScanDetailResponse,
    ScanListResponse,
    ScanRequest,
    ScanResponse,
    ScanSummary,
)
from security_scanner.orchestrator import ScanOrchestrator
from security_scanner.storage.database import DatabaseManager
from security_scanner.storage.models import Finding, Scan
from security_scanner.utils.logger import get_logger
from security_scanner.utils.validators import is_valid_domain

logger = get_logger(__name__)

router = APIRouter(
    tags=["scans"],
    dependencies=[Depends(verify_api_key)],
)


def _finding_to_response(finding: Finding) -> FindingResponse:
    """Convert a storage Finding to an API response model."""
    return FindingResponse(
        id=finding.id,
        severity=finding.severity,
        type=finding.type,
        domain=finding.domain,
        record_type=finding.record_type,
        target=finding.target,
        description=finding.description,
        cvss_score=finding.cvss_score,
        remediation=finding.remediation,
        confidence=finding.confidence,
        platform=finding.platform,
        detected_at=finding.detected_at,
    )


def _scan_to_response(scan: Scan) -> ScanResponse:
    """Convert a storage Scan to an API response model."""
    return ScanResponse(
        scan_id=scan.id,
        status=scan.status,
        domains=scan.domains_scanned,
        start_time=scan.start_time,
        end_time=scan.end_time,
        duration_seconds=scan.duration_seconds,
        total_findings=scan.total_findings,
        summary=ScanSummary(
            critical=scan.critical_findings,
            high=scan.high_findings,
            medium=scan.medium_findings,
            low=scan.low_findings,
        ),
    )


async def _run_scan_background(
    orchestrator: ScanOrchestrator,
    db: DatabaseManager,
    scan_id: str,
    domains: list[str],
) -> None:
    """Execute a scan in the background, updating the existing scan record."""
    try:
        result = await orchestrator.scan(domains)
        findings_count = result["summary"]
        from datetime import UTC, datetime

        await db.update_scan(
            scan_id=scan_id,
            end_time=datetime.now(UTC),
            status="completed",
            findings_count=findings_count,
        )
    except Exception:
        logger.exception("Background scan failed", scan_id=scan_id, domains=domains)
        from datetime import UTC, datetime

        try:
            await db.update_scan(
                scan_id=scan_id,
                end_time=datetime.now(UTC),
                status="failed",
                findings_count={},
            )
        except Exception:
            logger.exception("Failed to mark scan as failed", scan_id=scan_id)


@router.post(
    "/scans",
    response_model=ScanCreatedResponse,
    status_code=status.HTTP_202_ACCEPTED,
    responses={400: {"model": ErrorResponse}},
)
async def create_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    orchestrator: ScanOrchestrator = Depends(get_orchestrator),
    db: DatabaseManager = Depends(get_db),
) -> ScanCreatedResponse:
    """Start a new security scan.

    The scan runs asynchronously in the background. Use the returned scan_id
    to poll for results.
    """
    for domain in request.domains:
        if not is_valid_domain(domain):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid domain: {domain!r}",
            )

    # Create the scan record upfront so we can return the ID immediately
    scan = Scan(domains_scanned=request.domains, status="running")
    scan_id = await db.create_scan(scan)

    background_tasks.add_task(
        _run_scan_background, orchestrator, db, scan_id, request.domains,
    )

    return ScanCreatedResponse(
        scan_id=scan_id,
        status="running",
        domains=request.domains,
    )


@router.get(
    "/scans",
    response_model=ScanListResponse,
)
async def list_scans(
    limit: int = Query(default=10, ge=1, le=100, description="Max scans to return"),
    db: DatabaseManager = Depends(get_db),
) -> ScanListResponse:
    """List recent scans."""
    scans = await db.list_scans(limit=limit)
    return ScanListResponse(
        scans=[_scan_to_response(s) for s in scans],
        total=len(scans),
    )


@router.get(
    "/scans/{scan_id}",
    response_model=ScanDetailResponse,
    responses={404: {"model": ErrorResponse}},
)
async def get_scan(
    scan_id: str,
    db: DatabaseManager = Depends(get_db),
) -> ScanDetailResponse:
    """Get a scan by ID, including its findings."""
    scan = await db.get_scan(scan_id)
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan not found: {scan_id}",
        )

    findings = await db.get_scan_findings(scan_id)

    return ScanDetailResponse(
        scan_id=scan.id,
        status=scan.status,
        domains=scan.domains_scanned,
        start_time=scan.start_time,
        end_time=scan.end_time,
        duration_seconds=scan.duration_seconds,
        total_findings=scan.total_findings,
        summary=ScanSummary(
            critical=scan.critical_findings,
            high=scan.high_findings,
            medium=scan.medium_findings,
            low=scan.low_findings,
        ),
        findings=[_finding_to_response(f) for f in findings],
    )


@router.get(
    "/scans/{scan_id}/findings",
    response_model=list[FindingResponse],
    responses={404: {"model": ErrorResponse}},
)
async def get_scan_findings(
    scan_id: str,
    severity: str | None = Query(default=None, description="Filter by severity"),
    db: DatabaseManager = Depends(get_db),
) -> list[FindingResponse]:
    """Get findings for a scan, optionally filtered by severity."""
    scan = await db.get_scan(scan_id)
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan not found: {scan_id}",
        )

    findings = await db.get_scan_findings(scan_id)

    if severity:
        severity_upper = severity.upper()
        findings = [f for f in findings if f.severity == severity_upper]

    return [_finding_to_response(f) for f in findings]
