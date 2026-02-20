"""Dashboard view routes — serves HTML pages via Jinja2 + HTMX."""

from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, Form, HTTPException, Query, status
from fastapi.responses import HTMLResponse
from jinja2 import Environment, FileSystemLoader

from security_scanner import __version__
from security_scanner.api.dependencies import get_db, get_orchestrator
from security_scanner.api.routes.scans import _run_scan_background
from security_scanner.dashboard.context import (
    format_duration,
    severity_color,
    status_color,
    time_ago,
    truncate,
)
from security_scanner.dashboard.queries import (
    get_dashboard_stats,
    list_findings_filtered,
    list_scans_paginated,
)
from security_scanner.orchestrator import ScanOrchestrator
from security_scanner.storage.database import DatabaseManager
from security_scanner.storage.models import Scan
from security_scanner.utils.validators import is_valid_domain

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

_templates_dir = Path(__file__).parent / "templates"
_env = Environment(
    loader=FileSystemLoader(str(_templates_dir)),
    autoescape=True,
)
_env.globals.update(
    severity_color=severity_color,
    status_color=status_color,
    time_ago=time_ago,
    format_duration=format_duration,
    truncate=truncate,
)


def _render(template_name: str, **ctx: object) -> HTMLResponse:
    """Render a Jinja2 template to an HTMLResponse."""
    template = _env.get_template(template_name)
    html = template.render(version=__version__, **ctx)
    return HTMLResponse(html)


# ---------------------------------------------------------------------------
# Full-page routes
# ---------------------------------------------------------------------------


@router.get("/", response_class=HTMLResponse)
async def dashboard_overview(
    db: DatabaseManager = Depends(get_db),
) -> HTMLResponse:
    """Dashboard overview page."""
    stats = await get_dashboard_stats(db)
    scans, _total = await list_scans_paginated(db, limit=5, offset=0)
    has_running = any(s.status == "running" for s in scans)
    return _render(
        "dashboard.html",
        active_page="overview",
        stats=stats,
        scans=scans,
        has_running=has_running,
    )


@router.get("/scans", response_class=HTMLResponse)
async def scan_list(
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=20, ge=1, le=100),
    db: DatabaseManager = Depends(get_db),
) -> HTMLResponse:
    """Paginated scan list page."""
    offset = (page - 1) * limit
    scans, total = await list_scans_paginated(db, limit=limit, offset=offset)
    has_running = any(s.status == "running" for s in scans)
    return _render(
        "scans/list.html",
        active_page="scans",
        scans=scans,
        total=total,
        page=page,
        limit=limit,
        has_running=has_running,
    )


@router.get("/scans/new", response_class=HTMLResponse)
async def new_scan_form() -> HTMLResponse:
    """New scan form page."""
    return _render("scans/new.html", active_page="scans")


@router.get("/scans/{scan_id}", response_class=HTMLResponse)
async def scan_detail(
    scan_id: str,
    severity: str | None = Query(default=None),
    db: DatabaseManager = Depends(get_db),
) -> HTMLResponse:
    """Scan detail page with findings."""
    scan = await db.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    findings, _total = await list_findings_filtered(
        db, severity=severity, scan_id=scan_id, limit=500
    )
    return _render(
        "scans/detail.html",
        active_page="scans",
        scan=scan,
        findings=findings,
        severity_filter=severity.upper() if severity else None,
    )


@router.get("/findings", response_class=HTMLResponse)
async def findings_browser(
    severity: str | None = Query(default=None),
    domain: str | None = Query(default=None),
    type: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=50, ge=1, le=200),
    db: DatabaseManager = Depends(get_db),
) -> HTMLResponse:
    """Findings browser page with filters."""
    offset = (page - 1) * limit
    findings, total = await list_findings_filtered(
        db, severity=severity, domain=domain, finding_type=type, limit=limit, offset=offset
    )

    # Get distinct finding types for the filter dropdown
    all_findings, _ = await list_findings_filtered(db, limit=0, offset=0)
    # Query distinct types directly instead
    import aiosqlite

    async with aiosqlite.connect(db.db_path) as conn:
        cursor = await conn.execute("SELECT DISTINCT type FROM findings ORDER BY type")
        finding_types = [row[0] async for row in cursor]

    return _render(
        "findings/list.html",
        active_page="findings",
        findings=findings,
        total=total,
        page=page,
        limit=limit,
        finding_types=finding_types,
        filters={"severity": severity, "domain": domain, "type": type},
    )


# ---------------------------------------------------------------------------
# HTMX partial routes (return HTML fragments, no <html> wrapper)
# ---------------------------------------------------------------------------


@router.get("/partials/stats", response_class=HTMLResponse)
async def partials_stats(
    db: DatabaseManager = Depends(get_db),
) -> HTMLResponse:
    """Stats cards fragment for HTMX polling."""
    stats = await get_dashboard_stats(db)
    return _render("partials/stats_cards.html", stats=stats)


@router.get("/partials/scan-table", response_class=HTMLResponse)
async def partials_scan_table(
    limit: int = Query(default=5, ge=1, le=100),
    page: int = Query(default=1, ge=1),
    db: DatabaseManager = Depends(get_db),
) -> HTMLResponse:
    """Scan table rows fragment for HTMX polling."""
    offset = (page - 1) * limit
    scans, _total = await list_scans_paginated(db, limit=limit, offset=offset)
    return _render("partials/scan_table.html", scans=scans)


@router.get("/partials/scan-status/{scan_id}", response_class=HTMLResponse)
async def partials_scan_status(
    scan_id: str,
    db: DatabaseManager = Depends(get_db),
) -> HTMLResponse:
    """Single scan status badge fragment for HTMX polling."""
    scan = await db.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return _render("partials/scan_status.html", scan=scan)


@router.get("/partials/scan-findings/{scan_id}", response_class=HTMLResponse)
async def partials_scan_findings(
    scan_id: str,
    severity: str | None = Query(default=None),
    db: DatabaseManager = Depends(get_db),
) -> HTMLResponse:
    """Scan findings rows fragment for HTMX severity filter."""
    findings, _total = await list_findings_filtered(
        db, severity=severity, scan_id=scan_id, limit=500
    )
    return _render(
        "partials/scan_findings.html",
        findings=findings,
        severity_filter=severity.upper() if severity else None,
    )


@router.get("/partials/findings", response_class=HTMLResponse)
async def partials_findings(
    severity: str | None = Query(default=None),
    domain: str | None = Query(default=None),
    type: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=50, ge=1, le=200),
    db: DatabaseManager = Depends(get_db),
) -> HTMLResponse:
    """Cross-scan findings rows fragment for HTMX filter/pagination."""
    offset = (page - 1) * limit
    findings, _total = await list_findings_filtered(
        db, severity=severity, domain=domain, finding_type=type, limit=limit, offset=offset
    )
    return _render("partials/findings_table.html", findings=findings)


# ---------------------------------------------------------------------------
# Form handlers
# ---------------------------------------------------------------------------


@router.post("/scans/new", response_class=HTMLResponse)
async def create_scan(
    background_tasks: BackgroundTasks,
    domains: str = Form(...),
    orchestrator: ScanOrchestrator = Depends(get_orchestrator),
    db: DatabaseManager = Depends(get_db),
) -> HTMLResponse:
    """Handle new scan form submission."""
    domain_list = [d.strip() for d in domains.splitlines() if d.strip()]

    if not domain_list:
        return _render("partials/new_scan_result.html", error="No domains provided.")

    invalid = [d for d in domain_list if not is_valid_domain(d)]
    if invalid:
        return _render(
            "partials/new_scan_result.html",
            error=f"Invalid domain(s): {', '.join(invalid)}",
        )

    scan = Scan(domains_scanned=domain_list, status="running")
    scan_id = await db.create_scan(scan)

    background_tasks.add_task(
        _run_scan_background,
        orchestrator,
        db,
        scan_id,
        domain_list,
    )

    return _render(
        "partials/new_scan_result.html",
        scan_id=scan_id,
        domains=domain_list,
        error=None,
    )
