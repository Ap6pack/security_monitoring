"""Dashboard-specific database queries."""

import json
from datetime import UTC, datetime

import aiosqlite

from security_scanner.storage.database import DatabaseManager
from security_scanner.storage.models import Finding, Scan


async def get_dashboard_stats(db: DatabaseManager) -> dict[str, object]:
    """Get aggregate statistics for the dashboard overview."""
    async with aiosqlite.connect(db.db_path) as conn:
        conn.row_factory = aiosqlite.Row

        # Total and running scans
        cursor = await conn.execute(
            "SELECT COUNT(*) as total, "
            "SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END) as running, "
            "SUM(CASE WHEN start_time > ? THEN 1 ELSE 0 END) as last_24h "
            "FROM scans",
            (datetime.now(UTC).replace(hour=0, minute=0, second=0).isoformat(),),
        )
        row = await cursor.fetchone()
        assert row is not None
        total_scans = row["total"]
        running_scans = row["running"]
        scans_last_24h = row["last_24h"]

        # Total findings
        cursor = await conn.execute("SELECT COUNT(*) as total FROM findings")
        row = await cursor.fetchone()
        assert row is not None
        total_findings = row["total"]

        # Findings by severity
        cursor = await conn.execute(
            "SELECT severity, COUNT(*) as count FROM findings GROUP BY severity"
        )
        severity_counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        async for row in cursor:
            severity_counts[row["severity"]] = row["count"]

    return {
        "total_scans": total_scans,
        "running_scans": running_scans,
        "scans_last_24h": scans_last_24h,
        "total_findings": total_findings,
        "findings_by_severity": severity_counts,
    }


async def list_scans_paginated(
    db: DatabaseManager, limit: int = 20, offset: int = 0
) -> tuple[list[Scan], int]:
    """List scans with pagination support."""
    async with aiosqlite.connect(db.db_path) as conn:
        conn.row_factory = aiosqlite.Row

        cursor = await conn.execute("SELECT COUNT(*) as total FROM scans")
        row = await cursor.fetchone()
        assert row is not None
        total = row["total"]

        cursor = await conn.execute(
            "SELECT * FROM scans ORDER BY start_time DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )
        scans: list[Scan] = []
        async for row in cursor:
            scans.append(
                Scan(
                    id=row["id"],
                    start_time=row["start_time"],
                    end_time=row["end_time"],
                    duration_seconds=row["duration_seconds"],
                    domains_scanned=json.loads(row["domains_scanned"]),
                    status=row["status"],
                    scanner_version=row["scanner_version"] or "0.1.0",
                    total_findings=row["total_findings"] or 0,
                    critical_findings=row["critical_findings"] or 0,
                    high_findings=row["high_findings"] or 0,
                    medium_findings=row["medium_findings"] or 0,
                    low_findings=row["low_findings"] or 0,
                )
            )

    return scans, total


async def list_findings_filtered(
    db: DatabaseManager,
    severity: str | None = None,
    domain: str | None = None,
    finding_type: str | None = None,
    scan_id: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[Finding], int]:
    """List findings with optional filters and pagination."""
    conditions: list[str] = []
    params: list[object] = []

    if severity:
        conditions.append("severity = ?")
        params.append(severity.upper())
    if domain:
        conditions.append("domain LIKE ?")
        params.append(f"%{domain}%")
    if finding_type:
        conditions.append("type = ?")
        params.append(finding_type)
    if scan_id:
        conditions.append("scan_id = ?")
        params.append(scan_id)

    where = ""
    if conditions:
        where = "WHERE " + " AND ".join(conditions)

    async with aiosqlite.connect(db.db_path) as conn:
        conn.row_factory = aiosqlite.Row

        cursor = await conn.execute(f"SELECT COUNT(*) as total FROM findings {where}", params)
        row = await cursor.fetchone()
        assert row is not None
        total = row["total"]

        cursor = await conn.execute(
            f"SELECT * FROM findings {where} ORDER BY detected_at DESC LIMIT ? OFFSET ?",
            [*params, limit, offset],
        )
        findings: list[Finding] = []
        async for row in cursor:
            findings.append(
                Finding(
                    id=row["id"],
                    scan_id=row["scan_id"],
                    severity=row["severity"],
                    type=row["type"],
                    domain=row["domain"],
                    record_type=row["record_type"],
                    target=row["target"],
                    description=row["description"],
                    cvss_score=row["cvss_score"],
                    remediation=row["remediation"],
                    raw_data=json.loads(row["raw_data"]) if row["raw_data"] else {},
                    detected_at=row["detected_at"],
                    first_seen=row["first_seen"],
                    alerted=bool(row["alerted"]),
                    platform=row["platform"],
                    confidence=row["confidence"] or 1.0,
                )
            )

    return findings, total
