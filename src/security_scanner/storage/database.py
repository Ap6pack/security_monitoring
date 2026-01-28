"""Async SQLite database manager."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import aiosqlite

from security_scanner.storage.models import (
    AlertHistory,
    Certificate,
    Finding,
    Scan,
)
from security_scanner.utils.exceptions import DatabaseError
from security_scanner.utils.logger import get_logger

logger = get_logger(__name__)


class DatabaseManager:
    """
    Async SQLite database manager with connection pooling.

    Handles all database operations including:
    - Schema initialization and migrations
    - CRUD operations for scans, findings, and certificates
    - Query optimization with indexes
    - Transaction management
    """

    def __init__(self, db_path: Path) -> None:
        """
        Initialize the database manager.

        Args:
            db_path: Path to the SQLite database file
        """
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    async def initialize(self) -> None:
        """Initialize the database schema."""
        logger.info("Initializing database", path=str(self.db_path))

        migrations_dir = Path(__file__).parent / "migrations"
        migration_file = migrations_dir / "001_initial.sql"

        if not migration_file.exists():
            # Create migration inline if file doesn't exist
            schema = self._get_initial_schema()
        else:
            schema = migration_file.read_text()

        async with aiosqlite.connect(self.db_path) as db:
            await db.executescript(schema)
            await db.commit()

        logger.info("Database initialized successfully")

    def _get_initial_schema(self) -> str:
        """Get the initial database schema."""
        return """
        -- Scans table
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            start_time TIMESTAMP NOT NULL,
            end_time TIMESTAMP,
            duration_seconds INTEGER,
            domains_scanned TEXT NOT NULL,
            status TEXT NOT NULL,
            scanner_version TEXT NOT NULL,
            total_findings INTEGER DEFAULT 0,
            critical_findings INTEGER DEFAULT 0,
            high_findings INTEGER DEFAULT 0,
            medium_findings INTEGER DEFAULT 0,
            low_findings INTEGER DEFAULT 0
        );

        CREATE INDEX IF NOT EXISTS idx_scans_start_time ON scans(start_time DESC);
        CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);

        -- Findings table
        CREATE TABLE IF NOT EXISTS findings (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            severity TEXT NOT NULL,
            type TEXT NOT NULL,
            domain TEXT NOT NULL,
            record_type TEXT,
            target TEXT,
            description TEXT NOT NULL,
            cvss_score REAL,
            remediation TEXT NOT NULL,
            raw_data TEXT NOT NULL,
            detected_at TIMESTAMP NOT NULL,
            first_seen TIMESTAMP NOT NULL,
            alerted BOOLEAN DEFAULT 0,
            platform TEXT,
            confidence REAL DEFAULT 1.0,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        );

        CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
        CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
        CREATE INDEX IF NOT EXISTS idx_findings_domain ON findings(domain);
        CREATE INDEX IF NOT EXISTS idx_findings_detected_at ON findings(detected_at DESC);

        -- Certificates table
        CREATE TABLE IF NOT EXISTS certificates (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            cert_id TEXT NOT NULL,
            issuer TEXT NOT NULL,
            expires TIMESTAMP NOT NULL,
            shared BOOLEAN DEFAULT 0,
            san_count INTEGER DEFAULT 0,
            san_domains TEXT NOT NULL,
            external_domains TEXT NOT NULL,
            risk_level TEXT NOT NULL,
            logged_at TIMESTAMP NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        );

        CREATE INDEX IF NOT EXISTS idx_certificates_scan_id ON certificates(scan_id);
        CREATE INDEX IF NOT EXISTS idx_certificates_expires ON certificates(expires);
        CREATE INDEX IF NOT EXISTS idx_certificates_shared ON certificates(shared);

        -- Alert history table
        CREATE TABLE IF NOT EXISTS alert_history (
            id TEXT PRIMARY KEY,
            finding_id TEXT NOT NULL,
            channel TEXT NOT NULL,
            sent_at TIMESTAMP NOT NULL,
            success BOOLEAN NOT NULL,
            error_message TEXT,
            retry_count INTEGER DEFAULT 0,
            FOREIGN KEY (finding_id) REFERENCES findings(id)
        );

        CREATE INDEX IF NOT EXISTS idx_alert_history_finding_id ON alert_history(finding_id);
        CREATE INDEX IF NOT EXISTS idx_alert_history_sent_at ON alert_history(sent_at DESC);
        """

    async def create_scan(self, scan: Scan) -> str:
        """
        Create a new scan record.

        Args:
            scan: Scan model to create

        Returns:
            Scan ID
        """
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO scans (
                    id, start_time, end_time, duration_seconds, domains_scanned,
                    status, scanner_version, total_findings, critical_findings,
                    high_findings, medium_findings, low_findings
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan.id,
                    scan.start_time,
                    scan.end_time,
                    scan.duration_seconds,
                    json.dumps(scan.domains_scanned),
                    scan.status,
                    scan.scanner_version,
                    scan.total_findings,
                    scan.critical_findings,
                    scan.high_findings,
                    scan.medium_findings,
                    scan.low_findings,
                ),
            )
            await db.commit()

        logger.info("Created scan record", scan_id=scan.id)
        return scan.id

    async def update_scan(
        self,
        scan_id: str,
        end_time: datetime,
        status: str,
        findings_count: dict[str, int],
    ) -> None:
        """
        Update a scan record.

        Args:
            scan_id: Scan ID to update
            end_time: Scan end time
            status: Final status
            findings_count: Dictionary of finding counts by severity
        """
        async with aiosqlite.connect(self.db_path) as db:
            # Get start time to calculate duration
            cursor = await db.execute(
                "SELECT start_time FROM scans WHERE id = ?",
                (scan_id,),
            )
            row = await cursor.fetchone()
            if row:
                start_time = datetime.fromisoformat(row[0])
                duration = int((end_time - start_time).total_seconds())
            else:
                duration = 0

            await db.execute(
                """
                UPDATE scans SET
                    end_time = ?,
                    duration_seconds = ?,
                    status = ?,
                    total_findings = ?,
                    critical_findings = ?,
                    high_findings = ?,
                    medium_findings = ?,
                    low_findings = ?
                WHERE id = ?
                """,
                (
                    end_time,
                    duration,
                    status,
                    sum(findings_count.values()),
                    findings_count.get("CRITICAL", 0),
                    findings_count.get("HIGH", 0),
                    findings_count.get("MEDIUM", 0),
                    findings_count.get("LOW", 0),
                    scan_id,
                ),
            )
            await db.commit()

        logger.info("Updated scan record", scan_id=scan_id, status=status)

    async def create_finding(self, finding: Finding) -> str:
        """
        Create a new finding record.

        Args:
            finding: Finding model to create

        Returns:
            Finding ID
        """
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO findings (
                    id, scan_id, severity, type, domain, record_type, target,
                    description, cvss_score, remediation, raw_data, detected_at,
                    first_seen, alerted, platform, confidence
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding.id,
                    finding.scan_id,
                    finding.severity,
                    finding.type,
                    finding.domain,
                    finding.record_type,
                    finding.target,
                    finding.description,
                    finding.cvss_score,
                    finding.remediation,
                    json.dumps(finding.raw_data),
                    finding.detected_at,
                    finding.first_seen,
                    finding.alerted,
                    finding.platform,
                    finding.confidence,
                ),
            )
            await db.commit()

        logger.debug("Created finding", finding_id=finding.id, severity=finding.severity)
        return finding.id

    async def get_similar_findings(
        self,
        domain: str,
        finding_type: str,
        days: int = 30,
    ) -> list[Finding]:
        """
        Get similar findings for deduplication.

        Args:
            domain: Domain to check
            finding_type: Type of finding
            days: Number of days to look back

        Returns:
            List of similar findings
        """
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                """
                SELECT * FROM findings
                WHERE domain = ? AND type = ?
                AND detected_at > datetime('now', '-' || ? || ' days')
                ORDER BY detected_at DESC
                """,
                (domain, finding_type, days),
            )
            rows = await cursor.fetchall()

        findings = []
        for row in rows:
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
                    raw_data=json.loads(row["raw_data"]),
                    detected_at=datetime.fromisoformat(row["detected_at"]),
                    first_seen=datetime.fromisoformat(row["first_seen"]),
                    alerted=bool(row["alerted"]),
                    platform=row["platform"],
                    confidence=row["confidence"],
                )
            )

        return findings

    async def mark_finding_alerted(self, finding_id: str) -> None:
        """Mark a finding as alerted."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "UPDATE findings SET alerted = 1 WHERE id = ?",
                (finding_id,),
            )
            await db.commit()

    async def create_certificate(self, cert: Certificate) -> str:
        """Create a certificate record."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO certificates (
                    id, scan_id, cert_id, issuer, expires, shared, san_count,
                    san_domains, external_domains, risk_level, logged_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    cert.id,
                    cert.scan_id,
                    cert.cert_id,
                    cert.issuer,
                    cert.expires,
                    cert.shared,
                    cert.san_count,
                    json.dumps(cert.san_domains),
                    json.dumps(cert.external_domains),
                    cert.risk_level,
                    cert.logged_at,
                ),
            )
            await db.commit()

        return cert.id

    async def create_alert_history(self, alert: AlertHistory) -> str:
        """Create an alert history record."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO alert_history (
                    id, finding_id, channel, sent_at, success, error_message, retry_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert.id,
                    alert.finding_id,
                    alert.channel,
                    alert.sent_at,
                    alert.success,
                    alert.error_message,
                    alert.retry_count,
                ),
            )
            await db.commit()

        return alert.id

    async def get_scan(self, scan_id: str) -> Optional[Scan]:
        """Get a scan by ID."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
            row = await cursor.fetchone()

        if not row:
            return None

        return Scan(
            id=row["id"],
            start_time=datetime.fromisoformat(row["start_time"]),
            end_time=(
                datetime.fromisoformat(row["end_time"]) if row["end_time"] else None
            ),
            duration_seconds=row["duration_seconds"],
            domains_scanned=json.loads(row["domains_scanned"]),
            status=row["status"],
            scanner_version=row["scanner_version"],
            total_findings=row["total_findings"],
            critical_findings=row["critical_findings"],
            high_findings=row["high_findings"],
            medium_findings=row["medium_findings"],
            low_findings=row["low_findings"],
        )

    async def get_scan_findings(self, scan_id: str) -> list[Finding]:
        """Get all findings for a scan."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT * FROM findings WHERE scan_id = ? ORDER BY severity, detected_at",
                (scan_id,),
            )
            rows = await cursor.fetchall()

        findings = []
        for row in rows:
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
                    raw_data=json.loads(row["raw_data"]),
                    detected_at=datetime.fromisoformat(row["detected_at"]),
                    first_seen=datetime.fromisoformat(row["first_seen"]),
                    alerted=bool(row["alerted"]),
                    platform=row["platform"],
                    confidence=row["confidence"],
                )
            )

        return findings

    async def list_scans(self, limit: int = 10) -> list[Scan]:
        """List recent scans."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT * FROM scans ORDER BY start_time DESC LIMIT ?",
                (limit,),
            )
            rows = await cursor.fetchall()

        scans = []
        for row in rows:
            scans.append(
                Scan(
                    id=row["id"],
                    start_time=datetime.fromisoformat(row["start_time"]),
                    end_time=(
                        datetime.fromisoformat(row["end_time"]) if row["end_time"] else None
                    ),
                    duration_seconds=row["duration_seconds"],
                    domains_scanned=json.loads(row["domains_scanned"]),
                    status=row["status"],
                    scanner_version=row["scanner_version"],
                    total_findings=row["total_findings"],
                    critical_findings=row["critical_findings"],
                    high_findings=row["high_findings"],
                    medium_findings=row["medium_findings"],
                    low_findings=row["low_findings"],
                )
            )

        return scans
