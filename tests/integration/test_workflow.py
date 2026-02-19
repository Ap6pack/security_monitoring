"""Integration tests for scan workflow."""

from pathlib import Path

import pytest

from security_scanner.storage.database import DatabaseManager
from security_scanner.storage.models import Finding, Scan


class TestScanWorkflow:
    """Test end-to-end scan workflow."""

    @pytest.fixture
    async def db(self, tmp_path: Path) -> DatabaseManager:
        """Create temporary database for testing."""
        db_path = tmp_path / "test.db"
        db = DatabaseManager(db_path)
        await db.initialize()
        return db

    @pytest.mark.asyncio
    async def test_complete_scan_workflow(self, db: DatabaseManager) -> None:
        """Test complete scan workflow from start to finish."""
        # 1. Create scan
        scan = Scan(
            domains_scanned=["example.com", "test.com"],
            status="running",
        )
        scan_id = await db.create_scan(scan)
        assert scan_id is not None

        # 2. Add findings
        findings = [
            Finding(
                scan_id=scan_id,
                severity="CRITICAL",
                type="dangling_cname",
                domain="api.example.com",
                description="Critical issue",
                remediation="Fix immediately",
            ),
            Finding(
                scan_id=scan_id,
                severity="HIGH",
                type="takeover",
                domain="www.example.com",
                description="High severity issue",
                remediation="Fix soon",
            ),
            Finding(
                scan_id=scan_id,
                severity="MEDIUM",
                type="nxdomain",
                domain="mail.example.com",
                description="Medium severity issue",
                remediation="Investigate",
            ),
        ]

        for finding in findings:
            await db.create_finding(finding)

        # 3. Verify findings were stored
        retrieved_findings = await db.get_scan_findings(scan_id)
        assert len(retrieved_findings) == 3

        # 4. Verify scan exists
        completed_scan = await db.get_scan(scan_id)
        assert completed_scan is not None
        assert completed_scan.status == "running"  # Still running since we didn't update

    @pytest.mark.asyncio
    async def test_finding_deduplication_workflow(self, db: DatabaseManager) -> None:
        """Test that duplicate findings can be detected."""
        # Scan 1
        scan1 = Scan(domains_scanned=["example.com"])
        scan_id1 = await db.create_scan(scan1)

        finding1 = Finding(
            scan_id=scan_id1,
            severity="CRITICAL",
            type="dangling_cname",
            domain="api.example.com",
            target="target.com",
            description="Issue",
            remediation="Fix",
        )
        await db.create_finding(finding1)

        # Scan 2 - same finding
        scan2 = Scan(domains_scanned=["example.com"])
        await db.create_scan(scan2)

        # Check for similar findings
        similar = await db.get_similar_findings(
            domain="api.example.com",
            finding_type="dangling_cname",
            days=7,
        )

        assert len(similar) >= 1

    @pytest.mark.asyncio
    async def test_alert_workflow(self, db: DatabaseManager) -> None:
        """Test alert marking workflow."""
        scan = Scan(domains_scanned=["example.com"])
        scan_id = await db.create_scan(scan)

        finding = Finding(
            scan_id=scan_id,
            severity="CRITICAL",
            type="dangling_cname",
            domain="api.example.com",
            description="Critical",
            remediation="Fix",
        )
        finding_id = await db.create_finding(finding)

        # Mark as alerted
        await db.mark_finding_alerted(finding_id)

        # Verify
        findings = await db.get_scan_findings(scan_id)
        assert len(findings) > 0

    @pytest.mark.asyncio
    async def test_multiple_scans_workflow(self, db: DatabaseManager) -> None:
        """Test managing multiple scans."""
        # Create several scans
        scans_to_create = [
            Scan(domains_scanned=["example.com"], status="completed"),
            Scan(domains_scanned=["test.com"], status="completed"),
            Scan(domains_scanned=["sample.com"], status="running"),
        ]

        scan_ids = []
        for scan in scans_to_create:
            scan_id = await db.create_scan(scan)
            scan_ids.append(scan_id)

        # List scans
        scans = await db.list_scans(limit=10)
        assert len(scans) >= 3

        # Verify all scan IDs are in the list
        listed_scan_ids = [s.id for s in scans]
        for scan_id in scan_ids:
            assert scan_id in listed_scan_ids

    @pytest.mark.asyncio
    async def test_severity_filtering_workflow(self, db: DatabaseManager) -> None:
        """Test filtering findings by severity."""
        scan = Scan(domains_scanned=["example.com"])
        scan_id = await db.create_scan(scan)

        findings = [
            Finding(
                scan_id=scan_id,
                severity="CRITICAL",
                type="dangling_cname",
                domain=f"critical{i}.example.com",
                description="Critical",
                remediation="Fix",
            )
            for i in range(3)
        ] + [
            Finding(
                scan_id=scan_id,
                severity="LOW",
                type="info",
                domain="low.example.com",
                description="Info",
                remediation="Optional",
            )
        ]

        for finding in findings:
            await db.create_finding(finding)

        # Get all findings
        all_findings = await db.get_scan_findings(scan_id)
        assert len(all_findings) == 4

        # Count by severity
        critical_count = sum(1 for f in all_findings if f.severity == "CRITICAL")
        low_count = sum(1 for f in all_findings if f.severity == "LOW")

        assert critical_count == 3
        assert low_count == 1
