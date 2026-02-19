"""Unit tests for scan orchestrator."""

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from security_scanner.config import Settings
from security_scanner.orchestrator import ScanOrchestrator
from security_scanner.scanner.models import DNSResult, SubdomainResult
from security_scanner.storage.database import DatabaseManager
from security_scanner.storage.models import Finding


class TestScanOrchestrator:
    """Test scan orchestrator."""

    @pytest.fixture
    async def db(self, tmp_path: Path) -> DatabaseManager:
        """Create temporary database."""
        db_path = tmp_path / "test.db"
        db = DatabaseManager(db_path)
        await db.initialize()
        return db

    @pytest.fixture
    def settings(self) -> Settings:
        """Create test settings."""
        return Settings(
            dns_nameservers=["8.8.8.8"],
            http_timeout=5,
            http_max_retries=2,
            http_max_connections=10,
            rate_limit_requests_per_second=2.0,
            rate_limit_burst=5,
            cache_max_size=100,
            cache_ttl=300,
            enable_cache=True,
            dns_timeout=5,
            dns_max_retries=2,
            max_concurrent_scans=10,
            subdomain_sources=["crtsh"],
        )

    @pytest.fixture
    async def orchestrator(self, settings: Settings, db: DatabaseManager) -> ScanOrchestrator:
        """Create orchestrator instance."""
        orch = ScanOrchestrator(settings=settings, db=db)
        yield orch
        await orch.cleanup()

    @pytest.mark.asyncio
    async def test_initialization(self, orchestrator: ScanOrchestrator) -> None:
        """Test orchestrator initialization."""
        assert orchestrator.http_client is not None
        assert orchestrator.dns_scanner is not None
        assert orchestrator.subdomain_scanner is not None
        assert orchestrator.certificate_scanner is not None
        assert orchestrator.dangling_detector is not None
        assert orchestrator.takeover_detector is not None

    @pytest.mark.asyncio
    async def test_context_manager(self, settings: Settings, db: DatabaseManager) -> None:
        """Test orchestrator as async context manager."""
        async with ScanOrchestrator(settings=settings, db=db) as orch:
            assert orch is not None

        # Should clean up successfully

    @pytest.mark.asyncio
    async def test_scan_creates_scan_record(
        self, orchestrator: ScanOrchestrator, db: DatabaseManager
    ) -> None:
        """Test that scan creates a database record."""
        domains = ["example.com"]

        # Mock all scanner methods to avoid actual network calls
        with patch.object(orchestrator.subdomain_scanner, "scan", new_callable=AsyncMock) as mock_sub, \
             patch.object(orchestrator.dns_scanner, "scan", new_callable=AsyncMock) as mock_dns, \
             patch.object(orchestrator.dangling_detector, "detect", new_callable=AsyncMock) as mock_dang, \
             patch.object(orchestrator.takeover_detector, "detect", new_callable=AsyncMock) as mock_take:

            mock_sub.return_value = []
            mock_dns.return_value = []
            mock_dang.return_value = []
            mock_take.return_value = []

            result = await orchestrator.scan(domains)

            assert result["scan_id"] is not None
            assert result["domains"] == domains

            # Verify scan was created in database
            scan = await db.get_scan(result["scan_id"])
            assert scan is not None
            assert scan.domains_scanned == domains
            assert scan.status == "completed"

    @pytest.mark.asyncio
    async def test_scan_subdomain_discovery(self, orchestrator: ScanOrchestrator) -> None:
        """Test subdomain discovery during scan."""
        domains = ["example.com"]

        with patch.object(orchestrator.subdomain_scanner, "scan", new_callable=AsyncMock) as mock_sub, \
             patch.object(orchestrator.dns_scanner, "scan", new_callable=AsyncMock) as mock_dns, \
             patch.object(orchestrator.dangling_detector, "detect", new_callable=AsyncMock) as mock_dang, \
             patch.object(orchestrator.takeover_detector, "detect", new_callable=AsyncMock) as mock_take:

            # Mock subdomain discovery
            mock_sub.return_value = [
                SubdomainResult(domain="www.example.com", source="crtsh"),
                SubdomainResult(domain="api.example.com", source="crtsh"),
            ]
            mock_dns.return_value = []
            mock_dang.return_value = []
            mock_take.return_value = []

            await orchestrator.scan(domains)

            # Should scan root domain + discovered subdomains
            assert mock_dns.call_count == 3  # example.com + www + api

    @pytest.mark.asyncio
    async def test_scan_dns_resolution(self, orchestrator: ScanOrchestrator) -> None:
        """Test DNS resolution during scan."""
        domains = ["example.com"]

        with patch.object(orchestrator.subdomain_scanner, "scan", new_callable=AsyncMock) as mock_sub, \
             patch.object(orchestrator.dns_scanner, "scan", new_callable=AsyncMock) as mock_dns, \
             patch.object(orchestrator.dangling_detector, "detect", new_callable=AsyncMock) as mock_dang, \
             patch.object(orchestrator.takeover_detector, "detect", new_callable=AsyncMock) as mock_take:

            mock_sub.return_value = []
            mock_dns.return_value = [
                DNSResult(
                    domain="example.com",
                    record_type="A",
                    values=["93.184.216.34"],
                    ttl=300,
                    nameserver="8.8.8.8",
                )
            ]
            mock_dang.return_value = []
            mock_take.return_value = []

            await orchestrator.scan(domains)

            # Should call DNS scan for the domain
            mock_dns.assert_called_once()

    @pytest.mark.asyncio
    async def test_scan_detector_execution(self, orchestrator: ScanOrchestrator) -> None:
        """Test that detectors are executed during scan."""
        domains = ["example.com"]

        with patch.object(orchestrator.subdomain_scanner, "scan", new_callable=AsyncMock) as mock_sub, \
             patch.object(orchestrator.dns_scanner, "scan", new_callable=AsyncMock) as mock_dns, \
             patch.object(orchestrator.dangling_detector, "detect", new_callable=AsyncMock) as mock_dang, \
             patch.object(orchestrator.takeover_detector, "detect", new_callable=AsyncMock) as mock_take:

            mock_sub.return_value = []
            mock_dns.return_value = [
                DNSResult(
                    domain="example.com",
                    record_type="CNAME",
                    values=["cdn.example.com"],
                    ttl=300,
                    nameserver="8.8.8.8",
                )
            ]
            mock_dang.return_value = []
            mock_take.return_value = []

            await orchestrator.scan(domains)

            # Both detectors should be called
            mock_dang.assert_called_once()
            mock_take.assert_called_once()

    @pytest.mark.asyncio
    async def test_scan_finding_storage(
        self, orchestrator: ScanOrchestrator, db: DatabaseManager
    ) -> None:
        """Test that findings are stored in database."""
        domains = ["example.com"]

        with patch.object(orchestrator.subdomain_scanner, "scan", new_callable=AsyncMock) as mock_sub, \
             patch.object(orchestrator.dns_scanner, "scan", new_callable=AsyncMock) as mock_dns, \
             patch.object(orchestrator.dangling_detector, "detect", new_callable=AsyncMock) as mock_dang, \
             patch.object(orchestrator.takeover_detector, "detect", new_callable=AsyncMock) as mock_take:

            mock_sub.return_value = []
            mock_dns.return_value = []

            # Mock detector to return findings
            mock_finding = Finding(
                scan_id="",
                severity="CRITICAL",
                type="dangling_cname",
                domain="api.example.com",
                record_type="CNAME",
                target="old-service.herokuapp.com",
                description="Dangling CNAME detected",
                cvss_score=9.1,
                remediation="Remove the CNAME record",
                raw_data={},
                confidence=1.0,
            )
            mock_dang.return_value = [mock_finding]
            mock_take.return_value = []

            result = await orchestrator.scan(domains)

            assert len(result["findings"]) == 1

            # Verify finding was stored in database
            scan_findings = await db.get_scan_findings(result["scan_id"])
            assert len(scan_findings) == 1
            assert scan_findings[0].severity == "CRITICAL"

    @pytest.mark.asyncio
    async def test_scan_summary_counts(self, orchestrator: ScanOrchestrator) -> None:
        """Test that scan summary includes correct counts."""
        domains = ["example.com"]

        with patch.object(orchestrator.subdomain_scanner, "scan", new_callable=AsyncMock) as mock_sub, \
             patch.object(orchestrator.dns_scanner, "scan", new_callable=AsyncMock) as mock_dns, \
             patch.object(orchestrator.dangling_detector, "detect", new_callable=AsyncMock) as mock_dang, \
             patch.object(orchestrator.takeover_detector, "detect", new_callable=AsyncMock) as mock_take:

            mock_sub.return_value = []
            mock_dns.return_value = []

            # Return findings with different severities
            mock_dang.return_value = [
                Finding(
                    scan_id="",
                    severity="CRITICAL",
                    type="dangling_cname",
                    domain="api.example.com",
                    record_type="CNAME",
                    target="old-service.herokuapp.com",
                    description="Critical finding",
                    cvss_score=9.1,
                    remediation="Fix it",
                    raw_data={},
                    confidence=1.0,
                ),
            ]
            mock_take.return_value = [
                Finding(
                    scan_id="",
                    severity="HIGH",
                    type="subdomain_takeover",
                    domain="test.example.com",
                    record_type="CNAME",
                    target="app.herokuapp.com",
                    description="High finding",
                    cvss_score=7.5,
                    remediation="Fix it",
                    raw_data={},
                    confidence=0.95,
                ),
                Finding(
                    scan_id="",
                    severity="MEDIUM",
                    type="subdomain_takeover",
                    domain="dev.example.com",
                    record_type="CNAME",
                    target="test.azurewebsites.net",
                    description="Medium finding",
                    cvss_score=5.3,
                    remediation="Fix it",
                    raw_data={},
                    confidence=0.7,
                ),
            ]

            result = await orchestrator.scan(domains)

            assert result["summary"]["CRITICAL"] == 1
            assert result["summary"]["HIGH"] == 1
            assert result["summary"]["MEDIUM"] == 1
            assert result["summary"]["LOW"] == 0

    @pytest.mark.asyncio
    async def test_scan_multiple_domains(self, orchestrator: ScanOrchestrator) -> None:
        """Test scanning multiple domains."""
        domains = ["example.com", "test.com"]

        with patch.object(orchestrator.subdomain_scanner, "scan", new_callable=AsyncMock) as mock_sub, \
             patch.object(orchestrator.dns_scanner, "scan", new_callable=AsyncMock) as mock_dns, \
             patch.object(orchestrator.dangling_detector, "detect", new_callable=AsyncMock) as mock_dang, \
             patch.object(orchestrator.takeover_detector, "detect", new_callable=AsyncMock) as mock_take:

            mock_sub.return_value = []
            mock_dns.return_value = []
            mock_dang.return_value = []
            mock_take.return_value = []

            result = await orchestrator.scan(domains)

            # Should scan both domains
            assert mock_sub.call_count == 2
            assert result["domains"] == domains

    @pytest.mark.asyncio
    async def test_scan_error_handling(
        self, orchestrator: ScanOrchestrator, db: DatabaseManager
    ) -> None:
        """Test error handling during scan."""
        domains = ["example.com"]

        with patch.object(orchestrator.subdomain_scanner, "scan", new_callable=AsyncMock) as mock_sub:
            # Make scanner raise exception
            mock_sub.side_effect = Exception("Scanner error")

            with pytest.raises(Exception) as exc_info:
                await orchestrator.scan(domains)

            assert "Scanner error" in str(exc_info.value)

            # Scan should be marked as failed
            # Note: We need to get the scan_id somehow, but it's created internally
            # For now, just verify the exception is raised

    @pytest.mark.asyncio
    async def test_scan_dns_failure_continues(self, orchestrator: ScanOrchestrator) -> None:
        """Test that scan continues when DNS fails for one subdomain."""
        domains = ["example.com"]

        with patch.object(orchestrator.subdomain_scanner, "scan", new_callable=AsyncMock) as mock_sub, \
             patch.object(orchestrator.dns_scanner, "scan", new_callable=AsyncMock) as mock_dns, \
             patch.object(orchestrator.dangling_detector, "detect", new_callable=AsyncMock) as mock_dang, \
             patch.object(orchestrator.takeover_detector, "detect", new_callable=AsyncMock) as mock_take:

            mock_sub.return_value = [
                SubdomainResult(domain="www.example.com", source="crtsh"),
                SubdomainResult(domain="api.example.com", source="crtsh"),
            ]

            # Fail DNS for first subdomain, succeed for others
            mock_dns.side_effect = [
                [],  # example.com succeeds
                Exception("DNS failed"),  # www.example.com fails
                [],  # api.example.com succeeds
            ]

            mock_dang.return_value = []
            mock_take.return_value = []

            result = await orchestrator.scan(domains)

            # Should still complete successfully
            assert result["scan_id"] is not None

    @pytest.mark.asyncio
    async def test_cleanup(self, orchestrator: ScanOrchestrator) -> None:
        """Test resource cleanup."""
        await orchestrator.cleanup()

        # HTTP client should be closed
        # (Can't easily verify this without inspecting internal state)

    def test_count_findings_by_severity(self, orchestrator: ScanOrchestrator) -> None:
        """Test finding count aggregation."""
        findings = [
            Finding(
                scan_id="test",
                severity="CRITICAL",
                type="test",
                domain="example.com",
                record_type="CNAME",
                target="test.com",
                description="Test",
                cvss_score=9.0,
                remediation="Fix",
                raw_data={},
                confidence=1.0,
            ),
            Finding(
                scan_id="test",
                severity="CRITICAL",
                type="test",
                domain="example.com",
                record_type="CNAME",
                target="test.com",
                description="Test",
                cvss_score=9.0,
                remediation="Fix",
                raw_data={},
                confidence=1.0,
            ),
            Finding(
                scan_id="test",
                severity="HIGH",
                type="test",
                domain="example.com",
                record_type="CNAME",
                target="test.com",
                description="Test",
                cvss_score=7.0,
                remediation="Fix",
                raw_data={},
                confidence=1.0,
            ),
        ]

        counts = orchestrator._count_findings_by_severity(findings)

        assert counts["CRITICAL"] == 2
        assert counts["HIGH"] == 1
        assert counts["MEDIUM"] == 0
        assert counts["LOW"] == 0
