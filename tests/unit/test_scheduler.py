"""Unit tests for scan scheduler."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from security_scanner.scheduler import ScanScheduler


class TestScanScheduler:
    """Test scan scheduler functionality."""

    @pytest.fixture
    def settings(self):
        s = MagicMock()
        s.http_timeout = 10
        s.http_max_retries = 3
        s.http_max_connections = 100
        s.http_user_agent = "Test/1.0"
        s.rate_limit_requests_per_second = 2.0
        s.rate_limit_burst = 5
        s.cache_max_size = 100
        s.cache_ttl = 300
        s.enable_cache = False
        s.dns_nameservers = ["8.8.8.8"]
        s.dns_timeout = 5
        s.dns_max_retries = 3
        s.max_concurrent_scans = 10
        s.subdomain_sources = ["crtsh"]
        s.subfinder_path = None
        s.assetfinder_path = None
        s.certificate_json_file = None
        s.enable_certificate_monitoring = False
        return s

    @pytest.fixture
    def db(self):
        db = AsyncMock()
        db.initialize = AsyncMock()
        db.get_similar_findings = AsyncMock(return_value=[])
        return db

    @pytest.fixture
    def scheduler(self, settings, db):
        return ScanScheduler(
            settings=settings,
            db=db,
            domains=["example.com"],
            interval_seconds=60,
        )

    def test_initialization(self, scheduler):
        assert scheduler.domains == ["example.com"]
        assert scheduler.interval_seconds == 60
        assert scheduler.is_running is False
        assert scheduler.scan_count == 0
        assert scheduler.last_scan_id is None

    async def test_run_scan_success(self, scheduler, settings, db):
        mock_orchestrator = AsyncMock()
        mock_orchestrator.scan = AsyncMock(
            return_value={
                "scan_id": "test-123",
                "domains": ["example.com"],
                "findings": [],
                "summary": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            }
        )
        mock_orchestrator.__aenter__ = AsyncMock(return_value=mock_orchestrator)
        mock_orchestrator.__aexit__ = AsyncMock()

        scheduler._orchestrator = mock_orchestrator
        result = await scheduler._run_scan()

        assert result is not None
        assert result["scan_id"] == "test-123"
        assert scheduler.scan_count == 1
        assert scheduler.last_scan_id == "test-123"

    async def test_run_scan_failure(self, scheduler):
        mock_orchestrator = AsyncMock()
        mock_orchestrator.scan = AsyncMock(side_effect=Exception("Scan error"))

        scheduler._orchestrator = mock_orchestrator
        result = await scheduler._run_scan()

        assert result is None
        assert scheduler.scan_count == 1

    async def test_detect_new_findings_all_new(self, scheduler, db):
        finding1 = MagicMock()
        finding1.domain = "api.example.com"
        finding1.type = "dangling_cname"

        finding2 = MagicMock()
        finding2.domain = "www.example.com"
        finding2.type = "takeover"

        # Only one similar finding for each (the finding itself)
        db.get_similar_findings = AsyncMock(return_value=[MagicMock()])

        new = await scheduler._detect_new_findings([finding1, finding2])
        assert len(new) == 2

    async def test_detect_new_findings_none_new(self, scheduler, db):
        finding = MagicMock()
        finding.domain = "api.example.com"
        finding.type = "dangling_cname"

        # Multiple similar findings = not new
        db.get_similar_findings = AsyncMock(return_value=[MagicMock(), MagicMock()])

        new = await scheduler._detect_new_findings([finding])
        assert len(new) == 0

    async def test_stop(self, scheduler):
        scheduler._running = True
        await scheduler.stop()
        assert scheduler.is_running is False

    async def test_start_and_stop(self, scheduler, settings, db):
        """Test that start loop runs one scan and stops when signaled."""
        mock_orchestrator = AsyncMock()
        mock_orchestrator.scan = AsyncMock(
            return_value={
                "scan_id": "test-456",
                "domains": ["example.com"],
                "findings": [],
                "summary": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            }
        )
        mock_orchestrator.__aenter__ = AsyncMock(return_value=mock_orchestrator)
        mock_orchestrator.__aexit__ = AsyncMock()

        with patch.object(scheduler, "_run_scan", wraps=scheduler._run_scan):
            # Replace orchestrator creation in start
            with patch(
                "security_scanner.scheduler.ScanOrchestrator",
                return_value=mock_orchestrator,
            ):

                async def stop_on_sleep(seconds):
                    await scheduler.stop()

                with patch("asyncio.sleep", side_effect=stop_on_sleep):
                    await scheduler.start()

        assert scheduler.scan_count == 1

    async def test_multiple_scan_cycles(self, scheduler):
        """Test counting across multiple scans."""
        mock_orchestrator = AsyncMock()
        call_count = 0

        async def mock_scan(domains):
            nonlocal call_count
            call_count += 1
            return {
                "scan_id": f"scan-{call_count}",
                "domains": domains,
                "findings": [],
                "summary": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            }

        mock_orchestrator.scan = mock_scan
        scheduler._orchestrator = mock_orchestrator

        await scheduler._run_scan()
        await scheduler._run_scan()
        await scheduler._run_scan()

        assert scheduler.scan_count == 3
        assert scheduler.last_scan_id == "scan-3"
