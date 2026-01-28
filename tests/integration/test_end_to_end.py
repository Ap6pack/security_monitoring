"""End-to-end integration tests for complete scan workflows."""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from security_scanner.config import Settings
from security_scanner.orchestrator import ScanOrchestrator
from security_scanner.scanner.models import DNSResult, SubdomainResult
from security_scanner.storage.database import DatabaseManager
from security_scanner.storage.models import Finding
from tests.fixtures.mock_responses import (
    get_mock_crtsh_response,
    get_mock_http_response,
)


class TestEndToEndScan:
    """End-to-end integration tests for complete scan workflows."""

    @pytest.fixture
    async def db(self, tmp_path: Path) -> DatabaseManager:
        """Create temporary test database."""
        db_path = tmp_path / "test_e2e.db"
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

    @pytest.mark.asyncio
    async def test_complete_scan_with_findings(
        self, settings: Settings, db: DatabaseManager
    ) -> None:
        """Test complete scan workflow with mocked external dependencies."""
        async with ScanOrchestrator(settings=settings, db=db) as orchestrator:
            # Mock all external API calls at higher level
            with patch.object(orchestrator.http_client, "get", new_callable=AsyncMock) as mock_http_get, \
                 patch.object(orchestrator.http_client, "fetch_text", new_callable=AsyncMock) as mock_http_fetch, \
                 patch.object(orchestrator.dns_scanner, "scan", new_callable=AsyncMock) as mock_dns_scan, \
                 patch.object(orchestrator.dns_scanner, "check_dangling_cname", new_callable=AsyncMock) as mock_check_dangling:

                # Mock crt.sh response for subdomain discovery
                mock_http_get.return_value = get_mock_crtsh_response("example.com")

                # Mock DNS scan results with CNAME for api.example.com
                def dns_scan_side_effect(domain):
                    if domain == "api.example.com":
                        return [
                            DNSResult(
                                domain=domain,
                                record_type="CNAME",
                                values=["old-service.herokuapp.com"],
                                ttl=300,
                                nameserver="8.8.8.8",
                            )
                        ]
                    return [
                        DNSResult(
                            domain=domain,
                            record_type="A",
                            values=["93.184.216.34"],
                            ttl=300,
                            nameserver="8.8.8.8",
                        )
                    ]

                mock_dns_scan.side_effect = dns_scan_side_effect

                # Mock dangling CNAME check
                def check_dangling_side_effect(domain):
                    if domain == "api.example.com":
                        return (True, "old-service.herokuapp.com")
                    return (False, None)

                mock_check_dangling.side_effect = check_dangling_side_effect

                # Mock HTTP response for takeover verification
                mock_http_fetch.return_value = get_mock_http_response("heroku_takeover")

                # Run the scan
                result = await orchestrator.scan(["example.com"])

                # Verify scan completed
                assert result["scan_id"] is not None
                assert result["domains"] == ["example.com"]

                # Verify findings were detected
                assert len(result["findings"]) > 0

                # Verify findings are in database
                findings = await db.get_scan_findings(result["scan_id"])
                assert len(findings) > 0

                # Verify scan record exists
                scan = await db.get_scan(result["scan_id"])
                assert scan is not None
                assert scan.status == "completed"

    @pytest.mark.asyncio
    async def test_scan_with_no_findings(
        self, settings: Settings, db: DatabaseManager
    ) -> None:
        """Test scan that completes with no security findings."""
        async with ScanOrchestrator(settings=settings, db=db) as orchestrator:
            with patch.object(orchestrator.http_client, "get", new_callable=AsyncMock) as mock_http_get, \
                 patch.object(orchestrator.dns_scanner._resolver, "resolve") as mock_dns_resolve:

                # Mock minimal responses
                mock_http_get.return_value = []  # No subdomains

                from tests.fixtures.mock_responses import create_mock_dns_answer
                mock_dns_resolve.return_value = create_mock_dns_answer("A", ["93.184.216.34"])

                result = await orchestrator.scan(["example.com"])

                # Scan completes successfully
                assert result["scan_id"] is not None
                assert len(result["findings"]) == 0

                # Verify database state
                scan = await db.get_scan(result["scan_id"])
                assert scan is not None
                assert scan.status == "completed"

    @pytest.mark.asyncio
    async def test_scan_multiple_domains_with_different_findings(
        self, settings: Settings, db: DatabaseManager
    ) -> None:
        """Test scanning multiple domains with different finding types."""
        async with ScanOrchestrator(settings=settings, db=db) as orchestrator:
            with patch.object(orchestrator.http_client, "get", new_callable=AsyncMock) as mock_http_get, \
                 patch.object(orchestrator.http_client, "fetch_text", new_callable=AsyncMock) as mock_http_fetch, \
                 patch.object(orchestrator.dns_scanner, "scan", new_callable=AsyncMock) as mock_dns_scan, \
                 patch.object(orchestrator.dns_scanner, "check_dangling_cname", new_callable=AsyncMock) as mock_check_dangling:

                # Mock crt.sh responses for both domains
                def http_get_side_effect(url, params=None):
                    if params and "example.com" in params.get("q", ""):
                        return get_mock_crtsh_response("example.com")
                    elif params and "test.com" in params.get("q", ""):
                        return get_mock_crtsh_response("test.com")
                    return []

                mock_http_get.side_effect = http_get_side_effect

                # Mock DNS scan results
                def dns_scan_side_effect(domain):
                    if "api.example.com" in domain:
                        return [
                            DNSResult(
                                domain=domain,
                                record_type="CNAME",
                                values=["old-app.herokuapp.com"],
                                ttl=300,
                                nameserver="8.8.8.8",
                            )
                        ]
                    return [
                        DNSResult(
                            domain=domain,
                            record_type="A",
                            values=["93.184.216.34"] if "example.com" in domain else ["1.2.3.4"],
                            ttl=300,
                            nameserver="8.8.8.8",
                        )
                    ]

                mock_dns_scan.side_effect = dns_scan_side_effect

                # Mock dangling CNAME check
                def check_dangling_side_effect(domain):
                    if "api.example.com" in domain:
                        return (True, "old-app.herokuapp.com")
                    return (False, None)

                mock_check_dangling.side_effect = check_dangling_side_effect
                mock_http_fetch.return_value = get_mock_http_response("heroku_takeover")

                # Scan both domains
                result = await orchestrator.scan(["example.com", "test.com"])

                assert len(result["domains"]) == 2

                # Should have findings from first domain
                assert len(result["findings"]) > 0

    @pytest.mark.asyncio
    async def test_scan_with_partial_failures(
        self, settings: Settings, db: DatabaseManager
    ) -> None:
        """Test that scan completes even when some operations fail."""
        async with ScanOrchestrator(settings=settings, db=db) as orchestrator:
            with patch.object(orchestrator.http_client, "get", new_callable=AsyncMock) as mock_http_get, \
                 patch.object(orchestrator.dns_scanner._resolver, "resolve") as mock_dns_resolve:

                # Mock successful subdomain discovery
                mock_http_get.return_value = [
                    {
                        "id": "1",
                        "name_value": "www.example.com\napi.example.com\nbad.example.com",
                        "issuer_name": "Let's Encrypt",
                        "common_name": "example.com",
                        "not_before": "2024-01-01T00:00:00Z",
                        "not_after": "2024-12-31T23:59:59Z",
                        "entry_timestamp": "2024-01-01T00:00:00Z",
                    }
                ]

                # Mock DNS to fail for one subdomain
                def dns_side_effect(domain, rdtype):
                    from tests.fixtures.mock_responses import create_mock_dns_answer
                    import dns.exception

                    if "bad.example" in domain:
                        raise dns.exception.Timeout()  # Fail for this subdomain

                    # Others succeed
                    if str(rdtype) == "A":
                        return create_mock_dns_answer("A", ["93.184.216.34"])

                    import dns.resolver
                    raise dns.resolver.NoAnswer()

                mock_dns_resolve.side_effect = dns_side_effect

                result = await orchestrator.scan(["example.com"])

                # Should complete successfully despite partial failures
                assert result["scan_id"] is not None
                assert result["domains"] == ["example.com"]

                # Verify scan completed
                scan = await db.get_scan(result["scan_id"])
                assert scan is not None
                assert scan.status == "completed"

    @pytest.mark.asyncio
    async def test_scan_with_severity_distribution(
        self, settings: Settings, db: DatabaseManager
    ) -> None:
        """Test scan with findings of different severity levels."""
        async with ScanOrchestrator(settings=settings, db=db) as orchestrator:
            with patch.object(orchestrator.dangling_detector, "detect", new_callable=AsyncMock) as mock_dang, \
                 patch.object(orchestrator.takeover_detector, "detect", new_callable=AsyncMock) as mock_take, \
                 patch.object(orchestrator.subdomain_scanner, "scan", new_callable=AsyncMock) as mock_sub, \
                 patch.object(orchestrator.dns_scanner, "scan", new_callable=AsyncMock) as mock_dns:

                mock_sub.return_value = []
                mock_dns.return_value = []

                # Mock findings with different severities
                # Use side_effect to return new Finding objects each time
                def create_dang_findings(*args, **kwargs):
                    return [
                        Finding(
                            scan_id="",
                            severity="CRITICAL",
                            type="dangling_cname",
                            domain="critical.example.com",
                            record_type="CNAME",
                            target="target1.com",
                            description="Critical issue",
                            cvss_score=9.1,
                            remediation="Fix immediately",
                            raw_data={},
                            confidence=1.0,
                        ),
                        Finding(
                            scan_id="",
                            severity="MEDIUM",
                            type="nxdomain",
                            domain="medium.example.com",
                            record_type="A",
                            target=None,
                            description="Medium issue",
                            cvss_score=5.3,
                            remediation="Investigate",
                            raw_data={},
                            confidence=0.8,
                        ),
                    ]

                def create_take_findings(*args, **kwargs):
                    return [
                        Finding(
                            scan_id="",
                            severity="HIGH",
                            type="subdomain_takeover",
                            domain="high.example.com",
                            record_type="CNAME",
                            target="target2.com",
                            description="High issue",
                            cvss_score=7.5,
                            remediation="Fix soon",
                            raw_data={},
                            confidence=0.95,
                        ),
                    ]

                mock_dang.side_effect = create_dang_findings
                mock_take.side_effect = create_take_findings

                result = await orchestrator.scan(["example.com"])

                # Verify severity distribution
                assert result["summary"]["CRITICAL"] == 1
                assert result["summary"]["HIGH"] == 1
                assert result["summary"]["MEDIUM"] == 1
                assert result["summary"]["LOW"] == 0

                # Verify all findings are stored
                findings = await db.get_scan_findings(result["scan_id"])
                assert len(findings) == 3

                # Verify severity distribution matches
                severities = {f.severity for f in findings}
                assert "CRITICAL" in severities
                assert "HIGH" in severities
                assert "MEDIUM" in severities

    @pytest.mark.asyncio
    async def test_scan_deduplication_across_scans(
        self, settings: Settings, db: DatabaseManager
    ) -> None:
        """Test that similar findings are deduplicated across multiple scans."""
        async with ScanOrchestrator(settings=settings, db=db) as orchestrator:
            with patch.object(orchestrator.subdomain_scanner, "scan", new_callable=AsyncMock) as mock_sub, \
                 patch.object(orchestrator.dns_scanner, "scan", new_callable=AsyncMock) as mock_dns, \
                 patch.object(orchestrator.dangling_detector, "detect", new_callable=AsyncMock) as mock_dang, \
                 patch.object(orchestrator.takeover_detector, "detect", new_callable=AsyncMock) as mock_take:

                mock_sub.return_value = []
                mock_dns.return_value = []
                mock_take.return_value = []

                # Create new finding each time to avoid UUID conflicts
                def create_finding(*args, **kwargs):
                    return [
                        Finding(
                            scan_id="",
                            severity="CRITICAL",
                            type="dangling_cname",
                            domain="api.example.com",
                            record_type="CNAME",
                            target="old-service.herokuapp.com",
                            description="Dangling CNAME",
                            cvss_score=9.1,
                            remediation="Remove CNAME",
                            raw_data={},
                            confidence=1.0,
                        )
                    ]

                mock_dang.side_effect = create_finding

                # First scan
                result1 = await orchestrator.scan(["example.com"])
                assert len(result1["findings"]) == 1

                # Second scan with same finding
                result2 = await orchestrator.scan(["example.com"])
                assert len(result2["findings"]) == 1

                # Verify both findings are in database (not deduplicated by orchestrator)
                findings1 = await db.get_scan_findings(result1["scan_id"])
                findings2 = await db.get_scan_findings(result2["scan_id"])

                assert len(findings1) == 1
                assert len(findings2) == 1

                # But they have different scan_ids
                assert findings1[0].scan_id != findings2[0].scan_id

                # Can query for similar findings
                similar = await db.get_similar_findings(
                    domain="api.example.com",
                    finding_type="dangling_cname",
                    days=7,
                )
                assert len(similar) >= 2  # Should find both

    @pytest.mark.asyncio
    async def test_full_workflow_with_reporting_data(
        self, settings: Settings, db: DatabaseManager
    ) -> None:
        """Test complete workflow produces data suitable for reporting."""
        async with ScanOrchestrator(settings=settings, db=db) as orchestrator:
            with patch.object(orchestrator.subdomain_scanner, "scan", new_callable=AsyncMock) as mock_sub, \
                 patch.object(orchestrator.dns_scanner, "scan", new_callable=AsyncMock) as mock_dns, \
                 patch.object(orchestrator.dangling_detector, "detect", new_callable=AsyncMock) as mock_dang, \
                 patch.object(orchestrator.takeover_detector, "detect", new_callable=AsyncMock) as mock_take:

                mock_sub.return_value = [
                    SubdomainResult(domain="www.example.com", source="crtsh"),
                    SubdomainResult(domain="api.example.com", source="crtsh"),
                ]

                mock_dns.return_value = [
                    DNSResult(
                        domain="example.com",
                        record_type="A",
                        values=["93.184.216.34"],
                        ttl=300,
                        nameserver="8.8.8.8",
                    )
                ]

                # Create new finding each time to avoid UUID conflicts
                def create_reporting_finding(*args, **kwargs):
                    return [
                        Finding(
                            scan_id="",
                            severity="CRITICAL",
                            type="dangling_cname",
                            domain="api.example.com",
                            record_type="CNAME",
                            target="old-service.herokuapp.com",
                            description="Dangling CNAME detected for api.example.com",
                            cvss_score=9.1,
                            remediation="Remove the CNAME record immediately",
                            raw_data={"cname_target": "old-service.herokuapp.com"},
                            confidence=1.0,
                        )
                    ]

                mock_dang.side_effect = create_reporting_finding
                mock_take.return_value = []

                result = await orchestrator.scan(["example.com"])

                # Verify result structure is suitable for reporting
                assert "scan_id" in result
                assert "domains" in result
                assert "findings" in result
                assert "summary" in result

                # Verify finding has all required fields for reporting
                finding = result["findings"][0]
                assert hasattr(finding, "severity")
                assert hasattr(finding, "type")
                assert hasattr(finding, "domain")
                assert hasattr(finding, "description")
                assert hasattr(finding, "remediation")
                assert hasattr(finding, "cvss_score")
                assert hasattr(finding, "confidence")

                # Verify scan record has metadata
                scan = await db.get_scan(result["scan_id"])
                assert scan is not None
                assert scan.start_time is not None
                assert scan.end_time is not None
                assert scan.domains_scanned == ["example.com"]
