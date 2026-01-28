"""Unit tests for detectors."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from security_scanner.detectors.dangling_dns import DanglingDNSDetector
from security_scanner.detectors.patterns import PatternMatcher, PlatformPattern
from security_scanner.detectors.takeover import TakeoverDetector
from security_scanner.scanner.dns import DNSScanner
from security_scanner.scanner.models import DNSResult
from security_scanner.storage.models import Finding
from security_scanner.utils.http_client import HTTPClient
from tests.fixtures.mock_responses import get_mock_http_response


class TestDanglingDNSDetector:
    """Test dangling DNS detector."""

    @pytest.fixture
    def mock_dns_scanner(self) -> DNSScanner:
        """Create mock DNS scanner."""
        scanner = MagicMock(spec=DNSScanner)
        scanner.check_dangling_cname = AsyncMock()
        return scanner

    @pytest.fixture
    def detector(self, mock_dns_scanner: DNSScanner) -> DanglingDNSDetector:
        """Create dangling DNS detector instance."""
        return DanglingDNSDetector(dns_scanner=mock_dns_scanner)

    @pytest.mark.asyncio
    async def test_detect_dangling_cname(
        self, detector: DanglingDNSDetector, mock_dns_scanner: DNSScanner
    ) -> None:
        """Test detection of dangling CNAME."""
        scan_id = "test-scan-123"
        domain = "api.example.com"

        dns_records = [
            DNSResult(
                domain=domain,
                record_type="CNAME",
                values=["old-service.herokuapp.com"],
                ttl=300,
                nameserver="8.8.8.8",
            )
        ]

        mock_dns_scanner.check_dangling_cname.return_value = (True, "old-service.herokuapp.com")

        findings = await detector.detect({
            "domain": domain,
            "dns_records": dns_records,
            "scan_id": scan_id,
        })

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == "CRITICAL"
        assert finding.type == "dangling_cname"
        assert finding.domain == domain
        assert finding.target == "old-service.herokuapp.com"
        assert finding.cvss_score == 9.1
        assert finding.confidence == 1.0

    @pytest.mark.asyncio
    async def test_detect_no_dangling_cname(
        self, detector: DanglingDNSDetector, mock_dns_scanner: DNSScanner
    ) -> None:
        """Test detection when CNAME is not dangling."""
        dns_records = [
            DNSResult(
                domain="www.example.com",
                record_type="CNAME",
                values=["cdn.example.com"],
                ttl=300,
                nameserver="8.8.8.8",
            )
        ]

        mock_dns_scanner.check_dangling_cname.return_value = (False, "cdn.example.com")

        findings = await detector.detect({
            "domain": "www.example.com",
            "dns_records": dns_records,
            "scan_id": "test-scan",
        })

        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_detect_nxdomain_a_record(
        self, detector: DanglingDNSDetector, mock_dns_scanner: DNSScanner
    ) -> None:
        """Test detection of NXDOMAIN for A records."""
        dns_records = [
            DNSResult(
                domain="nonexistent.example.com",
                record_type="A",
                values=[],
                ttl=0,
                nameserver="8.8.8.8",
                error="NXDOMAIN",
            )
        ]

        findings = await detector.detect({
            "domain": "nonexistent.example.com",
            "dns_records": dns_records,
            "scan_id": "test-scan",
        })

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == "MEDIUM"
        assert finding.type == "nxdomain"
        assert "does not exist" in finding.description

    @pytest.mark.asyncio
    async def test_detect_empty_data(self, detector: DanglingDNSDetector) -> None:
        """Test detection with empty data."""
        findings = await detector.detect({})
        assert findings == []

        findings = await detector.detect({"domain": "example.com", "dns_records": []})
        assert findings == []

    @pytest.mark.asyncio
    async def test_detect_no_cname_records(
        self, detector: DanglingDNSDetector, mock_dns_scanner: DNSScanner
    ) -> None:
        """Test detection when there are no CNAME records."""
        dns_records = [
            DNSResult(
                domain="example.com",
                record_type="A",
                values=["93.184.216.34"],
                ttl=300,
                nameserver="8.8.8.8",
            )
        ]

        findings = await detector.detect({
            "domain": "example.com",
            "dns_records": dns_records,
            "scan_id": "test-scan",
        })

        # Should not call check_dangling_cname
        mock_dns_scanner.check_dangling_cname.assert_not_called()
        assert len(findings) == 0


class TestPatternMatcher:
    """Test pattern matcher."""

    @pytest.fixture
    def matcher(self) -> PatternMatcher:
        """Create pattern matcher instance."""
        return PatternMatcher()

    def test_match_cname_heroku(self, matcher: PatternMatcher) -> None:
        """Test Heroku CNAME pattern matching."""
        platform = matcher.match_cname("old-app.herokuapp.com")

        assert platform is not None
        assert platform.name == "Heroku"
        assert platform.severity == "HIGH"

    def test_match_cname_github_pages(self, matcher: PatternMatcher) -> None:
        """Test GitHub Pages CNAME pattern matching."""
        platform = matcher.match_cname("username.github.io")

        assert platform is not None
        assert platform.name == "GitHub Pages"

    def test_match_cname_aws_s3(self, matcher: PatternMatcher) -> None:
        """Test AWS S3 CNAME pattern matching."""
        platform = matcher.match_cname("bucket.s3.amazonaws.com")

        assert platform is not None
        assert platform.name == "AWS S3"

    def test_match_cname_aws_elastic_beanstalk(self, matcher: PatternMatcher) -> None:
        """Test AWS Elastic Beanstalk CNAME pattern matching."""
        platform = matcher.match_cname("myapp.us-west-2.elasticbeanstalk.com")

        assert platform is not None
        assert platform.name == "AWS Elastic Beanstalk"

    def test_match_cname_no_match(self, matcher: PatternMatcher) -> None:
        """Test CNAME that doesn't match any platform."""
        platform = matcher.match_cname("cdn.example.com")

        assert platform is None

    def test_match_http_response_heroku(self, matcher: PatternMatcher) -> None:
        """Test HTTP response matching for Heroku."""
        platform = PlatformPattern(
            name="Heroku",
            cname_patterns=["*.herokuapp.com"],
            http_patterns=["There's nothing here, yet.", "No such app"],
            dns_error="NXDOMAIN",
            severity="HIGH",
        )

        response_text = get_mock_http_response("heroku_takeover")
        matches = matcher.match_http_response(response_text, platform)

        assert matches is True

    def test_match_http_response_github_pages(self, matcher: PatternMatcher) -> None:
        """Test HTTP response matching for GitHub Pages."""
        platform = PlatformPattern(
            name="GitHub Pages",
            cname_patterns=["*.github.io"],
            http_patterns=["There isn't a GitHub Pages site here"],
            dns_error="NXDOMAIN",
            severity="HIGH",
        )

        response_text = get_mock_http_response("github_pages_takeover")
        matches = matcher.match_http_response(response_text, platform)

        assert matches is True

    def test_match_http_response_no_match(self, matcher: PatternMatcher) -> None:
        """Test HTTP response that doesn't match."""
        platform = PlatformPattern(
            name="Heroku",
            cname_patterns=["*.herokuapp.com"],
            http_patterns=["No such app"],
            dns_error="NXDOMAIN",
            severity="HIGH",
        )

        response_text = get_mock_http_response("normal_website")
        matches = matcher.match_http_response(response_text, platform)

        assert matches is False

    def test_load_patterns(self, matcher: PatternMatcher) -> None:
        """Test that patterns are loaded successfully."""
        # Check that at least some platforms are loaded
        assert len(matcher.platforms) >= 8

        # Check that Heroku pattern is present
        heroku = matcher.match_cname("app.herokuapp.com")
        assert heroku is not None


class TestTakeoverDetector:
    """Test takeover detector."""

    @pytest.fixture
    def mock_dns_scanner(self) -> DNSScanner:
        """Create mock DNS scanner."""
        scanner = MagicMock(spec=DNSScanner)
        scanner.resolve = AsyncMock()
        return scanner

    @pytest.fixture
    def mock_http_client(self) -> HTTPClient:
        """Create mock HTTP client."""
        client = MagicMock(spec=HTTPClient)
        client.fetch_text = AsyncMock()
        return client

    @pytest.fixture
    def detector(
        self, mock_dns_scanner: DNSScanner, mock_http_client: HTTPClient
    ) -> TakeoverDetector:
        """Create takeover detector instance."""
        return TakeoverDetector(
            dns_scanner=mock_dns_scanner,
            http_client=mock_http_client,
        )

    @pytest.mark.asyncio
    async def test_detect_heroku_takeover(
        self, detector: TakeoverDetector, mock_dns_scanner: DNSScanner, mock_http_client: HTTPClient
    ) -> None:
        """Test detection of Heroku subdomain takeover."""
        scan_id = "test-scan-123"
        domain = "api.example.com"

        dns_records = [
            DNSResult(
                domain=domain,
                record_type="CNAME",
                values=["old-app.herokuapp.com"],
                ttl=300,
                nameserver="8.8.8.8",
            )
        ]

        # Mock DNS resolution - target doesn't resolve
        mock_dns_scanner.resolve.return_value = DNSResult(
            domain="old-app.herokuapp.com",
            record_type="A",
            values=[],
            ttl=0,
            nameserver="8.8.8.8",
            error="NXDOMAIN",
        )

        # Mock HTTP response
        mock_http_client.fetch_text.return_value = get_mock_http_response("heroku_takeover")

        findings = await detector.detect({
            "domain": domain,
            "dns_records": dns_records,
            "scan_id": scan_id,
        })

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == "HIGH"
        assert finding.type == "subdomain_takeover"
        assert finding.domain == domain
        assert finding.target == "old-app.herokuapp.com"
        assert finding.platform == "Heroku"
        assert finding.confidence >= 0.95

    @pytest.mark.asyncio
    async def test_detect_github_pages_takeover(
        self, detector: TakeoverDetector, mock_dns_scanner: DNSScanner, mock_http_client: HTTPClient
    ) -> None:
        """Test detection of GitHub Pages subdomain takeover."""
        domain = "docs.example.com"

        dns_records = [
            DNSResult(
                domain=domain,
                record_type="CNAME",
                values=["username.github.io"],
                ttl=300,
                nameserver="8.8.8.8",
            )
        ]

        mock_dns_scanner.resolve.return_value = DNSResult(
            domain="username.github.io",
            record_type="A",
            values=[],
            ttl=0,
            nameserver="8.8.8.8",
            error="NXDOMAIN",
        )

        mock_http_client.fetch_text.return_value = get_mock_http_response("github_pages_takeover")

        findings = await detector.detect({
            "domain": domain,
            "dns_records": dns_records,
            "scan_id": "test-scan",
        })

        assert len(findings) == 1
        assert findings[0].platform == "GitHub Pages"

    @pytest.mark.asyncio
    async def test_detect_no_platform_match(
        self, detector: TakeoverDetector, mock_dns_scanner: DNSScanner
    ) -> None:
        """Test detection when CNAME doesn't match any platform."""
        dns_records = [
            DNSResult(
                domain="www.example.com",
                record_type="CNAME",
                values=["cdn.example.com"],  # Not a known platform
                ttl=300,
                nameserver="8.8.8.8",
            )
        ]

        findings = await detector.detect({
            "domain": "www.example.com",
            "dns_records": dns_records,
            "scan_id": "test-scan",
        })

        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_detect_target_resolves(
        self, detector: TakeoverDetector, mock_dns_scanner: DNSScanner, mock_http_client: HTTPClient
    ) -> None:
        """Test detection when CNAME target resolves (no takeover)."""
        dns_records = [
            DNSResult(
                domain="app.example.com",
                record_type="CNAME",
                values=["active-app.herokuapp.com"],
                ttl=300,
                nameserver="8.8.8.8",
            )
        ]

        # Mock DNS resolution - target DOES resolve
        mock_dns_scanner.resolve.return_value = DNSResult(
            domain="active-app.herokuapp.com",
            record_type="A",
            values=["1.2.3.4"],
            ttl=300,
            nameserver="8.8.8.8",
        )

        findings = await detector.detect({
            "domain": "app.example.com",
            "dns_records": dns_records,
            "scan_id": "test-scan",
        })

        # Should not detect takeover if target resolves
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_detect_http_verification_fails(
        self, detector: TakeoverDetector, mock_dns_scanner: DNSScanner, mock_http_client: HTTPClient
    ) -> None:
        """Test detection when HTTP verification doesn't match."""
        dns_records = [
            DNSResult(
                domain="api.example.com",
                record_type="CNAME",
                values=["old-app.herokuapp.com"],
                ttl=300,
                nameserver="8.8.8.8",
            )
        ]

        mock_dns_scanner.resolve.return_value = DNSResult(
            domain="old-app.herokuapp.com",
            record_type="A",
            values=[],
            ttl=0,
            nameserver="8.8.8.8",
            error="NXDOMAIN",
        )

        # HTTP response doesn't match platform pattern
        mock_http_client.fetch_text.return_value = get_mock_http_response("normal_website")

        findings = await detector.detect({
            "domain": "api.example.com",
            "dns_records": dns_records,
            "scan_id": "test-scan",
        })

        # Should still detect with medium confidence (DNS error matches but HTTP doesn't)
        assert len(findings) == 1
        assert findings[0].confidence == 0.7

    @pytest.mark.asyncio
    async def test_detect_empty_data(self, detector: TakeoverDetector) -> None:
        """Test detection with empty data."""
        findings = await detector.detect({})
        assert findings == []

    @pytest.mark.asyncio
    async def test_detect_no_cname_records(self, detector: TakeoverDetector) -> None:
        """Test detection when there are no CNAME records."""
        dns_records = [
            DNSResult(
                domain="example.com",
                record_type="A",
                values=["93.184.216.34"],
                ttl=300,
                nameserver="8.8.8.8",
            )
        ]

        findings = await detector.detect({
            "domain": "example.com",
            "dns_records": dns_records,
            "scan_id": "test-scan",
        })

        assert len(findings) == 0

    def test_calculate_cvss(self, detector: TakeoverDetector) -> None:
        """Test CVSS score calculation."""
        assert detector._calculate_cvss("CRITICAL") == 9.1
        assert detector._calculate_cvss("HIGH") == 7.5
        assert detector._calculate_cvss("MEDIUM") == 5.3
        assert detector._calculate_cvss("LOW") == 3.7
        assert detector._calculate_cvss("UNKNOWN") == 5.0  # Default
