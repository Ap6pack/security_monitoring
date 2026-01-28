"""Unit tests for certificate scanner."""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from security_scanner.scanner.certificate import CertificateScanner
from security_scanner.scanner.models import CertificateResult
from security_scanner.utils.exceptions import ScannerError
from security_scanner.utils.http_client import HTTPClient
from tests.fixtures.mock_responses import (
    get_mock_crtsh_expired_cert,
    get_mock_crtsh_response,
    get_mock_crtsh_shared_cert,
)


class TestCertificateScanner:
    """Test certificate scanner functionality."""

    @pytest.fixture
    def mock_http_client(self) -> HTTPClient:
        """Create mock HTTP client."""
        client = MagicMock(spec=HTTPClient)
        client.get = AsyncMock()
        return client

    @pytest.fixture
    def scanner(self, mock_http_client: HTTPClient) -> CertificateScanner:
        """Create certificate scanner instance."""
        return CertificateScanner(http_client=mock_http_client)

    @pytest.mark.asyncio
    async def test_scan_success(self, scanner: CertificateScanner, mock_http_client: HTTPClient) -> None:
        """Test successful certificate scan."""
        domain = "example.com"
        mock_http_client.get.return_value = get_mock_crtsh_response(domain)

        results = await scanner.scan(domain)

        assert len(results) > 0
        assert all(isinstance(r, CertificateResult) for r in results)

        # Verify HTTP client was called
        mock_http_client.get.assert_called_once()
        call_args = mock_http_client.get.call_args
        assert call_args[0][0] == "https://crt.sh/json"
        assert call_args[1]["params"]["q"] == domain

    @pytest.mark.asyncio
    async def test_scan_certificate_parsing(self, scanner: CertificateScanner, mock_http_client: HTTPClient) -> None:
        """Test certificate data parsing."""
        domain = "example.com"
        mock_http_client.get.return_value = get_mock_crtsh_response(domain)

        results = await scanner.scan(domain)

        # Check first certificate
        cert = results[0]
        assert cert.cert_id is not None
        assert cert.issuer is not None
        assert cert.common_name is not None
        assert len(cert.san_domains) > 0
        assert isinstance(cert.not_before, datetime)
        assert isinstance(cert.not_after, datetime)
        assert isinstance(cert.logged_at, datetime)

    @pytest.mark.asyncio
    async def test_scan_wildcard_detection(self, scanner: CertificateScanner, mock_http_client: HTTPClient) -> None:
        """Test wildcard certificate detection."""
        domain = "example.com"
        mock_http_client.get.return_value = get_mock_crtsh_response(domain)

        results = await scanner.scan(domain)

        # Should detect wildcard cert
        wildcard_certs = [c for c in results if c.is_wildcard]
        assert len(wildcard_certs) > 0
        assert any("*." in domain for cert in wildcard_certs for domain in cert.san_domains)

    @pytest.mark.asyncio
    async def test_scan_expired_certificate(self, scanner: CertificateScanner, mock_http_client: HTTPClient) -> None:
        """Test expired certificate detection."""
        domain = "example.com"
        mock_http_client.get.return_value = get_mock_crtsh_expired_cert(domain)

        results = await scanner.scan(domain)

        assert len(results) > 0
        expired_certs = [c for c in results if c.is_expired]
        assert len(expired_certs) > 0

    @pytest.mark.asyncio
    async def test_scan_invalid_response_format(
        self, scanner: CertificateScanner, mock_http_client: HTTPClient
    ) -> None:
        """Test handling of invalid response format."""
        mock_http_client.get.return_value = {"error": "Invalid"}

        results = await scanner.scan("example.com")

        # Should return empty list for invalid format
        assert results == []

    @pytest.mark.asyncio
    async def test_scan_api_error(self, scanner: CertificateScanner, mock_http_client: HTTPClient) -> None:
        """Test handling of API errors."""
        mock_http_client.get.side_effect = Exception("API down")

        with pytest.raises(ScannerError) as exc_info:
            await scanner.scan("example.com")

        assert "Certificate scan failed" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_scan_empty_results(self, scanner: CertificateScanner, mock_http_client: HTTPClient) -> None:
        """Test handling of empty results."""
        mock_http_client.get.return_value = []

        results = await scanner.scan("example.com")

        assert results == []

    @pytest.mark.asyncio
    async def test_parse_certificates_deduplication(
        self, scanner: CertificateScanner, mock_http_client: HTTPClient
    ) -> None:
        """Test that certificates are deduplicated by ID."""
        domain = "example.com"

        # Mock response with duplicate cert IDs
        duplicate_response = [
            {
                "id": "123",
                "issuer_name": "Let's Encrypt",
                "common_name": "example.com",
                "name_value": "example.com",
                "not_before": "2024-01-01T00:00:00Z",
                "not_after": "2024-12-31T23:59:59Z",
                "entry_timestamp": "2024-01-01T00:00:00Z",
            },
            {
                "id": "123",  # Same ID
                "issuer_name": "Let's Encrypt",
                "common_name": "example.com",
                "name_value": "example.com",
                "not_before": "2024-01-01T00:00:00Z",
                "not_after": "2024-12-31T23:59:59Z",
                "entry_timestamp": "2024-01-01T00:00:00Z",
            },
        ]
        mock_http_client.get.return_value = duplicate_response

        results = await scanner.scan(domain)

        # Should only have one certificate
        assert len(results) == 1

    def test_find_shared_certificates(self, scanner: CertificateScanner) -> None:
        """Test finding shared certificates."""
        now = datetime.now(timezone.utc)

        certificates = [
            CertificateResult(
                cert_id="1",
                issuer="Let's Encrypt",
                not_before=now,
                not_after=now + timedelta(days=90),
                common_name="example.com",
                san_domains=["example.com", "www.example.com"],  # Only target domain
                is_wildcard=False,
                is_expired=False,
                logged_at=now,
            ),
            CertificateResult(
                cert_id="2",
                issuer="Let's Encrypt",
                not_before=now,
                not_after=now + timedelta(days=90),
                common_name="example.com",
                san_domains=[
                    "example.com",
                    "api.example.com",
                    "external.otherdomain.com",  # External domain
                ],
                is_wildcard=False,
                is_expired=False,
                logged_at=now,
            ),
        ]

        shared = scanner.find_shared_certificates(certificates, "example.com")

        assert len(shared) == 1
        assert shared[0].cert_id == "2"
        assert "external.otherdomain.com" in shared[0].san_domains

    def test_find_recently_issued(self, scanner: CertificateScanner) -> None:
        """Test finding recently issued certificates."""
        now = datetime.now(timezone.utc)

        certificates = [
            CertificateResult(
                cert_id="1",
                issuer="Let's Encrypt",
                not_before=now - timedelta(days=5),  # Recent
                not_after=now + timedelta(days=85),
                common_name="example.com",
                san_domains=["example.com"],
                is_wildcard=False,
                is_expired=False,
                logged_at=now,
            ),
            CertificateResult(
                cert_id="2",
                issuer="Let's Encrypt",
                not_before=now - timedelta(days=60),  # Old
                not_after=now + timedelta(days=30),
                common_name="old.example.com",
                san_domains=["old.example.com"],
                is_wildcard=False,
                is_expired=False,
                logged_at=now - timedelta(days=60),
            ),
        ]

        recent = scanner.find_recently_issued(certificates, days=30)

        assert len(recent) == 1
        assert recent[0].cert_id == "1"

    def test_find_expiring_soon(self, scanner: CertificateScanner) -> None:
        """Test finding certificates expiring soon."""
        now = datetime.now(timezone.utc)

        certificates = [
            CertificateResult(
                cert_id="1",
                issuer="Let's Encrypt",
                not_before=now - timedelta(days=60),
                not_after=now + timedelta(days=10),  # Expiring soon
                common_name="example.com",
                san_domains=["example.com"],
                is_wildcard=False,
                is_expired=False,
                logged_at=now - timedelta(days=60),
            ),
            CertificateResult(
                cert_id="2",
                issuer="Let's Encrypt",
                not_before=now - timedelta(days=30),
                not_after=now + timedelta(days=60),  # Not expiring soon
                common_name="safe.example.com",
                san_domains=["safe.example.com"],
                is_wildcard=False,
                is_expired=False,
                logged_at=now - timedelta(days=30),
            ),
            CertificateResult(
                cert_id="3",
                issuer="Let's Encrypt",
                not_before=now - timedelta(days=90),
                not_after=now - timedelta(days=1),  # Already expired
                common_name="expired.example.com",
                san_domains=["expired.example.com"],
                is_wildcard=False,
                is_expired=True,
                logged_at=now - timedelta(days=90),
            ),
        ]

        expiring = scanner.find_expiring_soon(certificates, days=30)

        assert len(expiring) == 1
        assert expiring[0].cert_id == "1"
        # Should not include already expired cert
        assert all(not cert.is_expired for cert in expiring)

    @pytest.mark.asyncio
    async def test_scan_san_domains_parsing(
        self, scanner: CertificateScanner, mock_http_client: HTTPClient
    ) -> None:
        """Test parsing of Subject Alternative Names."""
        domain = "example.com"

        mock_response = [
            {
                "id": "1",
                "issuer_name": "Let's Encrypt",
                "common_name": "example.com",
                "name_value": "example.com\nwww.example.com\napi.example.com",  # Multiple SANs
                "not_before": "2024-01-01T00:00:00Z",
                "not_after": "2024-12-31T23:59:59Z",
                "entry_timestamp": "2024-01-01T00:00:00Z",
            },
        ]
        mock_http_client.get.return_value = mock_response

        results = await scanner.scan(domain)

        assert len(results) == 1
        cert = results[0]
        assert len(cert.san_domains) == 3
        assert "example.com" in cert.san_domains
        assert "www.example.com" in cert.san_domains
        assert "api.example.com" in cert.san_domains

    @pytest.mark.asyncio
    async def test_scan_malformed_certificate_entry(
        self, scanner: CertificateScanner, mock_http_client: HTTPClient
    ) -> None:
        """Test handling of malformed certificate entries."""
        domain = "example.com"

        mock_response = [
            {
                "id": "1",
                "issuer_name": "Let's Encrypt",
                # Missing common_name, name_value, dates
            },
            {
                "id": "2",
                "issuer_name": "Let's Encrypt",
                "common_name": "example.com",
                "name_value": "example.com",
                "not_before": "2024-01-01T00:00:00Z",
                "not_after": "2024-12-31T23:59:59Z",
                "entry_timestamp": "2024-01-01T00:00:00Z",
            },
        ]
        mock_http_client.get.return_value = mock_response

        results = await scanner.scan(domain)

        # Should skip malformed entry, only parse valid one
        assert len(results) == 1
        assert results[0].cert_id == "2"

    @pytest.mark.asyncio
    async def test_close(self, scanner: CertificateScanner) -> None:
        """Test cleanup method."""
        await scanner.close()  # Should not raise
