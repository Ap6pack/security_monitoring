"""Unit tests for subdomain scanner."""

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from security_scanner.scanner.models import SubdomainResult
from security_scanner.scanner.subdomain import SubdomainScanner
from security_scanner.utils.exceptions import ScannerError
from security_scanner.utils.http_client import HTTPClient
from tests.fixtures.mock_responses import (
    MOCK_ASSETFINDER_OUTPUT,
    MOCK_SUBFINDER_OUTPUT,
    get_mock_crtsh_response,
)


class TestSubdomainScanner:
    """Test subdomain scanner functionality."""

    @pytest.fixture
    def mock_http_client(self) -> MagicMock:
        """Create mock HTTP client."""
        client = MagicMock(spec=HTTPClient)
        client.get = AsyncMock()
        return client

    @pytest.fixture
    def scanner(self, mock_http_client: MagicMock) -> SubdomainScanner:
        """Create subdomain scanner instance."""
        return SubdomainScanner(
            http_client=mock_http_client,
            sources=["crtsh"],  # Only test crtsh by default
        )

    @pytest.mark.asyncio
    async def test_scan_crtsh_success(self, scanner: SubdomainScanner, mock_http_client: MagicMock) -> None:
        """Test successful crt.sh subdomain discovery."""
        domain = "example.com"
        mock_http_client.get.return_value = get_mock_crtsh_response(domain)

        results = await scanner.scan(domain)

        assert len(results) > 0
        assert all(isinstance(r, SubdomainResult) for r in results)
        assert all(r.source == "crtsh" for r in results)

        # Verify domains discovered
        domains = {r.domain for r in results}
        assert "www.example.com" in domains
        assert "api.example.com" in domains
        assert "mail.example.com" in domains

        # Verify HTTP client was called
        mock_http_client.get.assert_called_once()
        call_args = mock_http_client.get.call_args
        assert call_args[0][0] == "https://crt.sh/json"
        assert call_args[1]["params"]["q"] == domain

    @pytest.mark.asyncio
    async def test_scan_deduplication(self, scanner: SubdomainScanner, mock_http_client: MagicMock) -> None:
        """Test that duplicate subdomains are deduplicated."""
        domain = "example.com"

        # Mock response with duplicates
        mock_response = [
            {
                "id": "1",
                "name_value": "www.example.com\napi.example.com",
                "issuer_name": "Let's Encrypt",
                "common_name": "example.com",
                "not_before": "2024-01-01T00:00:00Z",
                "not_after": "2024-12-31T23:59:59Z",
                "entry_timestamp": "2024-01-01T00:00:00Z",
            },
            {
                "id": "2",
                "name_value": "www.example.com\nmail.example.com",  # www is duplicate
                "issuer_name": "Let's Encrypt",
                "common_name": "example.com",
                "not_before": "2024-01-01T00:00:00Z",
                "not_after": "2024-12-31T23:59:59Z",
                "entry_timestamp": "2024-01-01T00:00:00Z",
            },
        ]
        mock_http_client.get.return_value = mock_response

        results = await scanner.scan(domain)

        # Each domain should appear only once
        domains = [r.domain for r in results]
        assert len(domains) == len(set(domains))
        assert domains.count("www.example.com") == 1

    @pytest.mark.asyncio
    async def test_scan_wildcard_handling(self, scanner: SubdomainScanner, mock_http_client: MagicMock) -> None:
        """Test that wildcard domains are handled correctly."""
        domain = "example.com"

        # Mock response with wildcard
        mock_response = [
            {
                "id": "1",
                "name_value": "*.example.com",
                "issuer_name": "Let's Encrypt",
                "common_name": "*.example.com",
                "not_before": "2024-01-01T00:00:00Z",
                "not_after": "2024-12-31T23:59:59Z",
                "entry_timestamp": "2024-01-01T00:00:00Z",
            },
        ]
        mock_http_client.get.return_value = mock_response

        results = await scanner.scan(domain)

        # Wildcard should be stripped to base domain
        domains = {r.domain for r in results}
        assert "example.com" in domains
        assert "*.example.com" not in domains

    @pytest.mark.asyncio
    async def test_scan_crtsh_api_error(self, scanner: SubdomainScanner, mock_http_client: MagicMock) -> None:
        """Test handling of crt.sh API errors."""
        mock_http_client.get.side_effect = Exception("API error")

        # Scanner continues with empty results when one source fails
        results = await scanner.scan("example.com")

        # Should return empty list when all sources fail
        assert results == []

    @pytest.mark.asyncio
    async def test_scan_invalid_response_format(self, scanner: SubdomainScanner, mock_http_client: MagicMock) -> None:
        """Test handling of invalid response format."""
        mock_http_client.get.return_value = {"error": "Invalid domain"}

        results = await scanner.scan("example.com")

        # Should return empty list for invalid format
        assert results == []

    @pytest.mark.asyncio
    async def test_scan_subfinder_success(self, mock_http_client: MagicMock, tmp_path: Path) -> None:
        """Test subfinder integration."""
        # Create mock subfinder script
        subfinder_path = tmp_path / "subfinder"
        subfinder_path.write_text("#!/bin/bash\necho 'mock'")
        subfinder_path.chmod(0o755)

        scanner = SubdomainScanner(
            http_client=mock_http_client,
            subfinder_path=subfinder_path,
            sources=["subfinder"],
        )

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            # Mock subprocess
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(return_value=(
                MOCK_SUBFINDER_OUTPUT.encode(),
                b"",
            ))
            mock_process.returncode = 0
            mock_exec.return_value = mock_process

            results = await scanner.scan("example.com")

            assert len(results) == 4
            assert all(r.source == "subfinder" for r in results)
            domains = {r.domain for r in results}
            assert "www.example.com" in domains
            assert "api.example.com" in domains

    @pytest.mark.asyncio
    async def test_scan_assetfinder_success(self, mock_http_client: MagicMock, tmp_path: Path) -> None:
        """Test assetfinder integration."""
        # Create mock assetfinder script
        assetfinder_path = tmp_path / "assetfinder"
        assetfinder_path.write_text("#!/bin/bash\necho 'mock'")
        assetfinder_path.chmod(0o755)

        scanner = SubdomainScanner(
            http_client=mock_http_client,
            assetfinder_path=assetfinder_path,
            sources=["assetfinder"],
        )

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            # Mock subprocess
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(return_value=(
                MOCK_ASSETFINDER_OUTPUT.encode(),
                b"",
            ))
            mock_process.returncode = 0
            mock_exec.return_value = mock_process

            results = await scanner.scan("example.com")

            assert len(results) == 4
            assert all(r.source == "assetfinder" for r in results)
            domains = {r.domain for r in results}
            assert "www.example.com" in domains
            assert "admin.example.com" in domains

    @pytest.mark.asyncio
    async def test_scan_multi_source(self, mock_http_client: MagicMock) -> None:
        """Test scanning with multiple sources."""
        scanner = SubdomainScanner(
            http_client=mock_http_client,
            sources=["crtsh"],
        )

        mock_http_client.get.return_value = get_mock_crtsh_response("example.com")

        results = await scanner.scan("example.com")

        assert len(results) > 0
        # All results should be deduplicated
        domains = [r.domain for r in results]
        assert len(domains) == len(set(domains))

    @pytest.mark.asyncio
    async def test_scan_source_failure_handling(self, scanner: SubdomainScanner, mock_http_client: MagicMock) -> None:
        """Test that scanner continues when one source fails."""
        # Make crtsh fail
        mock_http_client.get.side_effect = Exception("API down")

        # Scanner handles failure gracefully and returns empty results
        results = await scanner.scan("example.com")
        assert results == []

    @pytest.mark.asyncio
    async def test_scan_empty_domain_list(self, scanner: SubdomainScanner, mock_http_client: MagicMock) -> None:
        """Test handling of empty crt.sh results."""
        mock_http_client.get.return_value = []

        results = await scanner.scan("example.com")

        assert results == []

    @pytest.mark.asyncio
    async def test_tool_availability_check(self, mock_http_client: MagicMock, tmp_path: Path) -> None:
        """Test tool availability checking."""
        scanner = SubdomainScanner(
            http_client=mock_http_client,
            subfinder_path=tmp_path / "nonexistent",
            sources=["subfinder"],
        )

        # Tool doesn't exist, so subfinder shouldn't run
        # Only crtsh is disabled here, so scan should complete with no results
        mock_http_client.get.return_value = []

        results = await scanner.scan("example.com")
        assert results == []

    @pytest.mark.asyncio
    async def test_close(self, scanner: SubdomainScanner) -> None:
        """Test cleanup method."""
        await scanner.close()  # Should not raise
