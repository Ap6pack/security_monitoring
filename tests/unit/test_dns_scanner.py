"""Unit tests for DNS scanner."""

import asyncio
from unittest.mock import AsyncMock, patch

import dns.exception
import dns.resolver
import pytest

from security_scanner.scanner.dns import DNSScanner
from security_scanner.scanner.models import DNSResult
from security_scanner.storage.cache import DNSCache
from tests.fixtures.mock_responses import create_mock_dns_answer


class TestDNSScanner:
    """Test DNS scanner functionality."""

    @pytest.fixture
    def cache(self) -> DNSCache:
        """Create DNS cache instance."""
        return DNSCache(max_size=100, default_ttl=300)

    @pytest.fixture
    def scanner(self, cache: DNSCache) -> DNSScanner:
        """Create DNS scanner instance."""
        return DNSScanner(
            nameservers=["8.8.8.8", "1.1.1.1"],
            cache=cache,
            timeout=5,
            max_retries=3,
            max_concurrent=50,
        )

    @pytest.mark.asyncio
    async def test_resolve_a_record_success(self, scanner: DNSScanner) -> None:
        """Test successful A record resolution."""
        domain = "example.com"

        with patch.object(scanner._resolver, "resolve") as mock_resolve:
            mock_resolve.return_value = create_mock_dns_answer("A", ["93.184.216.34"])

            result = await scanner.resolve(domain, "A")

            assert result.domain == domain
            assert result.record_type == "A"
            assert "93.184.216.34" in result.values
            assert result.error is None
            assert result.ttl == 300

    @pytest.mark.asyncio
    async def test_resolve_aaaa_record(self, scanner: DNSScanner) -> None:
        """Test AAAA record resolution."""
        domain = "example.com"

        with patch.object(scanner._resolver, "resolve") as mock_resolve:
            mock_resolve.return_value = create_mock_dns_answer(
                "AAAA",
                ["2606:2800:220:1:248:1893:25c8:1946"]
            )

            result = await scanner.resolve(domain, "AAAA")

            assert result.record_type == "AAAA"
            assert "2606:2800:220:1:248:1893:25c8:1946" in result.values
            assert result.error is None

    @pytest.mark.asyncio
    async def test_resolve_cname_record(self, scanner: DNSScanner) -> None:
        """Test CNAME record resolution."""
        domain = "www.example.com"

        with patch.object(scanner._resolver, "resolve") as mock_resolve:
            mock_resolve.return_value = create_mock_dns_answer("CNAME", ["example.com"])

            result = await scanner.resolve(domain, "CNAME")

            assert result.record_type == "CNAME"
            assert "example.com" in result.values
            assert result.error is None

    @pytest.mark.asyncio
    async def test_resolve_mx_record(self, scanner: DNSScanner) -> None:
        """Test MX record resolution."""
        domain = "example.com"

        with patch.object(scanner._resolver, "resolve") as mock_resolve:
            mock_resolve.return_value = create_mock_dns_answer("MX", ["10 mail.example.com"])

            result = await scanner.resolve(domain, "MX")

            assert result.record_type == "MX"
            assert len(result.values) > 0
            assert "mail.example.com" in result.values[0]

    @pytest.mark.asyncio
    async def test_resolve_nxdomain(self, scanner: DNSScanner) -> None:
        """Test handling of NXDOMAIN errors."""
        domain = "nonexistent.example.com"

        with patch.object(scanner._resolver, "resolve") as mock_resolve:
            mock_resolve.side_effect = dns.resolver.NXDOMAIN()

            result = await scanner.resolve(domain, "A")

            assert result.domain == domain
            assert result.error == "NXDOMAIN"
            assert result.values == []

    @pytest.mark.asyncio
    async def test_resolve_no_answer(self, scanner: DNSScanner) -> None:
        """Test handling of NoAnswer errors."""
        domain = "example.com"

        with patch.object(scanner._resolver, "resolve") as mock_resolve:
            mock_resolve.side_effect = dns.resolver.NoAnswer()

            result = await scanner.resolve(domain, "MX")

            assert result.error == "NoAnswer"
            assert result.values == []

    @pytest.mark.asyncio
    async def test_resolve_timeout(self, scanner: DNSScanner) -> None:
        """Test handling of DNS timeout."""
        domain = "example.com"

        with patch.object(scanner._resolver, "resolve") as mock_resolve:
            mock_resolve.side_effect = dns.exception.Timeout()

            result = await scanner.resolve(domain, "A")

            # After retries, should return error result
            assert result.domain == domain
            assert result.error is not None
            assert result.values == []

    @pytest.mark.asyncio
    async def test_resolve_with_retries(self, scanner: DNSScanner) -> None:
        """Test retry logic on transient failures."""
        domain = "example.com"

        with patch.object(scanner._resolver, "resolve") as mock_resolve:
            # Fail twice, succeed on third attempt
            mock_resolve.side_effect = [
                dns.exception.Timeout(),
                dns.exception.Timeout(),
                create_mock_dns_answer("A", ["93.184.216.34"]),
            ]

            result = await scanner.resolve(domain, "A")

            assert result.error is None
            assert "93.184.216.34" in result.values
            assert mock_resolve.call_count == 3

    @pytest.mark.asyncio
    async def test_resolve_cache_hit(self, scanner: DNSScanner, cache: DNSCache) -> None:
        """Test that cached results are returned."""
        domain = "example.com"
        cached_result = DNSResult(
            domain=domain,
            record_type="A",
            values=["93.184.216.34"],
            ttl=300,
            nameserver="8.8.8.8",
        )

        # Populate cache
        cache.set(domain, "A", cached_result, ttl=300)

        with patch.object(scanner._resolver, "resolve") as mock_resolve:
            result = await scanner.resolve(domain, "A", use_cache=True)

            assert result.domain == domain
            assert "93.184.216.34" in result.values
            # Should not have called resolver (cache hit)
            mock_resolve.assert_not_called()

    @pytest.mark.asyncio
    async def test_resolve_cache_miss(self, scanner: DNSScanner) -> None:
        """Test behavior on cache miss."""
        domain = "example.com"

        with patch.object(scanner._resolver, "resolve") as mock_resolve:
            mock_resolve.return_value = create_mock_dns_answer("A", ["93.184.216.34"])

            result = await scanner.resolve(domain, "A", use_cache=True)

            assert result.error is None
            # Should have called resolver (cache miss)
            mock_resolve.assert_called_once()

    @pytest.mark.asyncio
    async def test_resolve_no_cache(self, scanner: DNSScanner, cache: DNSCache) -> None:
        """Test that cache can be bypassed."""
        domain = "example.com"

        # Populate cache
        cached_result = DNSResult(
            domain=domain,
            record_type="A",
            values=["1.2.3.4"],
            ttl=300,
            nameserver="8.8.8.8",
        )
        cache.set(domain, "A", cached_result, ttl=300)

        with patch.object(scanner._resolver, "resolve") as mock_resolve:
            mock_resolve.return_value = create_mock_dns_answer("A", ["93.184.216.34"])

            result = await scanner.resolve(domain, "A", use_cache=False)

            # Should get new result, not cached
            assert "93.184.216.34" in result.values
            assert "1.2.3.4" not in result.values
            mock_resolve.assert_called_once()

    @pytest.mark.asyncio
    async def test_scan_all_record_types(self, scanner: DNSScanner) -> None:
        """Test scanning all record types for a domain."""
        domain = "example.com"

        with patch.object(scanner._resolver, "resolve") as mock_resolve:
            mock_resolve.side_effect = [
                create_mock_dns_answer("A", ["93.184.216.34"]),
                create_mock_dns_answer("AAAA", ["2606:2800:220:1:248:1893:25c8:1946"]),
                create_mock_dns_answer("CNAME", ["cdn.example.com"]),
                create_mock_dns_answer("MX", ["10 mail.example.com"]),
            ]

            results = await scanner.scan(domain)

            assert len(results) == 4
            record_types = {r.record_type for r in results}
            assert record_types == {"A", "AAAA", "CNAME", "MX"}

    @pytest.mark.asyncio
    async def test_check_dangling_cname_true(self, scanner: DNSScanner) -> None:
        """Test detection of dangling CNAME."""
        domain = "api.example.com"

        with patch.object(scanner, "resolve") as mock_resolve:
            # First call: CNAME exists
            mock_resolve.side_effect = [
                DNSResult(
                    domain=domain,
                    record_type="CNAME",
                    values=["old-service.herokuapp.com"],
                    ttl=300,
                    nameserver="8.8.8.8",
                ),
                # Second call: Target doesn't resolve
                DNSResult(
                    domain="old-service.herokuapp.com",
                    record_type="A",
                    values=[],
                    ttl=0,
                    nameserver="8.8.8.8",
                    error="NXDOMAIN",
                ),
            ]

            is_dangling, target = await scanner.check_dangling_cname(domain)

            assert is_dangling is True
            assert target == "old-service.herokuapp.com"

    @pytest.mark.asyncio
    async def test_check_dangling_cname_false(self, scanner: DNSScanner) -> None:
        """Test non-dangling CNAME."""
        domain = "www.example.com"

        with patch.object(scanner, "resolve") as mock_resolve:
            # First call: CNAME exists
            mock_resolve.side_effect = [
                DNSResult(
                    domain=domain,
                    record_type="CNAME",
                    values=["cdn.example.com"],
                    ttl=300,
                    nameserver="8.8.8.8",
                ),
                # Second call: Target resolves successfully
                DNSResult(
                    domain="cdn.example.com",
                    record_type="A",
                    values=["1.2.3.4"],
                    ttl=300,
                    nameserver="8.8.8.8",
                ),
            ]

            is_dangling, target = await scanner.check_dangling_cname(domain)

            assert is_dangling is False
            assert target == "cdn.example.com"

    @pytest.mark.asyncio
    async def test_check_dangling_cname_no_cname(self, scanner: DNSScanner) -> None:
        """Test check on domain without CNAME."""
        domain = "example.com"

        with patch.object(scanner, "resolve") as mock_resolve:
            # No CNAME record
            mock_resolve.return_value = DNSResult(
                domain=domain,
                record_type="CNAME",
                values=[],
                ttl=0,
                nameserver="8.8.8.8",
                error="NoAnswer",
            )

            is_dangling, target = await scanner.check_dangling_cname(domain)

            assert is_dangling is False
            assert target is None

    @pytest.mark.asyncio
    async def test_resolve_with_all_nameservers(self, scanner: DNSScanner) -> None:
        """Test resolving with all nameservers."""
        domain = "example.com"

        with patch("dns.asyncresolver.Resolver") as mock_resolver_class:
            mock_resolver1 = AsyncMock()
            mock_resolver1.resolve = AsyncMock(return_value=create_mock_dns_answer("A", ["93.184.216.34"]))

            mock_resolver2 = AsyncMock()
            mock_resolver2.resolve = AsyncMock(return_value=create_mock_dns_answer("A", ["93.184.216.35"]))

            mock_resolver_class.side_effect = [mock_resolver1, mock_resolver2]

            results = await scanner.resolve_with_all_nameservers(domain, "A")

            assert len(results) == 2
            assert "8.8.8.8" in results
            assert "1.1.1.1" in results

    @pytest.mark.asyncio
    async def test_concurrency_control(self, scanner: DNSScanner) -> None:
        """Test that semaphore limits concurrent queries."""
        domains = [f"test{i}.example.com" for i in range(100)]

        with patch.object(scanner._resolver, "resolve") as mock_resolve:
            mock_resolve.return_value = create_mock_dns_answer("A", ["1.2.3.4"])

            # Run many queries concurrently
            tasks = [scanner.resolve(domain, "A") for domain in domains]
            results = await asyncio.gather(*tasks)

            assert len(results) == 100
            assert all(r.error is None for r in results)

    @pytest.mark.asyncio
    async def test_close(self, scanner: DNSScanner) -> None:
        """Test cleanup method."""
        await scanner.close()  # Should not raise

