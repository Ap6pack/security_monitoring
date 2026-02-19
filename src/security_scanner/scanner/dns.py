"""DNS resolution scanner with async support."""

import asyncio

import dns.asyncresolver
import dns.exception
import dns.rdatatype
import dns.resolver

from security_scanner.scanner.models import DNSResult
from security_scanner.storage.cache import DNSCache
from security_scanner.utils.exceptions import DNSError
from security_scanner.utils.logger import get_logger
from security_scanner.utils.validators import normalize_domain

logger = get_logger(__name__)


class DNSScanner:
    """
    Async DNS resolution scanner with caching and multiple nameservers.

    Features:
    - Query multiple record types (A, AAAA, CNAME, MX)
    - Multiple nameserver support with fallback
    - TTL-aware caching
    - Concurrent resolution with semaphore
    - Retry with exponential backoff
    - Dangling DNS detection
    """

    def __init__(
        self,
        nameservers: list[str],
        cache: DNSCache | None = None,
        timeout: int = 5,
        max_retries: int = 3,
        max_concurrent: int = 50,
    ) -> None:
        """
        Initialize the DNS scanner.

        Args:
            nameservers: List of DNS nameservers to use
            cache: Optional DNS cache
            timeout: Query timeout in seconds
            max_retries: Maximum retry attempts
            max_concurrent: Maximum concurrent queries
        """
        self.nameservers = nameservers
        self.cache = cache or DNSCache()
        self.timeout = timeout
        self.max_retries = max_retries
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._resolver = dns.asyncresolver.Resolver()
        self._resolver.nameservers = nameservers
        self._resolver.timeout = timeout
        self._resolver.lifetime = timeout * max_retries

    async def scan(self, domain: str) -> list[DNSResult]:
        """
        Perform comprehensive DNS scan for a domain.

        Args:
            domain: Domain to scan

        Returns:
            List of DNS results for all record types
        """
        domain = normalize_domain(domain)
        logger.debug("Starting DNS scan", domain=domain)

        record_types = ["A", "AAAA", "CNAME", "MX"]
        tasks = [self.resolve(domain, record_type) for record_type in record_types]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        dns_results: list[DNSResult] = []
        for result in results:
            if isinstance(result, DNSResult):
                dns_results.append(result)
            elif isinstance(result, Exception):
                logger.debug("DNS query failed", error=str(result))

        logger.debug("DNS scan complete", domain=domain, count=len(dns_results))
        return dns_results

    async def resolve(
        self,
        domain: str,
        record_type: str = "A",
        use_cache: bool = True,
    ) -> DNSResult:
        """
        Resolve a specific DNS record type for a domain.

        Args:
            domain: Domain to resolve
            record_type: DNS record type (A, AAAA, CNAME, MX)
            use_cache: Whether to use cache

        Returns:
            DNS resolution result

        Raises:
            DNSError: If resolution fails after retries
        """
        domain = normalize_domain(domain)

        # Check cache first
        if use_cache and self.cache:
            cached = self.cache.get(domain, record_type)
            if cached is not None:
                logger.debug("DNS cache hit", domain=domain, record_type=record_type)
                return cached  # type: ignore[no-any-return]

        async with self._semaphore:
            for attempt in range(self.max_retries):
                try:
                    result = await self._query(domain, record_type)

                    # Cache successful result
                    if use_cache and self.cache and not result.error:
                        self.cache.set(domain, record_type, result, ttl=result.ttl)

                    return result

                except dns.exception.DNSException as e:
                    if attempt == self.max_retries - 1:
                        # Last attempt failed
                        error_msg = f"DNS resolution failed after {self.max_retries} attempts"
                        logger.warning(
                            error_msg,
                            domain=domain,
                            record_type=record_type,
                            error=str(e),
                        )
                        return DNSResult(
                            domain=domain,
                            record_type=record_type,
                            values=[],
                            ttl=0,
                            nameserver=self.nameservers[0],
                            error=str(e),
                        )

                    # Wait before retry
                    await asyncio.sleep(2**attempt)

        raise DNSError(
            "DNS resolution failed",
            domain=domain,
            query_type=record_type,
        )

    async def _query(self, domain: str, record_type: str) -> DNSResult:
        """
        Execute a DNS query.

        Args:
            domain: Domain to query
            record_type: Record type to query

        Returns:
            DNS result

        Raises:
            dns.exception.DNSException: If query fails
        """
        try:
            rdtype = dns.rdatatype.from_text(record_type)
            answer = await self._resolver.resolve(domain, rdtype)

            values = []
            for rdata in answer:
                if record_type in ("A", "AAAA"):
                    values.append(str(rdata))
                elif record_type == "CNAME":
                    values.append(str(rdata.target).rstrip("."))
                elif record_type == "MX":
                    values.append(f"{rdata.preference} {str(rdata.exchange).rstrip('.')}")
                else:
                    values.append(str(rdata))

            return DNSResult(
                domain=domain,
                record_type=record_type,
                values=values,
                ttl=int(answer.rrset.ttl) if hasattr(answer, "rrset") and answer.rrset else 300,
                nameserver=self.nameservers[0],
            )

        except dns.resolver.NXDOMAIN:
            # Domain doesn't exist
            return DNSResult(
                domain=domain,
                record_type=record_type,
                values=[],
                ttl=0,
                nameserver=self.nameservers[0],
                error="NXDOMAIN",
            )

        except dns.resolver.NoAnswer:
            # No records of this type
            return DNSResult(
                domain=domain,
                record_type=record_type,
                values=[],
                ttl=0,
                nameserver=self.nameservers[0],
                error="NoAnswer",
            )

        except dns.exception.Timeout:
            # Let timeout propagate to retry handler
            raise

    async def check_dangling_cname(self, domain: str) -> tuple[bool, str | None]:
        """
        Check if a domain has a dangling CNAME record.

        A CNAME is dangling if it points to a target that doesn't resolve.

        Args:
            domain: Domain to check

        Returns:
            Tuple of (is_dangling, cname_target)
        """
        domain = normalize_domain(domain)

        try:
            # Check for CNAME record
            cname_result = await self.resolve(domain, "CNAME")

            if cname_result.error or not cname_result.values:
                return False, None

            cname_target = cname_result.values[0]

            # Try to resolve the CNAME target
            try:
                target_result = await self.resolve(cname_target, "A")

                # If target doesn't resolve, CNAME is dangling
                if target_result.error == "NXDOMAIN":
                    logger.warning(
                        "Dangling CNAME detected",
                        domain=domain,
                        target=cname_target,
                    )
                    return True, cname_target

                return False, cname_target

            except Exception as e:
                logger.debug(
                    "Error resolving CNAME target",
                    domain=domain,
                    target=cname_target,
                    error=str(e),
                )
                # If we can't resolve the target, consider it potentially dangling
                return True, cname_target

        except Exception as e:
            logger.debug("Error checking dangling CNAME", domain=domain, error=str(e))
            return False, None

    async def resolve_with_all_nameservers(
        self,
        domain: str,
        record_type: str = "A",
    ) -> dict[str, DNSResult]:
        """
        Resolve a domain using all configured nameservers.

        Useful for detecting inconsistencies across nameservers.

        Args:
            domain: Domain to resolve
            record_type: DNS record type

        Returns:
            Dictionary mapping nameserver to result
        """
        tasks = []
        for nameserver in self.nameservers:
            resolver = dns.asyncresolver.Resolver()
            resolver.nameservers = [nameserver]
            resolver.timeout = self.timeout
            tasks.append(self._query_with_resolver(resolver, domain, record_type, nameserver))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        ns_results = {}
        for i, result in enumerate(results):
            nameserver = self.nameservers[i]
            if isinstance(result, DNSResult):
                ns_results[nameserver] = result
            elif isinstance(result, Exception):
                ns_results[nameserver] = DNSResult(
                    domain=domain,
                    record_type=record_type,
                    values=[],
                    ttl=0,
                    nameserver=nameserver,
                    error=str(result),
                )

        return ns_results

    async def _query_with_resolver(
        self,
        resolver: dns.asyncresolver.Resolver,
        domain: str,
        record_type: str,
        nameserver: str,
    ) -> DNSResult:
        """Query with a specific resolver."""
        try:
            rdtype = dns.rdatatype.from_text(record_type)
            answer = await resolver.resolve(domain, rdtype)

            values = []
            for rdata in answer:
                if record_type in ("A", "AAAA"):
                    values.append(str(rdata))
                elif record_type == "CNAME":
                    values.append(str(rdata.target).rstrip("."))
                elif record_type == "MX":
                    values.append(f"{rdata.preference} {str(rdata.exchange).rstrip('.')}")
                else:
                    values.append(str(rdata))

            return DNSResult(
                domain=domain,
                record_type=record_type,
                values=values,
                ttl=int(answer.rrset.ttl) if hasattr(answer, "rrset") and answer.rrset else 300,
                nameserver=nameserver,
            )

        except Exception as e:
            return DNSResult(
                domain=domain,
                record_type=record_type,
                values=[],
                ttl=0,
                nameserver=nameserver,
                error=str(e),
            )

    async def close(self) -> None:
        """Close resources."""
        pass
