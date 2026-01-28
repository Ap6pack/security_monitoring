"""Main scan orchestration logic."""

import asyncio
from datetime import datetime, timezone
from typing import Any

from security_scanner.config import Settings
from security_scanner.detectors.dangling_dns import DanglingDNSDetector
from security_scanner.detectors.patterns import PatternMatcher
from security_scanner.detectors.takeover import TakeoverDetector
from security_scanner.scanner.certificate import CertificateScanner
from security_scanner.scanner.dns import DNSScanner
from security_scanner.scanner.subdomain import SubdomainScanner
from security_scanner.storage.cache import DNSCache
from security_scanner.storage.database import DatabaseManager
from security_scanner.storage.models import Scan
from security_scanner.utils.http_client import HTTPClient
from security_scanner.utils.logger import get_logger
from security_scanner.utils.validators import normalize_domain

logger = get_logger(__name__)


class ScanOrchestrator:
    """
    Main orchestrator for security scans.

    Coordinates:
    - Subdomain discovery
    - DNS resolution
    - Certificate transparency analysis
    - Vulnerability detection
    - Result storage
    - Report generation
    """

    def __init__(self, settings: Settings, db: DatabaseManager) -> None:
        """
        Initialize the orchestrator.

        Args:
            settings: Application settings
            db: Database manager
        """
        self.settings = settings
        self.db = db

        # Initialize components
        self.http_client = HTTPClient(
            timeout=settings.http_timeout,
            max_retries=settings.http_max_retries,
            max_connections=settings.http_max_connections,
            rate_limit=settings.rate_limit_requests_per_second,
            rate_burst=settings.rate_limit_burst,
            user_agent=settings.http_user_agent,
        )

        self.dns_cache = (
            DNSCache(
                max_size=settings.cache_max_size,
                default_ttl=settings.cache_ttl,
            )
            if settings.enable_cache
            else None
        )

        self.dns_scanner = DNSScanner(
            nameservers=settings.dns_nameservers,
            cache=self.dns_cache,
            timeout=settings.dns_timeout,
            max_retries=settings.dns_max_retries,
            max_concurrent=settings.max_concurrent_scans,
        )

        self.subdomain_scanner = SubdomainScanner(
            http_client=self.http_client,
            subfinder_path=settings.subfinder_path,
            assetfinder_path=settings.assetfinder_path,
            sources=settings.subdomain_sources,
        )

        self.certificate_scanner = CertificateScanner(
            http_client=self.http_client,
        )

        # Initialize detectors
        self.pattern_matcher = PatternMatcher()
        self.dangling_detector = DanglingDNSDetector(self.dns_scanner)
        self.takeover_detector = TakeoverDetector(
            dns_scanner=self.dns_scanner,
            http_client=self.http_client,
            pattern_matcher=self.pattern_matcher,
        )

    async def __aenter__(self) -> "ScanOrchestrator":
        """Async context manager entry."""
        return self

    async def __aexit__(self, *args: Any) -> None:
        """Async context manager exit."""
        await self.cleanup()

    async def cleanup(self) -> None:
        """Cleanup resources."""
        await self.http_client.close()

    async def scan(self, domains: list[str]) -> dict[str, Any]:
        """
        Execute a comprehensive security scan.

        Args:
            domains: List of domains to scan

        Returns:
            Dictionary with scan results
        """
        # Normalize domains
        domains = [normalize_domain(d) for d in domains]

        # Create scan record
        scan = Scan(
            domains_scanned=domains,
            status="running",
        )
        await self.db.create_scan(scan)

        logger.info("Starting security scan", scan_id=scan.id, domains=domains)

        all_findings = []

        try:
            for domain in domains:
                domain_findings = await self._scan_domain(domain, scan.id)
                all_findings.extend(domain_findings)

            # Update scan record
            findings_by_severity = self._count_findings_by_severity(all_findings)
            await self.db.update_scan(
                scan_id=scan.id,
                end_time=datetime.now(timezone.utc),
                status="completed",
                findings_count=findings_by_severity,
            )

            logger.info(
                "Scan completed",
                scan_id=scan.id,
                total_findings=len(all_findings),
                findings_by_severity=findings_by_severity,
            )

            return {
                "scan_id": scan.id,
                "domains": domains,
                "findings": all_findings,
                "summary": findings_by_severity,
            }

        except Exception as e:
            logger.error("Scan failed", scan_id=scan.id, error=str(e))
            await self.db.update_scan(
                scan_id=scan.id,
                end_time=datetime.now(timezone.utc),
                status="failed",
                findings_count={},
            )
            raise

    async def _scan_domain(self, domain: str, scan_id: str) -> list[Any]:
        """Scan a single domain."""
        logger.info("Scanning domain", domain=domain)

        findings = []

        # 1. Discover subdomains
        logger.info("Discovering subdomains", domain=domain)
        subdomains_result = await self.subdomain_scanner.scan(domain)
        all_domains = [domain] + [s.domain for s in subdomains_result]

        logger.info(
            "Subdomain discovery complete",
            domain=domain,
            count=len(all_domains),
        )

        # 2. Resolve DNS for all domains
        logger.info("Resolving DNS records", domain=domain, count=len(all_domains))
        dns_tasks = [self.dns_scanner.scan(d) for d in all_domains]
        dns_results_list = await asyncio.gather(*dns_tasks, return_exceptions=True)

        # 3. Run detectors on each domain
        for i, subdomain in enumerate(all_domains):
            if isinstance(dns_results_list[i], Exception):
                logger.warning(
                    "DNS scan failed for subdomain",
                    subdomain=subdomain,
                    error=str(dns_results_list[i]),
                )
                continue

            dns_records = dns_results_list[i]

            # Run dangling DNS detector
            dangling_findings = await self.dangling_detector.detect(
                {
                    "domain": subdomain,
                    "dns_records": dns_records,
                    "scan_id": scan_id,
                }
            )
            findings.extend(dangling_findings)

            # Run takeover detector
            takeover_findings = await self.takeover_detector.detect(
                {
                    "domain": subdomain,
                    "dns_records": dns_records,
                    "scan_id": scan_id,
                }
            )
            findings.extend(takeover_findings)

        # 4. Store findings in database
        for finding in findings:
            await self.db.create_finding(finding)

        logger.info(
            "Domain scan complete",
            domain=domain,
            findings_count=len(findings),
        )

        return findings

    def _count_findings_by_severity(self, findings: list[Any]) -> dict[str, int]:
        """Count findings by severity level."""
        counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
        }

        for finding in findings:
            severity = finding.severity
            if severity in counts:
                counts[severity] += 1

        return counts
