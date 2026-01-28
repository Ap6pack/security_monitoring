"""Subdomain takeover detection with platform-specific patterns."""

from typing import Any, Optional

from security_scanner.detectors.patterns import PatternMatcher, PlatformPattern
from security_scanner.scanner.dns import DNSScanner
from security_scanner.scanner.models import DNSResult
from security_scanner.storage.models import Finding
from security_scanner.utils.http_client import HTTPClient
from security_scanner.utils.logger import get_logger

logger = get_logger(__name__)


class TakeoverDetector:
    """
    Detector for potential subdomain takeover vulnerabilities.

    Combines DNS analysis with platform-specific patterns to identify
    subdomains that may be vulnerable to takeover attacks.
    """

    def __init__(
        self,
        dns_scanner: DNSScanner,
        http_client: HTTPClient,
        pattern_matcher: Optional[PatternMatcher] = None,
    ) -> None:
        """
        Initialize the takeover detector.

        Args:
            dns_scanner: DNS scanner instance
            http_client: HTTP client for fetching pages
            pattern_matcher: Pattern matcher (creates default if not provided)
        """
        self.dns_scanner = dns_scanner
        self.http_client = http_client
        self.pattern_matcher = pattern_matcher or PatternMatcher()

    async def detect(self, data: dict[str, Any]) -> list[Finding]:
        """
        Detect potential subdomain takeover vulnerabilities.

        Args:
            data: Dictionary containing 'domain' and 'dns_records'

        Returns:
            List of findings
        """
        domain = data.get("domain", "")
        dns_records: list[DNSResult] = data.get("dns_records", [])
        scan_id = data.get("scan_id", "")

        if not domain or not dns_records:
            return []

        findings: list[Finding] = []

        # Check CNAME records for platform patterns
        cname_records = [r for r in dns_records if r.record_type == "CNAME" and r.values]

        for cname_record in cname_records:
            for cname_target in cname_record.values:
                finding = await self._check_platform_takeover(
                    cname_record.domain,
                    cname_target,
                    scan_id,
                )
                if finding:
                    findings.append(finding)

        return findings

    async def _check_platform_takeover(
        self,
        domain: str,
        cname_target: str,
        scan_id: str,
    ) -> Optional[Finding]:
        """
        Check if a CNAME target matches known vulnerable platforms.

        Args:
            domain: The subdomain
            cname_target: The CNAME target
            scan_id: Current scan ID

        Returns:
            Finding if vulnerability detected
        """
        # Match CNAME against platform patterns
        platform = self.pattern_matcher.match_cname(cname_target)
        if not platform:
            return None

        logger.debug(
            "Potential platform match",
            domain=domain,
            target=cname_target,
            platform=platform.name,
        )

        # Try to resolve the CNAME target
        try:
            target_result = await self.dns_scanner.resolve(cname_target, "A", use_cache=False)

            # If target doesn't resolve, check HTTP response
            if target_result.error == platform.dns_error:
                # Target doesn't resolve - try HTTP verification
                http_match = await self._verify_http_pattern(
                    domain,
                    platform,
                )

                if http_match:
                    # High confidence takeover vulnerability
                    return self._create_takeover_finding(
                        scan_id=scan_id,
                        domain=domain,
                        cname_target=cname_target,
                        platform=platform,
                        confidence=0.95,
                    )
                else:
                    # Medium confidence - DNS error matches but HTTP doesn't
                    return self._create_takeover_finding(
                        scan_id=scan_id,
                        domain=domain,
                        cname_target=cname_target,
                        platform=platform,
                        confidence=0.7,
                    )

        except Exception as e:
            logger.debug(
                "Error checking platform takeover",
                domain=domain,
                error=str(e),
            )

        return None

    async def _verify_http_pattern(
        self,
        domain: str,
        platform: PlatformPattern,
    ) -> bool:
        """
        Verify HTTP response matches platform error patterns.

        Args:
            domain: Domain to check
            platform: Platform pattern

        Returns:
            True if HTTP response matches platform patterns
        """
        try:
            # Try both HTTP and HTTPS
            for scheme in ["https", "http"]:
                try:
                    url = f"{scheme}://{domain}"
                    response_text = await self.http_client.fetch_text(
                        url,
                        rate_limit=True,
                    )

                    if self.pattern_matcher.match_http_response(response_text, platform):
                        logger.debug(
                            "HTTP pattern match",
                            domain=domain,
                            platform=platform.name,
                        )
                        return True

                except Exception:
                    continue

        except Exception as e:
            logger.debug("HTTP verification failed", domain=domain, error=str(e))

        return False

    def _create_takeover_finding(
        self,
        scan_id: str,
        domain: str,
        cname_target: str,
        platform: PlatformPattern,
        confidence: float,
    ) -> Finding:
        """Create a takeover finding."""
        severity = platform.severity
        cvss_score = self._calculate_cvss(severity)

        description = (
            f"Potential {platform.name} subdomain takeover detected. "
            f"{domain} points to {cname_target} which appears to be unclaimed. "
        )

        if platform.description:
            description += f"\n{platform.description}"

        remediation = platform.remediation or (
            "1. Verify if the service on the target platform still exists\n"
            "2. If not needed, remove the CNAME record immediately\n"
            "3. If needed, reconfigure the service on the target platform\n"
            "4. Monitor for unauthorized changes"
        )

        return Finding(
            scan_id=scan_id,
            severity=severity,
            type="subdomain_takeover",
            domain=domain,
            record_type="CNAME",
            target=cname_target,
            description=description,
            cvss_score=cvss_score,
            remediation=remediation,
            raw_data={
                "platform": platform.name,
                "cname_target": cname_target,
                "dns_error": platform.dns_error,
            },
            platform=platform.name,
            confidence=confidence,
        )

    def _calculate_cvss(self, severity: str) -> float:
        """Calculate CVSS score based on severity."""
        cvss_scores = {
            "CRITICAL": 9.1,  # CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N
            "HIGH": 7.5,  # CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N
            "MEDIUM": 5.3,  # CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N
            "LOW": 3.7,  # CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N
        }
        return cvss_scores.get(severity, 5.0)
