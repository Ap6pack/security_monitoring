"""Dangling DNS detection logic."""

from typing import Any

from security_scanner.scanner.dns import DNSScanner
from security_scanner.scanner.models import DNSResult
from security_scanner.storage.models import Finding
from security_scanner.utils.logger import get_logger

logger = get_logger(__name__)


class DanglingDNSDetector:
    """
    Detector for dangling DNS records.

    A DNS record is considered "dangling" if:
    1. CNAME points to a non-existent target (NXDOMAIN)
    2. A/AAAA record points to unresponsive IP
    3. MX record points to non-existent mail server
    """

    def __init__(self, dns_scanner: DNSScanner) -> None:
        """
        Initialize the dangling DNS detector.

        Args:
            dns_scanner: DNS scanner instance
        """
        self.dns_scanner = dns_scanner

    async def detect(self, data: dict[str, Any]) -> list[Finding]:
        """
        Detect dangling DNS records.

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

        # Check for dangling CNAME records
        cname_findings = await self._check_dangling_cname(domain, dns_records, scan_id)
        findings.extend(cname_findings)

        # Check for unresponsive A/AAAA records
        ip_findings = self._check_unresponsive_ips(domain, dns_records, scan_id)
        findings.extend(ip_findings)

        return findings

    async def _check_dangling_cname(
        self,
        domain: str,
        dns_records: list[DNSResult],
        scan_id: str,
    ) -> list[Finding]:
        """Check for dangling CNAME records."""
        findings: list[Finding] = []

        # Find CNAME records
        cname_records = [r for r in dns_records if r.record_type == "CNAME" and r.values]

        for cname_record in cname_records:
            for cname_target in cname_record.values:
                # Check if the CNAME target resolves
                is_dangling, target = await self.dns_scanner.check_dangling_cname(
                    cname_record.domain
                )

                if is_dangling and target:
                    # Calculate CVSS score
                    # CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N = 9.1
                    cvss_score = 9.1

                    finding = Finding(
                        scan_id=scan_id,
                        severity="CRITICAL",
                        type="dangling_cname",
                        domain=cname_record.domain,
                        record_type="CNAME",
                        target=target,
                        description=(
                            f"Dangling CNAME record detected. "
                            f"{cname_record.domain} points to {target}, "
                            f"but the target does not resolve. This could allow "
                            f"subdomain takeover if an attacker registers the target."
                        ),
                        cvss_score=cvss_score,
                        remediation=(
                            "1. Verify if the CNAME target is still needed\n"
                            "2. If not needed, remove the CNAME record immediately\n"
                            "3. If needed, ensure the target service exists and is configured\n"
                            "4. Monitor for unauthorized changes to the target service"
                        ),
                        raw_data={
                            "cname_target": target,
                            "nameserver": cname_record.nameserver,
                            "ttl": cname_record.ttl,
                        },
                        confidence=1.0,
                    )

                    findings.append(finding)
                    logger.warning(
                        "Dangling CNAME detected",
                        domain=cname_record.domain,
                        target=target,
                    )

        return findings

    def _check_unresponsive_ips(
        self,
        domain: str,
        dns_records: list[DNSResult],
        scan_id: str,
    ) -> list[Finding]:
        """Check for A/AAAA records pointing to potentially unresponsive IPs."""
        findings: list[Finding] = []

        # Find A/AAAA records with errors
        ip_records = [
            r for r in dns_records if r.record_type in ("A", "AAAA") and r.error and not r.values
        ]

        for ip_record in ip_records:
            if ip_record.error == "NXDOMAIN":
                # Domain doesn't exist at all
                finding = Finding(
                    scan_id=scan_id,
                    severity="MEDIUM",
                    type="nxdomain",
                    domain=ip_record.domain,
                    record_type=ip_record.record_type,
                    target=None,
                    description=(
                        f"Domain {ip_record.domain} does not exist (NXDOMAIN). "
                        f"This could indicate a misconfiguration or a deleted service."
                    ),
                    cvss_score=5.3,  # CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N
                    remediation=(
                        "1. Verify if this domain should exist\n"
                        "2. If not needed, remove any references to it\n"
                        "3. If needed, create the appropriate DNS records"
                    ),
                    raw_data={
                        "error": ip_record.error,
                        "nameserver": ip_record.nameserver,
                    },
                    confidence=0.8,
                )

                findings.append(finding)

        return findings
