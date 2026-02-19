"""Certificate transparency scanner."""

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from security_scanner.scanner.models import CertificateResult
from security_scanner.utils.exceptions import ScannerError
from security_scanner.utils.http_client import HTTPClient
from security_scanner.utils.logger import get_logger
from security_scanner.utils.validators import normalize_domain

logger = get_logger(__name__)


class CertificateScanner:
    """
    Certificate Transparency log scanner.

    Queries CT logs to discover certificates and identify:
    - Shared certificates (multi-domain SANs)
    - Expired certificates
    - Recently issued certificates
    - Wildcard certificates
    """

    def __init__(
        self,
        http_client: HTTPClient,
        json_file: Path | None = None,
    ) -> None:
        """
        Initialize the certificate scanner.

        Args:
            http_client: HTTP client for API requests
            json_file: Optional path to pre-downloaded crt.sh JSON file (fallback for rate limiting)
        """
        self.http_client = http_client
        self.json_file = json_file

    async def scan(self, domain: str) -> list[CertificateResult]:
        """
        Scan certificate transparency logs for a domain.

        Args:
            domain: Domain to scan

        Returns:
            List of certificate results
        """
        domain = normalize_domain(domain)
        logger.info("Starting certificate transparency scan", domain=domain)

        # Try to load from file first if provided
        if self.json_file and self.json_file.exists():
            try:
                logger.info("Loading certificate data from file", file=str(self.json_file))
                with open(self.json_file, encoding="utf-8") as f:
                    data = json.load(f)

                if not isinstance(data, list):
                    logger.warning("Invalid JSON file format", file=str(self.json_file))
                else:
                    certificates = self._parse_certificates(data, domain)
                    logger.info(
                        "Certificate scan complete (from file)",
                        domain=domain,
                        count=len(certificates),
                    )
                    return certificates
            except Exception as e:
                logger.warning(
                    "Failed to load certificate file, falling back to API",
                    error=str(e),
                )

        # Fall back to API request
        # Add delay to respect rate limits
        await asyncio.sleep(1.5)

        url = "https://crt.sh/json"
        params = {"q": domain}

        try:
            data = await self.http_client.get(url, params=params)

            if not isinstance(data, list):  # type: ignore[unreachable]
                logger.warning("Unexpected crt.sh response format", domain=domain)
                return []

            certificates = self._parse_certificates(data, domain)  # type: ignore[unreachable]

            logger.info(
                "Certificate scan complete",
                domain=domain,
                count=len(certificates),
            )

            return certificates

        except Exception as e:
            logger.error("Certificate scan failed", domain=domain, error=str(e))
            raise ScannerError(f"Certificate scan failed: {e}") from e

    def _parse_certificates(
        self,
        data: list[dict[str, Any]],
        _target_domain: str,
    ) -> list[CertificateResult]:
        """
        Parse certificate data from crt.sh.

        Args:
            data: Raw data from crt.sh
            target_domain: Target domain being scanned

        Returns:
            List of parsed certificate results
        """
        certificates: dict[str, CertificateResult] = {}
        now = datetime.now(UTC)

        for entry in data:
            try:
                cert_id = str(entry.get("id", ""))
                if not cert_id or cert_id in certificates:
                    continue

                # Parse dates
                not_before = entry.get("not_before")
                not_after = entry.get("not_after")

                if not_before:
                    not_before = datetime.fromisoformat(not_before.replace("Z", "+00:00"))
                else:
                    not_before = now

                if not_after:
                    not_after = datetime.fromisoformat(not_after.replace("Z", "+00:00"))
                else:
                    not_after = now

                # Parse SANs
                name_value = entry.get("name_value", "")
                san_domains = [
                    name.strip().lower() for name in name_value.split("\n") if name.strip()
                ]

                # Remove duplicates
                san_domains = list(set(san_domains))

                # Skip certificates with no domain names
                if not san_domains:
                    continue

                # Check for wildcards
                is_wildcard = any(name.startswith("*.") for name in san_domains)

                # Check if expired
                is_expired = not_after < now

                # Get common name
                common_name = entry.get("common_name", "")
                if not common_name and san_domains:
                    common_name = san_domains[0]

                # Get issuer
                issuer = entry.get("issuer_name", "Unknown")

                # Get logged timestamp
                entry_timestamp = entry.get("entry_timestamp")
                if entry_timestamp:
                    logged_at = datetime.fromisoformat(entry_timestamp.replace("Z", "+00:00"))
                else:
                    logged_at = now

                cert_result = CertificateResult(
                    cert_id=cert_id,
                    issuer=issuer,
                    not_before=not_before,
                    not_after=not_after,
                    common_name=common_name,
                    san_domains=san_domains,
                    is_wildcard=is_wildcard,
                    is_expired=is_expired,
                    logged_at=logged_at,
                )

                certificates[cert_id] = cert_result

            except Exception as e:
                logger.debug("Error parsing certificate entry", error=str(e))
                continue

        return list(certificates.values())

    def find_shared_certificates(
        self,
        certificates: list[CertificateResult],
        target_domain: str,
    ) -> list[CertificateResult]:
        """
        Find certificates that are shared across multiple domains.

        Args:
            certificates: List of certificates
            target_domain: Target domain

        Returns:
            List of shared certificates
        """
        shared = []

        for cert in certificates:
            # Check if certificate has multiple domains
            if len(cert.san_domains) > 1:
                # Check if it includes domains outside the target domain
                external_domains = [
                    domain for domain in cert.san_domains if not domain.endswith(target_domain)
                ]

                if external_domains:
                    shared.append(cert)

        return shared

    def find_recently_issued(
        self,
        certificates: list[CertificateResult],
        days: int = 30,
    ) -> list[CertificateResult]:
        """
        Find recently issued certificates.

        Args:
            certificates: List of certificates
            days: Number of days to consider as "recent"

        Returns:
            List of recently issued certificates
        """
        cutoff = datetime.now(UTC)
        from datetime import timedelta

        cutoff = cutoff - timedelta(days=days)

        recent = [cert for cert in certificates if cert.not_before >= cutoff]

        return recent

    def find_expiring_soon(
        self,
        certificates: list[CertificateResult],
        days: int = 30,
    ) -> list[CertificateResult]:
        """
        Find certificates expiring soon.

        Args:
            certificates: List of certificates
            days: Number of days to look ahead

        Returns:
            List of certificates expiring soon
        """
        cutoff = datetime.now(UTC)
        from datetime import timedelta

        cutoff = cutoff + timedelta(days=days)

        expiring = [
            cert for cert in certificates if not cert.is_expired and cert.not_after <= cutoff
        ]

        return expiring

    async def close(self) -> None:
        """Close resources (no resources to close for this scanner)."""
        pass
