"""Subdomain discovery scanner using multiple sources."""

import asyncio
import json
import subprocess
from pathlib import Path
from typing import Optional

from security_scanner.scanner.models import SubdomainResult
from security_scanner.utils.exceptions import ScannerError
from security_scanner.utils.http_client import HTTPClient
from security_scanner.utils.logger import get_logger
from security_scanner.utils.validators import is_valid_domain, normalize_domain

logger = get_logger(__name__)


class SubdomainScanner:
    """
    Multi-source subdomain discovery scanner.

    Sources:
    - Certificate Transparency (crt.sh API)
    - subfinder (if available)
    - assetfinder (if available)
    """

    def __init__(
        self,
        http_client: HTTPClient,
        subfinder_path: Optional[Path] = None,
        assetfinder_path: Optional[Path] = None,
        sources: Optional[list[str]] = None,
    ) -> None:
        """
        Initialize the subdomain scanner.

        Args:
            http_client: HTTP client for API requests
            subfinder_path: Path to subfinder binary
            assetfinder_path: Path to assetfinder binary
            sources: List of sources to use (default: all available)
        """
        self.http_client = http_client
        self.subfinder_path = subfinder_path
        self.assetfinder_path = assetfinder_path
        self.sources = sources or ["crtsh", "subfinder", "assetfinder"]

    async def scan(self, domain: str) -> list[SubdomainResult]:
        """
        Discover subdomains for a domain using multiple sources.

        Args:
            domain: Domain to scan

        Returns:
            List of discovered subdomains
        """
        domain = normalize_domain(domain)
        logger.info("Starting subdomain discovery", domain=domain, sources=self.sources)

        tasks = []

        if "crtsh" in self.sources:
            tasks.append(self._scan_crtsh(domain))

        if "subfinder" in self.sources and self._is_tool_available("subfinder"):
            tasks.append(self._scan_subfinder(domain))

        if "assetfinder" in self.sources and self._is_tool_available("assetfinder"):
            tasks.append(self._scan_assetfinder(domain))

        # Run all sources concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Combine and deduplicate results
        all_subdomains: set[str] = set()
        subdomain_results: list[SubdomainResult] = []

        for result in results:
            if isinstance(result, Exception):
                logger.warning("Subdomain source failed", error=str(result))
                continue

            for subdomain_result in result:  # type: ignore[union-attr]
                if subdomain_result.domain not in all_subdomains:
                    all_subdomains.add(subdomain_result.domain)
                    subdomain_results.append(subdomain_result)

        logger.info(
            "Subdomain discovery complete",
            domain=domain,
            count=len(subdomain_results),
        )

        return subdomain_results

    async def _scan_crtsh(self, domain: str) -> list[SubdomainResult]:
        """
        Query crt.sh Certificate Transparency logs.

        Args:
            domain: Domain to search

        Returns:
            List of subdomains from CT logs
        """
        logger.debug("Querying crt.sh", domain=domain)

        url = "https://crt.sh/json"
        params = {"q": domain}

        try:
            # Add delay to respect rate limits
            await asyncio.sleep(1.5)

            data = await self.http_client.get(url, params=params)

            if not isinstance(data, list):  # type: ignore[unreachable]
                return []

            subdomains: set[str] = set()  # type: ignore[unreachable]
            results: list[SubdomainResult] = []

            for entry in data:
                name_value = entry.get("name_value", "")
                if not name_value:
                    continue

                # CT logs can have multiple names separated by newlines
                names = name_value.split("\n")
                for name in names:
                    name = name.strip().lower()

                    # Skip wildcards for now
                    if name.startswith("*."):
                        name = name[2:]

                    # Validate domain
                    if is_valid_domain(name) and name not in subdomains:
                        subdomains.add(name)
                        results.append(
                            SubdomainResult(
                                domain=name,
                                source="crtsh",
                            )
                        )

            logger.debug("crt.sh query complete", domain=domain, count=len(results))
            return results

        except Exception as e:
            logger.error("crt.sh query failed", domain=domain, error=str(e))
            raise ScannerError(f"crt.sh query failed: {e}")

    async def _scan_subfinder(self, domain: str) -> list[SubdomainResult]:
        """
        Run subfinder subprocess for subdomain discovery.

        Args:
            domain: Domain to search

        Returns:
            List of subdomains from subfinder
        """
        if not self.subfinder_path or not self.subfinder_path.exists():
            logger.debug("subfinder not available")
            return []

        logger.debug("Running subfinder", domain=domain)

        try:
            # Run subfinder with JSON output
            process = await asyncio.create_subprocess_exec(
                str(self.subfinder_path),
                "-d",
                domain,
                "-json",
                "-silent",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=60)

            if process.returncode != 0:
                logger.warning(
                    "subfinder failed",
                    domain=domain,
                    stderr=stderr.decode(),
                )
                return []

            results: list[SubdomainResult] = []
            for line in stdout.decode().splitlines():
                if not line.strip():
                    continue

                try:
                    data = json.loads(line)
                    subdomain = data.get("host", "")
                    if subdomain and is_valid_domain(subdomain):
                        results.append(
                            SubdomainResult(
                                domain=subdomain.lower(),
                                source="subfinder",
                            )
                        )
                except json.JSONDecodeError:
                    continue

            logger.debug("subfinder complete", domain=domain, count=len(results))
            return results

        except asyncio.TimeoutError:
            logger.warning("subfinder timeout", domain=domain)
            return []
        except Exception as e:
            logger.error("subfinder failed", domain=domain, error=str(e))
            return []

    async def _scan_assetfinder(self, domain: str) -> list[SubdomainResult]:
        """
        Run assetfinder subprocess for subdomain discovery.

        Args:
            domain: Domain to search

        Returns:
            List of subdomains from assetfinder
        """
        if not self.assetfinder_path or not self.assetfinder_path.exists():
            logger.debug("assetfinder not available")
            return []

        logger.debug("Running assetfinder", domain=domain)

        try:
            # Run assetfinder
            process = await asyncio.create_subprocess_exec(
                str(self.assetfinder_path),
                "--subs-only",
                domain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=60)

            if process.returncode != 0:
                logger.warning(
                    "assetfinder failed",
                    domain=domain,
                    stderr=stderr.decode(),
                )
                return []

            results: list[SubdomainResult] = []
            for line in stdout.decode().splitlines():
                subdomain = line.strip().lower()
                if subdomain and is_valid_domain(subdomain):
                    results.append(
                        SubdomainResult(
                            domain=subdomain,
                            source="assetfinder",
                        )
                    )

            logger.debug("assetfinder complete", domain=domain, count=len(results))
            return results

        except asyncio.TimeoutError:
            logger.warning("assetfinder timeout", domain=domain)
            return []
        except Exception as e:
            logger.error("assetfinder failed", domain=domain, error=str(e))
            return []

    def _is_tool_available(self, tool: str) -> bool:
        """
        Check if a tool is available.

        Args:
            tool: Tool name

        Returns:
            True if tool is available
        """
        if tool == "subfinder":
            path = self.subfinder_path
        elif tool == "assetfinder":
            path = self.assetfinder_path
        else:
            return False

        if path and path.exists():
            return True

        # Check if it's in PATH
        try:
            subprocess.run(
                [tool, "--help"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            return True
        except FileNotFoundError:
            return False

    async def close(self) -> None:
        """Close resources (no resources to close for this scanner)."""
        pass
