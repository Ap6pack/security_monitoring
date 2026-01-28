"""Platform takeover detection patterns."""

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import yaml

from security_scanner.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class PlatformPattern:
    """Platform-specific takeover detection pattern."""

    name: str
    cname_patterns: list[str]
    http_patterns: list[str]
    dns_error: str
    severity: str
    description: str = ""
    remediation: str = ""


class PatternMatcher:
    """
    Pattern matcher for detecting potential subdomain takeovers.

    Loads platform patterns from YAML configuration and provides
    matching capabilities for CNAME targets and HTTP responses.
    """

    def __init__(self, patterns_file: Optional[Path] = None) -> None:
        """
        Initialize the pattern matcher.

        Args:
            patterns_file: Path to patterns YAML file (optional)
        """
        self.patterns: dict[str, PlatformPattern] = {}
        if patterns_file and patterns_file.exists():
            self._load_patterns(patterns_file)
        else:
            self._load_default_patterns()

    def _load_patterns(self, patterns_file: Path) -> None:
        """Load patterns from YAML file."""
        try:
            with open(patterns_file) as f:
                data = yaml.safe_load(f)

            platforms = data.get("platforms", {})
            for platform_id, config in platforms.items():
                self.patterns[platform_id] = PlatformPattern(
                    name=config.get("name", platform_id),
                    cname_patterns=config.get("cname_patterns", []),
                    http_patterns=config.get("http_patterns", []),
                    dns_error=config.get("dns_error", "NXDOMAIN"),
                    severity=config.get("severity", "HIGH"),
                    description=config.get("description", ""),
                    remediation=config.get("remediation", ""),
                )

            logger.info("Loaded takeover patterns", count=len(self.patterns))

        except Exception as e:
            logger.warning("Failed to load patterns file", error=str(e))
            self._load_default_patterns()

    def _load_default_patterns(self) -> None:
        """Load default platform patterns."""
        self.patterns = {
            "heroku": PlatformPattern(
                name="Heroku",
                cname_patterns=["*.herokuapp.com", "*.herokussl.com"],
                http_patterns=[
                    "No such app",
                    "There's nothing here, yet",
                    "herokucdn.com/error-pages/no-such-app.html",
                ],
                dns_error="NXDOMAIN",
                severity="HIGH",
                description="Heroku app not found or deleted",
                remediation="Verify the Heroku app exists or remove the CNAME record",
            ),
            "github_pages": PlatformPattern(
                name="GitHub Pages",
                cname_patterns=["*.github.io"],
                http_patterns=[
                    "There isn't a GitHub Pages site here",
                    "404 - File not found",
                    "For root URLs (like http://example.com/) you must provide an index.html",
                ],
                dns_error="NXDOMAIN",
                severity="HIGH",
                description="GitHub Pages site not found",
                remediation="Configure GitHub Pages or remove the CNAME record",
            ),
            "aws_s3": PlatformPattern(
                name="AWS S3",
                cname_patterns=[
                    "*.s3.amazonaws.com",
                    "*.s3-*.amazonaws.com",
                    "*.s3-website-*.amazonaws.com",
                ],
                http_patterns=[
                    "NoSuchBucket",
                    "The specified bucket does not exist",
                    "Code: NoSuchBucket",
                ],
                dns_error="NXDOMAIN",
                severity="HIGH",
                description="S3 bucket not found or deleted",
                remediation="Create the S3 bucket or remove the CNAME record",
            ),
            "aws_elastic_beanstalk": PlatformPattern(
                name="AWS Elastic Beanstalk",
                cname_patterns=[
                    "*.elasticbeanstalk.com",
                    "*.us-east-1.elasticbeanstalk.com",
                    "*.us-west-2.elasticbeanstalk.com",
                ],
                http_patterns=[
                    "Service not found",
                    "The specified service does not exist",
                ],
                dns_error="NXDOMAIN",
                severity="HIGH",
                description="Elastic Beanstalk environment not found",
                remediation="Create the environment or remove the CNAME record",
            ),
            "azure": PlatformPattern(
                name="Microsoft Azure",
                cname_patterns=[
                    "*.azurewebsites.net",
                    "*.cloudapp.net",
                    "*.cloudapp.azure.com",
                    "*.trafficmanager.net",
                ],
                http_patterns=[
                    "404 - Web app not found",
                    "Error 404 - Web app not found",
                    "The resource you are looking for has been removed",
                ],
                dns_error="NXDOMAIN",
                severity="HIGH",
                description="Azure service not found",
                remediation="Create the Azure resource or remove the CNAME record",
            ),
            "google_cloud": PlatformPattern(
                name="Google Cloud",
                cname_patterns=[
                    "*.appspot.com",
                    "*.cloudfunctions.net",
                    "*.run.app",
                ],
                http_patterns=[
                    "404. That's an error",
                    "The requested URL was not found on this server",
                ],
                dns_error="NXDOMAIN",
                severity="MEDIUM",
                description="Google Cloud service not found",
                remediation="Verify the service exists or remove the CNAME record",
            ),
            "netlify": PlatformPattern(
                name="Netlify",
                cname_patterns=["*.netlify.com", "*.netlify.app"],
                http_patterns=[
                    "Not Found - Request ID:",
                    "There isn't a Netlify site",
                ],
                dns_error="NXDOMAIN",
                severity="HIGH",
                description="Netlify site not found",
                remediation="Configure the Netlify site or remove the CNAME record",
            ),
            "vercel": PlatformPattern(
                name="Vercel",
                cname_patterns=["*.vercel.app", "*.now.sh"],
                http_patterns=[
                    "The deployment could not be found",
                    "404: NOT_FOUND",
                ],
                dns_error="NXDOMAIN",
                severity="HIGH",
                description="Vercel deployment not found",
                remediation="Deploy to Vercel or remove the CNAME record",
            ),
        }

        logger.info("Loaded default takeover patterns", count=len(self.patterns))

    def match_cname(self, cname_target: str) -> Optional[PlatformPattern]:
        """
        Match a CNAME target against known platform patterns.

        Args:
            cname_target: CNAME target to match

        Returns:
            Matching platform pattern if found
        """
        cname_target = cname_target.lower()

        for pattern in self.patterns.values():
            for cname_pattern in pattern.cname_patterns:
                # Simple wildcard matching
                if cname_pattern.startswith("*."):
                    suffix = cname_pattern[2:]
                    if cname_target.endswith(suffix):
                        return pattern
                elif cname_target == cname_pattern:
                    return pattern

        return None

    def match_http_response(
        self,
        response_text: str,
        platform_pattern: PlatformPattern,
    ) -> bool:
        """
        Check if HTTP response matches platform error patterns.

        Args:
            response_text: HTTP response text
            platform_pattern: Platform pattern to match against

        Returns:
            True if response matches any pattern
        """
        response_text = response_text.lower()

        for http_pattern in platform_pattern.http_patterns:
            if http_pattern.lower() in response_text:
                return True

        return False

    def get_all_patterns(self) -> list[PlatformPattern]:
        """Get all loaded patterns."""
        return list(self.patterns.values())
