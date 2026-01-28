"""Mock responses for external APIs used in testing."""

from datetime import datetime, timedelta, timezone
from typing import Any


# Mock crt.sh API responses
def get_mock_crtsh_response(domain: str = "example.com") -> list[dict[str, Any]]:
    """Get mock crt.sh API response."""
    now = datetime.now(timezone.utc)

    return [
        {
            "id": "123456789",
            "issuer_name": "Let's Encrypt Authority X3",
            "common_name": f"www.{domain}",
            "name_value": f"www.{domain}\n{domain}\napi.{domain}",
            "not_before": (now - timedelta(days=30)).isoformat() + "Z",
            "not_after": (now + timedelta(days=60)).isoformat() + "Z",
            "entry_timestamp": (now - timedelta(days=30)).isoformat() + "Z",
        },
        {
            "id": "987654321",
            "issuer_name": "DigiCert Inc",
            "common_name": f"mail.{domain}",
            "name_value": f"mail.{domain}",
            "not_before": (now - timedelta(days=60)).isoformat() + "Z",
            "not_after": (now + timedelta(days=30)).isoformat() + "Z",
            "entry_timestamp": (now - timedelta(days=60)).isoformat() + "Z",
        },
        {
            "id": "111222333",
            "issuer_name": "Let's Encrypt Authority X3",
            "common_name": f"*.{domain}",
            "name_value": f"*.{domain}",
            "not_before": (now - timedelta(days=90)).isoformat() + "Z",
            "not_after": (now + timedelta(days=90)).isoformat() + "Z",
            "entry_timestamp": (now - timedelta(days=90)).isoformat() + "Z",
        },
    ]


def get_mock_crtsh_expired_cert(domain: str = "example.com") -> list[dict[str, Any]]:
    """Get mock crt.sh response with expired certificate."""
    now = datetime.now(timezone.utc)

    return [
        {
            "id": "444555666",
            "issuer_name": "Let's Encrypt Authority X3",
            "common_name": f"old.{domain}",
            "name_value": f"old.{domain}",
            "not_before": (now - timedelta(days=180)).isoformat() + "Z",
            "not_after": (now - timedelta(days=30)).isoformat() + "Z",
            "entry_timestamp": (now - timedelta(days=180)).isoformat() + "Z",
        },
    ]


def get_mock_crtsh_shared_cert(domain: str = "example.com") -> list[dict[str, Any]]:
    """Get mock crt.sh response with shared certificate."""
    now = datetime.now(timezone.utc)

    return [
        {
            "id": "777888999",
            "issuer_name": "Let's Encrypt Authority X3",
            "common_name": f"{domain}",
            "name_value": f"{domain}\napi.{domain}\nexternal.otherdomain.com\ntest.anotherdomain.com",
            "not_before": (now - timedelta(days=15)).isoformat() + "Z",
            "not_after": (now + timedelta(days=75)).isoformat() + "Z",
            "entry_timestamp": (now - timedelta(days=15)).isoformat() + "Z",
        },
    ]


# Mock DNS responses
class MockDNSAnswer:
    """Mock DNS answer object."""

    def __init__(self, values: list[str], ttl: int = 300):
        """Initialize mock DNS answer."""
        self.values = values
        self.rrset = type('obj', (object,), {'ttl': ttl})()

    def __iter__(self):
        """Iterate over values."""
        return iter(self.values)


class MockDNSRdata:
    """Mock DNS rdata for different record types."""

    def __init__(self, value: str, record_type: str):
        """Initialize mock rdata."""
        self.value = value
        self.record_type = record_type

        if record_type == "CNAME":
            self.target = type('obj', (object,), {'__str__': lambda: value + "."})()
        elif record_type == "MX":
            parts = value.split()
            self.preference = int(parts[0]) if len(parts) > 1 else 10
            self.exchange = type('obj', (object,), {'__str__': lambda: parts[1] + "." if len(parts) > 1 else "mail.example.com."})()

    def __str__(self):
        """String representation."""
        return self.value


def create_mock_dns_answer(record_type: str, values: list[str], ttl: int = 300) -> MockDNSAnswer:
    """Create mock DNS answer for testing."""
    rdata_objects = [MockDNSRdata(value, record_type) for value in values]
    return MockDNSAnswer(rdata_objects, ttl)


# Mock HTTP responses for platform detection
MOCK_HTTP_RESPONSES = {
    "heroku_takeover": "There's nothing here, yet.",
    "github_pages_takeover": "There isn't a GitHub Pages site here.",
    "aws_s3_takeover": "NoSuchBucket\nThe specified bucket does not exist",
    "azure_takeover": "404 - Web app not found",
    "netlify_takeover": "Not Found - Request ID:",
    "normal_website": "<html><head><title>Welcome</title></head><body>Normal website content</body></html>",
}


def get_mock_http_response(platform: str) -> str:
    """Get mock HTTP response for platform detection."""
    return MOCK_HTTP_RESPONSES.get(platform, MOCK_HTTP_RESPONSES["normal_website"])


# Mock subprocess outputs
MOCK_SUBFINDER_OUTPUT = """{"host":"www.example.com"}
{"host":"api.example.com"}
{"host":"mail.example.com"}
{"host":"dev.example.com"}
"""

MOCK_ASSETFINDER_OUTPUT = """www.example.com
api.example.com
admin.example.com
staging.example.com
"""


# Sample findings for testing
def create_sample_finding(
    scan_id: str = "test-scan-123",
    severity: str = "CRITICAL",
    finding_type: str = "dangling_cname",
    domain: str = "api.example.com",
) -> dict[str, Any]:
    """Create a sample finding for testing."""
    return {
        "scan_id": scan_id,
        "severity": severity,
        "type": finding_type,
        "domain": domain,
        "record_type": "CNAME",
        "target": "old-service.herokuapp.com",
        "description": f"Dangling CNAME detected for {domain}",
        "cvss_score": 9.1,
        "remediation": "Remove the CNAME record or reconfigure the service",
        "raw_data": {"cname_target": "old-service.herokuapp.com"},
        "confidence": 1.0,
    }
