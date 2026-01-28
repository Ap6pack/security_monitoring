"""Unit tests for validators."""

import pytest

from security_scanner.utils.validators import (
    extract_root_domain,
    is_valid_domain,
    normalize_domain,
    validate_email,
    validate_ipv4,
)


class TestDomainValidation:
    """Test domain validation functions."""

    def test_valid_domains(self) -> None:
        """Test valid domain names."""
        assert is_valid_domain("example.com")
        assert is_valid_domain("sub.example.com")
        assert is_valid_domain("api.v2.example.com")
        assert is_valid_domain("example-test.com")

    def test_invalid_domains(self) -> None:
        """Test invalid domain names."""
        assert not is_valid_domain("")
        assert not is_valid_domain("192.168.1.1")
        assert not is_valid_domain("not a domain")
        assert not is_valid_domain("example..com")

    def test_wildcard_domains(self) -> None:
        """Test wildcard domain handling."""
        assert not is_valid_domain("*.example.com", allow_wildcards=False)
        assert is_valid_domain("*.example.com", allow_wildcards=True)

    def test_normalize_domain(self) -> None:
        """Test domain normalization."""
        assert normalize_domain("EXAMPLE.COM") == "example.com"
        assert normalize_domain("https://example.com") == "example.com"
        assert normalize_domain("example.com:443") == "example.com"
        assert normalize_domain("example.com/path") == "example.com"

    def test_extract_root_domain(self) -> None:
        """Test root domain extraction."""
        assert extract_root_domain("api.example.com") == "example.com"
        assert extract_root_domain("v2.api.example.com") == "example.com"
        assert extract_root_domain("example.co.uk") == "example.co.uk"


class TestEmailValidation:
    """Test email validation."""

    def test_valid_emails(self) -> None:
        """Test valid email addresses."""
        assert validate_email("test@example.com")
        assert validate_email("user.name@example.com")

    def test_invalid_emails(self) -> None:
        """Test invalid email addresses."""
        assert not validate_email("not-an-email")
        assert not validate_email("@example.com")
        assert not validate_email("")


class TestIPValidation:
    """Test IP address validation."""

    def test_valid_ipv4(self) -> None:
        """Test valid IPv4 addresses."""
        assert validate_ipv4("192.168.1.1")
        assert validate_ipv4("8.8.8.8")
        assert validate_ipv4("255.255.255.255")

    def test_invalid_ipv4(self) -> None:
        """Test invalid IPv4 addresses."""
        assert not validate_ipv4("256.1.1.1")
        assert not validate_ipv4("not-an-ip")
        assert not validate_ipv4("")
