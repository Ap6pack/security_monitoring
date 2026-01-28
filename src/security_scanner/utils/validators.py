"""Input validation utilities for domains, URLs, and other data."""

import re
from typing import Pattern
from urllib.parse import urlparse

import validators

from security_scanner.utils.exceptions import ValidationError

# Compiled regex patterns for performance
DOMAIN_PATTERN: Pattern[str] = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$"
)

WILDCARD_DOMAIN_PATTERN: Pattern[str] = re.compile(
    r"^\*\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$"
)

IP_ADDRESS_PATTERN: Pattern[str] = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)


def is_valid_domain(domain: str, allow_wildcards: bool = False) -> bool:
    """
    Validate if a string is a valid domain name.

    Args:
        domain: Domain name to validate
        allow_wildcards: Whether to allow wildcard domains (*.example.com)

    Returns:
        True if domain is valid, False otherwise
    """
    if not domain or not isinstance(domain, str):
        return False

    # Remove leading/trailing whitespace
    domain = domain.strip()

    # Check length constraints
    if len(domain) > 253:
        return False

    # Check for wildcards
    if domain.startswith("*."):
        if not allow_wildcards:
            return False
        return bool(WILDCARD_DOMAIN_PATTERN.match(domain))

    # Check if it's an IP address (not allowed as domain)
    if IP_ADDRESS_PATTERN.match(domain):
        return False

    # Validate domain format
    return bool(DOMAIN_PATTERN.match(domain))


def normalize_domain(domain: str) -> str:
    """
    Normalize a domain name to lowercase without protocol or path.

    Args:
        domain: Domain name to normalize

    Returns:
        Normalized domain name

    Raises:
        ValidationError: If domain is invalid
    """
    if not domain or not isinstance(domain, str):
        raise ValidationError("Domain cannot be empty", field="domain", value=domain)

    # Remove whitespace
    domain = domain.strip()

    # Remove protocol if present
    if "://" in domain:
        domain = domain.split("://", 1)[1]

    # Remove path, query, and fragment
    domain = domain.split("/", 1)[0]
    domain = domain.split("?", 1)[0]
    domain = domain.split("#", 1)[0]

    # Remove port if present
    if ":" in domain and not domain.count(":") > 1:  # IPv6 has multiple colons
        domain = domain.rsplit(":", 1)[0]

    # Convert to lowercase
    domain = domain.lower()

    # Validate the normalized domain
    if not is_valid_domain(domain, allow_wildcards=True):
        raise ValidationError(
            f"Invalid domain format: {domain}",
            field="domain",
            value=domain,
        )

    return domain


def validate_url(url: str) -> bool:
    """
    Validate if a string is a valid URL.

    Args:
        url: URL to validate

    Returns:
        True if URL is valid, False otherwise
    """
    if not url or not isinstance(url, str):
        return False

    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False


def validate_email(email: str) -> bool:
    """
    Validate if a string is a valid email address.

    Args:
        email: Email address to validate

    Returns:
        True if email is valid, False otherwise
    """
    if not email or not isinstance(email, str):
        return False

    return bool(validators.email(email))


def validate_ipv4(ip: str) -> bool:
    """
    Validate if a string is a valid IPv4 address.

    Args:
        ip: IP address to validate

    Returns:
        True if IPv4 is valid, False otherwise
    """
    if not ip or not isinstance(ip, str):
        return False

    return bool(IP_ADDRESS_PATTERN.match(ip))


def validate_ipv6(ip: str) -> bool:
    """
    Validate if a string is a valid IPv6 address.

    Args:
        ip: IP address to validate

    Returns:
        True if IPv6 is valid, False otherwise
    """
    if not ip or not isinstance(ip, str):
        return False

    return bool(validators.ipv6(ip))


def extract_root_domain(domain: str) -> str:
    """
    Extract the root domain from a subdomain.

    Args:
        domain: Full domain name

    Returns:
        Root domain (e.g., "example.com" from "api.example.com")

    Raises:
        ValidationError: If domain is invalid
    """
    domain = normalize_domain(domain)

    # Handle wildcards
    if domain.startswith("*."):
        domain = domain[2:]

    parts = domain.split(".")
    if len(parts) < 2:
        raise ValidationError(
            f"Cannot extract root domain from: {domain}",
            field="domain",
            value=domain,
        )

    # Handle common TLDs with two parts (co.uk, com.au, etc.)
    if len(parts) >= 3 and parts[-2] in {"co", "com", "gov", "net", "org", "ac", "edu"}:
        return ".".join(parts[-3:])

    return ".".join(parts[-2:])


def sanitize_filename(filename: str, replacement: str = "_") -> str:
    """
    Sanitize a string to be safe for use as a filename.

    Args:
        filename: Filename to sanitize
        replacement: Character to replace invalid characters with

    Returns:
        Sanitized filename
    """
    # Remove invalid characters
    invalid_chars = r'[<>:"/\\|?*\x00-\x1f]'
    sanitized = re.sub(invalid_chars, replacement, filename)

    # Remove leading/trailing dots and spaces
    sanitized = sanitized.strip(". ")

    # Ensure filename is not empty
    if not sanitized:
        sanitized = "unnamed"

    # Limit length
    max_length = 255
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length]

    return sanitized
