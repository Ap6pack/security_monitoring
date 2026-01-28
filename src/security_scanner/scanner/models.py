"""Pydantic models for scanner results."""

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


class SubdomainResult(BaseModel):
    """Subdomain discovery result."""

    domain: str = Field(description="Discovered subdomain")
    source: str = Field(description="Discovery source")
    discovered_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="Discovery timestamp",
    )


class DNSResult(BaseModel):
    """DNS resolution result."""

    domain: str = Field(description="Domain queried")
    record_type: str = Field(description="Record type (A, AAAA, CNAME, MX)")
    values: list[str] = Field(default_factory=list, description="Record values")
    ttl: int = Field(default=300, description="Time to live")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Query timestamp")
    nameserver: str = Field(description="Nameserver used")
    error: Optional[str] = Field(default=None, description="Error if resolution failed")
    is_dangling: bool = Field(default=False, description="Whether the record is dangling")


class CertificateResult(BaseModel):
    """Certificate transparency result."""

    cert_id: str = Field(description="Certificate ID from CT log")
    issuer: str = Field(description="Certificate issuer")
    not_before: datetime = Field(description="Valid from date")
    not_after: datetime = Field(description="Expiration date")
    common_name: str = Field(description="Common name")
    san_domains: list[str] = Field(default_factory=list, description="Subject Alternative Names")
    is_wildcard: bool = Field(default=False, description="Whether it's a wildcard certificate")
    is_expired: bool = Field(default=False, description="Whether the certificate is expired")
    logged_at: datetime = Field(description="CT log timestamp")


class ScanResult(BaseModel):
    """Combined scan result."""

    domain: str = Field(description="Target domain")
    subdomains: list[SubdomainResult] = Field(
        default_factory=list,
        description="Discovered subdomains",
    )
    dns_records: list[DNSResult] = Field(
        default_factory=list,
        description="DNS resolution results",
    )
    certificates: list[CertificateResult] = Field(
        default_factory=list,
        description="Certificate transparency results",
    )
    scan_time: datetime = Field(
        default_factory=datetime.utcnow,
        description="Scan timestamp",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional metadata",
    )
