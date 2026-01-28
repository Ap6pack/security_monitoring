"""Data models for storage."""

from datetime import datetime
from typing import Any, Optional
from uuid import uuid4

from pydantic import BaseModel, Field


def generate_uuid() -> str:
    """Generate a new UUID string."""
    return str(uuid4())


class Scan(BaseModel):
    """Scan session record."""

    id: str = Field(default_factory=generate_uuid, description="Unique scan ID")
    start_time: datetime = Field(default_factory=datetime.utcnow, description="Scan start time")
    end_time: Optional[datetime] = Field(default=None, description="Scan end time")
    duration_seconds: Optional[int] = Field(default=None, description="Scan duration")
    domains_scanned: list[str] = Field(default_factory=list, description="Domains scanned")
    status: str = Field(default="running", description="Scan status")
    scanner_version: str = Field(default="0.1.0", description="Scanner version")
    total_findings: int = Field(default=0, description="Total findings count")
    critical_findings: int = Field(default=0, description="Critical findings count")
    high_findings: int = Field(default=0, description="High findings count")
    medium_findings: int = Field(default=0, description="Medium findings count")
    low_findings: int = Field(default=0, description="Low findings count")


class Finding(BaseModel):
    """Security finding record."""

    id: str = Field(default_factory=generate_uuid, description="Unique finding ID")
    scan_id: str = Field(description="Associated scan ID")
    severity: str = Field(description="Finding severity (CRITICAL, HIGH, MEDIUM, LOW)")
    type: str = Field(description="Finding type (dangling_dns, takeover, etc.)")
    domain: str = Field(description="Affected domain")
    record_type: Optional[str] = Field(default=None, description="DNS record type")
    target: Optional[str] = Field(default=None, description="Target resource")
    description: str = Field(description="Finding description")
    cvss_score: Optional[float] = Field(default=None, description="CVSS score")
    remediation: str = Field(description="Remediation steps")
    raw_data: dict[str, Any] = Field(default_factory=dict, description="Raw data")
    detected_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="Detection timestamp",
    )
    first_seen: datetime = Field(
        default_factory=datetime.utcnow,
        description="First seen timestamp",
    )
    alerted: bool = Field(default=False, description="Whether alert was sent")
    platform: Optional[str] = Field(default=None, description="Detected platform")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Detection confidence")


class Certificate(BaseModel):
    """Certificate transparency record."""

    id: str = Field(default_factory=generate_uuid, description="Unique record ID")
    scan_id: str = Field(description="Associated scan ID")
    cert_id: str = Field(description="Certificate ID from CT log")
    issuer: str = Field(description="Certificate issuer")
    expires: datetime = Field(description="Expiration date")
    shared: bool = Field(default=False, description="Whether cert is shared across domains")
    san_count: int = Field(default=0, description="Number of SANs")
    san_domains: list[str] = Field(default_factory=list, description="SAN domains")
    external_domains: list[str] = Field(
        default_factory=list,
        description="External domains in SANs",
    )
    risk_level: str = Field(default="LOW", description="Risk assessment")
    logged_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="CT log timestamp",
    )


class AlertHistory(BaseModel):
    """Alert sending history."""

    id: str = Field(default_factory=generate_uuid, description="Unique alert ID")
    finding_id: str = Field(description="Associated finding ID")
    channel: str = Field(description="Alert channel (email, slack)")
    sent_at: datetime = Field(default_factory=datetime.utcnow, description="Send timestamp")
    success: bool = Field(description="Whether alert was successful")
    error_message: Optional[str] = Field(default=None, description="Error message if failed")
    retry_count: int = Field(default=0, description="Number of retry attempts")


class DNSRecord(BaseModel):
    """DNS resolution record."""

    domain: str = Field(description="Domain name")
    record_type: str = Field(description="Record type (A, AAAA, CNAME, MX, etc.)")
    values: list[str] = Field(default_factory=list, description="Record values")
    ttl: int = Field(default=300, description="Time to live")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Query timestamp")
    nameserver: str = Field(description="Nameserver used")
    is_dangling: bool = Field(default=False, description="Whether record is dangling")
    error: Optional[str] = Field(default=None, description="Error message if query failed")


class SubdomainRecord(BaseModel):
    """Subdomain discovery record."""

    domain: str = Field(description="Subdomain")
    source: str = Field(description="Discovery source")
    discovered_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="Discovery timestamp",
    )
