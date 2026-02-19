"""API request and response models."""

from datetime import datetime

from pydantic import BaseModel, Field

# --- Request Models ---


class ScanRequest(BaseModel):
    """Request body for starting a new scan."""

    domains: list[str] = Field(..., min_length=1, description="Domains to scan")


class ReportRequest(BaseModel):
    """Request body for generating a report."""

    formats: list[str] = Field(
        default=["json"],
        description="Report formats to generate (json, html, markdown, csv)",
    )


# --- Response Models ---


class FindingResponse(BaseModel):
    """Single finding in API responses."""

    id: str
    severity: str
    type: str
    domain: str
    record_type: str | None = None
    target: str | None = None
    description: str
    cvss_score: float | None = None
    remediation: str
    confidence: float = 1.0
    platform: str | None = None
    detected_at: datetime


class ScanSummary(BaseModel):
    """Severity counts for a scan."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class ScanResponse(BaseModel):
    """Response for a single scan."""

    scan_id: str
    status: str
    domains: list[str]
    start_time: datetime
    end_time: datetime | None = None
    duration_seconds: int | None = None
    total_findings: int = 0
    summary: ScanSummary = Field(default_factory=ScanSummary)


class ScanDetailResponse(ScanResponse):
    """Response for a single scan with findings."""

    findings: list[FindingResponse] = Field(default_factory=list)


class ScanListResponse(BaseModel):
    """Response for listing scans."""

    scans: list[ScanResponse]
    total: int


class ScanCreatedResponse(BaseModel):
    """Response when a scan is accepted for execution."""

    scan_id: str
    status: str = "running"
    domains: list[str]
    message: str = "Scan started"


class ReportGeneratedResponse(BaseModel):
    """Response when reports have been generated."""

    scan_id: str
    reports: list[str]
    message: str = "Reports generated"


class HealthResponse(BaseModel):
    """Health check response."""

    status: str = "healthy"
    version: str
    database: str = "connected"


class ConfigValidationResponse(BaseModel):
    """Configuration validation response."""

    valid: bool
    database_path: str
    log_level: str
    dns_nameservers: list[str]
    subdomain_sources: list[str]


class ErrorResponse(BaseModel):
    """Standard error response."""

    detail: str
