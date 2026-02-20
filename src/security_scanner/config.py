"""Configuration management using Pydantic settings."""

from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration with validation."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Database
    database_path: Path = Field(
        default=Path("data/security_scanner.db"),
        description="Path to SQLite database file",
    )

    # Logging
    log_level: str = Field(default="INFO", description="Logging level")
    log_file: Path | None = Field(
        default=Path("logs/security_scanner.log"), description="Log file path"
    )
    log_format: Literal["json", "console"] = Field(
        default="console",
        description="Log output format",
    )

    # DNS Configuration
    dns_nameservers: list[str] = Field(
        default=["8.8.8.8", "1.1.1.1"],
        description="DNS nameservers to use",
    )
    dns_timeout: int = Field(default=5, ge=1, le=30, description="DNS query timeout in seconds")
    dns_max_retries: int = Field(default=3, ge=0, le=10, description="Maximum DNS retry attempts")

    # HTTP Client
    http_timeout: int = Field(
        default=10, ge=1, le=60, description="HTTP request timeout in seconds"
    )
    http_max_retries: int = Field(default=3, ge=0, le=10, description="Maximum HTTP retry attempts")
    http_max_connections: int = Field(
        default=100,
        ge=1,
        le=1000,
        description="Maximum concurrent HTTP connections",
    )
    http_user_agent: str = Field(
        default="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        description="User agent for HTTP requests",
    )

    # Rate Limiting
    rate_limit_requests_per_second: float = Field(
        default=2.0,
        ge=0.1,
        le=100.0,
        description="Maximum requests per second",
    )
    rate_limit_burst: int = Field(
        default=5,
        ge=1,
        le=100,
        description="Burst capacity for rate limiter",
    )

    # Scanner Configuration
    max_concurrent_scans: int = Field(
        default=50,
        ge=1,
        le=500,
        description="Maximum concurrent scan operations",
    )
    subdomain_sources: list[str] = Field(
        default=["crtsh", "subfinder", "assetfinder"],
        description="Subdomain discovery sources to use",
    )
    enable_certificate_monitoring: bool = Field(
        default=True,
        description="Enable certificate transparency monitoring",
    )
    certificate_json_file: Path | None = Field(
        default=None,
        description="Path to pre-downloaded crt.sh JSON file (fallback for rate limiting)",
    )

    # External Tools
    subfinder_path: Path = Field(
        default=Path("/usr/local/bin/subfinder"),
        description="Path to subfinder binary",
    )
    assetfinder_path: Path = Field(
        default=Path("/usr/local/bin/assetfinder"),
        description="Path to assetfinder binary",
    )

    # Email Alerting
    enable_email_alerts: bool = Field(default=False, description="Enable email alerts")
    smtp_host: str = Field(default="smtp.gmail.com", description="SMTP server host")
    smtp_port: int = Field(default=587, ge=1, le=65535, description="SMTP server port")
    smtp_username: str = Field(default="", description="SMTP username")
    smtp_password: str = Field(default="", description="SMTP password")
    smtp_from: str = Field(default="security@example.com", description="From email address")
    smtp_to: str = Field(default="admin@example.com", description="To email address")
    smtp_use_tls: bool = Field(default=True, description="Use TLS for SMTP")

    # Slack Alerting
    enable_slack_alerts: bool = Field(default=False, description="Enable Slack alerts")
    slack_webhook_url: str = Field(default="", description="Slack webhook URL")

    # Webhook Alerting
    enable_webhook_alerts: bool = Field(default=False, description="Enable webhook alerts")
    webhook_url: str = Field(default="", description="Webhook URL for generic HTTP POST alerts")

    # Alert Thresholds
    alert_on_critical: bool = Field(default=True, description="Alert on critical findings")
    alert_on_high: bool = Field(default=True, description="Alert on high severity findings")
    alert_min_findings: int = Field(
        default=1,
        ge=1,
        description="Minimum findings to trigger alert",
    )

    # Report Configuration
    report_output_dir: Path = Field(
        default=Path("reports"),
        description="Directory for generated reports",
    )
    report_formats: list[str] = Field(
        default=["json", "html", "markdown"],
        description="Report formats to generate",
    )

    # Performance Tuning
    cache_ttl: int = Field(default=3600, ge=0, description="Cache TTL in seconds")
    cache_max_size: int = Field(default=10000, ge=0, description="Maximum cache size")
    enable_cache: bool = Field(default=True, description="Enable result caching")

    # Development
    debug: bool = Field(default=False, description="Enable debug mode")
    profile: bool = Field(default=False, description="Enable profiling")

    @field_validator("dns_nameservers", mode="before")
    @classmethod
    def parse_nameservers(cls, v: str | list[str]) -> list[str]:
        """Parse DNS nameservers from string or list."""
        if isinstance(v, str):
            return [ns.strip() for ns in v.split(",") if ns.strip()]
        return v

    @field_validator("subdomain_sources", mode="before")
    @classmethod
    def parse_subdomain_sources(cls, v: str | list[str]) -> list[str]:
        """Parse subdomain sources from string or list."""
        if isinstance(v, str):
            return [s.strip() for s in v.split(",") if s.strip()]
        return v

    @field_validator("report_formats", mode="before")
    @classmethod
    def parse_report_formats(cls, v: str | list[str]) -> list[str]:
        """Parse report formats from string or list."""
        if isinstance(v, str):
            return [f.strip() for f in v.split(",") if f.strip()]
        return v

    def ensure_directories(self) -> None:
        """Ensure required directories exist."""
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        if self.log_file:
            self.log_file.parent.mkdir(parents=True, exist_ok=True)
        self.report_output_dir.mkdir(parents=True, exist_ok=True)


def load_settings() -> Settings:
    """Load and validate application settings."""
    settings = Settings()
    settings.ensure_directories()
    return settings
