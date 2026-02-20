# Copyright (c) 2024 Veritas Aequitas Holdings LLC. All rights reserved.
"""Comprehensive unit tests for the FastAPI REST API."""

from __future__ import annotations

import os
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from fastapi import FastAPI

from security_scanner.api import dependencies as deps
from security_scanner.api.app import create_app
from security_scanner.storage.models import Finding, Scan

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_scan(
    scan_id: str = "scan-001",
    domains: list[str] | None = None,
    status: str = "completed",
    total_findings: int = 2,
    critical: int = 1,
    high: int = 1,
    medium: int = 0,
    low: int = 0,
) -> Scan:
    """Build a Scan instance for testing."""
    return Scan(
        id=scan_id,
        start_time=datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC),
        end_time=datetime(2024, 1, 1, 12, 5, 0, tzinfo=UTC),
        duration_seconds=300,
        domains_scanned=domains or ["example.com"],
        status=status,
        scanner_version="0.1.0",
        total_findings=total_findings,
        critical_findings=critical,
        high_findings=high,
        medium_findings=medium,
        low_findings=low,
    )


def _make_finding(
    finding_id: str = "finding-001",
    scan_id: str = "scan-001",
    severity: str = "CRITICAL",
    domain: str = "example.com",
) -> Finding:
    """Build a Finding instance for testing."""
    return Finding(
        id=finding_id,
        scan_id=scan_id,
        severity=severity,
        type="dangling_dns",
        domain=domain,
        record_type="CNAME",
        target="old.cdn.example.com",
        description="Dangling CNAME detected",
        cvss_score=9.8,
        remediation="Remove the DNS record",
        raw_data={"record": "CNAME"},
        detected_at=datetime(2024, 1, 1, 12, 1, 0, tzinfo=UTC),
        first_seen=datetime(2024, 1, 1, 12, 1, 0, tzinfo=UTC),
        alerted=False,
        platform="aws",
        confidence=0.95,
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clear_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure SECURITY_SCANNER_API_KEY is absent unless a test sets it."""
    monkeypatch.delenv("SECURITY_SCANNER_API_KEY", raising=False)


@pytest.fixture
def mock_settings() -> MagicMock:
    """Create a mock Settings object."""
    settings: MagicMock = MagicMock()
    settings.database_path = Path("/tmp/test.db")
    settings.log_level = "INFO"
    settings.dns_nameservers = ["8.8.8.8"]
    settings.subdomain_sources = ["crtsh"]
    settings.report_output_dir = Path("/tmp/reports")
    # Disable alert channels to prevent AlertManager from creating real HTTP clients
    settings.enable_email_alerts = False
    settings.enable_slack_alerts = False
    settings.enable_webhook_alerts = False
    return settings


@pytest.fixture
def mock_db() -> AsyncMock:
    """Create a mock DatabaseManager."""
    return AsyncMock()


@pytest.fixture
def mock_orchestrator() -> AsyncMock:
    """Create a mock ScanOrchestrator."""
    return AsyncMock()


@pytest.fixture
def app() -> FastAPI:
    """Create a FastAPI test application with a no-op lifespan."""

    @asynccontextmanager
    async def _noop_lifespan(_application: FastAPI) -> AsyncGenerator[None, None]:
        yield

    test_app = create_app()
    test_app.router.lifespan_context = _noop_lifespan
    return test_app


@pytest.fixture
async def client(
    app: FastAPI,
    mock_settings: MagicMock,
    mock_db: AsyncMock,
    mock_orchestrator: AsyncMock,
) -> AsyncGenerator[httpx.AsyncClient, None]:
    """Create an async HTTP test client with mocked app state."""
    deps.app_state.settings = mock_settings
    deps.app_state.db = mock_db
    deps.app_state.orchestrator = mock_orchestrator
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as c:
        yield c
    deps.app_state.settings = None
    deps.app_state.db = None
    deps.app_state.orchestrator = None


# ---------------------------------------------------------------------------
# Health & Config
# ---------------------------------------------------------------------------


class TestHealthEndpoint:
    """Tests for GET /api/v1/health."""

    async def test_health_returns_200(self, client: httpx.AsyncClient) -> None:
        """Health check should return 200 with version."""
        resp = await client.get("/api/v1/health")

        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "healthy"
        assert "version" in body
        assert body["version"] == "0.1.0"

    async def test_health_no_auth_required(
        self,
        client: httpx.AsyncClient,
    ) -> None:
        """Health endpoint must be accessible without an API key."""
        with patch.dict(os.environ, {"SECURITY_SCANNER_API_KEY": "secret"}):
            resp = await client.get("/api/v1/health")

        assert resp.status_code == 200


class TestConfigValidateEndpoint:
    """Tests for GET /api/v1/config/validate."""

    async def test_config_validate_returns_settings(
        self,
        client: httpx.AsyncClient,
    ) -> None:
        """Config validate should return current settings."""
        resp = await client.get("/api/v1/config/validate")

        assert resp.status_code == 200
        body = resp.json()
        assert body["valid"] is True
        assert body["database_path"] == "/tmp/test.db"
        assert body["log_level"] == "INFO"
        assert body["dns_nameservers"] == ["8.8.8.8"]
        assert body["subdomain_sources"] == ["crtsh"]


# ---------------------------------------------------------------------------
# Create Scan
# ---------------------------------------------------------------------------


class TestCreateScan:
    """Tests for POST /api/v1/scans."""

    async def test_create_scan_valid(
        self,
        client: httpx.AsyncClient,
        mock_db: AsyncMock,
    ) -> None:
        """A valid scan request should return 202."""
        mock_db.create_scan.return_value = "new-scan-id"

        resp = await client.post(
            "/api/v1/scans",
            json={"domains": ["example.com"]},
        )

        assert resp.status_code == 202
        body = resp.json()
        assert body["scan_id"] == "new-scan-id"
        assert body["status"] == "running"
        assert body["domains"] == ["example.com"]
        mock_db.create_scan.assert_awaited_once()

    async def test_create_scan_multiple_domains(
        self,
        client: httpx.AsyncClient,
        mock_db: AsyncMock,
    ) -> None:
        """Multiple domains should be accepted."""
        mock_db.create_scan.return_value = "multi-scan-id"

        resp = await client.post(
            "/api/v1/scans",
            json={"domains": ["a.com", "b.com", "c.com"]},
        )

        assert resp.status_code == 202
        body = resp.json()
        assert body["domains"] == ["a.com", "b.com", "c.com"]

    async def test_create_scan_empty_domains(
        self,
        client: httpx.AsyncClient,
    ) -> None:
        """An empty domains list should return 422 (Pydantic validation)."""
        resp = await client.post(
            "/api/v1/scans",
            json={"domains": []},
        )

        assert resp.status_code == 422

    async def test_create_scan_missing_domains(
        self,
        client: httpx.AsyncClient,
    ) -> None:
        """A request with no domains key should return 422 (Pydantic validation)."""
        resp = await client.post("/api/v1/scans", json={})

        assert resp.status_code == 422

    async def test_create_scan_invalid_domain_entry(
        self,
        client: httpx.AsyncClient,
    ) -> None:
        """A domain that is an empty string should return 400."""
        resp = await client.post(
            "/api/v1/scans",
            json={"domains": [""]},
        )

        assert resp.status_code == 400
        assert "Invalid domain" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# List Scans
# ---------------------------------------------------------------------------


class TestListScans:
    """Tests for GET /api/v1/scans."""

    async def test_list_scans_empty(
        self,
        client: httpx.AsyncClient,
        mock_db: AsyncMock,
    ) -> None:
        """When there are no scans the list should be empty."""
        mock_db.list_scans.return_value = []

        resp = await client.get("/api/v1/scans")

        assert resp.status_code == 200
        body = resp.json()
        assert body["scans"] == []
        assert body["total"] == 0

    async def test_list_scans_with_results(
        self,
        client: httpx.AsyncClient,
        mock_db: AsyncMock,
    ) -> None:
        """Scans should be serialised correctly."""
        mock_db.list_scans.return_value = [
            _make_scan("s1", ["a.com"]),
            _make_scan("s2", ["b.com"]),
        ]

        resp = await client.get("/api/v1/scans")

        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 2
        assert body["scans"][0]["scan_id"] == "s1"
        assert body["scans"][1]["scan_id"] == "s2"

    async def test_list_scans_limit_parameter(
        self,
        client: httpx.AsyncClient,
        mock_db: AsyncMock,
    ) -> None:
        """The limit query parameter should be forwarded to the DB."""
        mock_db.list_scans.return_value = [_make_scan()]

        resp = await client.get("/api/v1/scans", params={"limit": 5})

        assert resp.status_code == 200
        mock_db.list_scans.assert_awaited_once_with(limit=5)

    async def test_list_scans_response_shape(
        self,
        client: httpx.AsyncClient,
        mock_db: AsyncMock,
    ) -> None:
        """Verify the full shape of a scan response entry."""
        mock_db.list_scans.return_value = [_make_scan()]

        resp = await client.get("/api/v1/scans")

        scan_resp: dict[str, Any] = resp.json()["scans"][0]
        assert scan_resp["status"] == "completed"
        assert scan_resp["total_findings"] == 2
        assert scan_resp["summary"]["critical"] == 1
        assert scan_resp["summary"]["high"] == 1


# ---------------------------------------------------------------------------
# Get Scan
# ---------------------------------------------------------------------------


class TestGetScan:
    """Tests for GET /api/v1/scans/{scan_id}."""

    async def test_get_scan_found(
        self,
        client: httpx.AsyncClient,
        mock_db: AsyncMock,
    ) -> None:
        """An existing scan should be returned with its findings."""
        mock_db.get_scan.return_value = _make_scan("scan-100")
        mock_db.get_scan_findings.return_value = [
            _make_finding("f1", "scan-100"),
        ]

        resp = await client.get("/api/v1/scans/scan-100")

        assert resp.status_code == 200
        body = resp.json()
        assert body["scan_id"] == "scan-100"
        assert len(body["findings"]) == 1
        assert body["findings"][0]["id"] == "f1"

    async def test_get_scan_not_found(
        self,
        client: httpx.AsyncClient,
        mock_db: AsyncMock,
    ) -> None:
        """A non-existent scan should return 404."""
        mock_db.get_scan.return_value = None

        resp = await client.get("/api/v1/scans/does-not-exist")

        assert resp.status_code == 404
        assert "not found" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# Get Scan Findings
# ---------------------------------------------------------------------------


class TestGetScanFindings:
    """Tests for GET /api/v1/scans/{scan_id}/findings."""

    async def test_findings_all(
        self,
        client: httpx.AsyncClient,
        mock_db: AsyncMock,
    ) -> None:
        """All findings should be returned when no severity filter is given."""
        mock_db.get_scan.return_value = _make_scan("scan-200")
        mock_db.get_scan_findings.return_value = [
            _make_finding("f1", "scan-200", severity="CRITICAL"),
            _make_finding("f2", "scan-200", severity="HIGH"),
        ]

        resp = await client.get("/api/v1/scans/scan-200/findings")

        assert resp.status_code == 200
        assert len(resp.json()) == 2

    async def test_findings_filter_by_severity(
        self,
        client: httpx.AsyncClient,
        mock_db: AsyncMock,
    ) -> None:
        """Only findings matching the requested severity should be returned."""
        mock_db.get_scan.return_value = _make_scan("scan-200")
        mock_db.get_scan_findings.return_value = [
            _make_finding("f1", "scan-200", severity="CRITICAL"),
            _make_finding("f2", "scan-200", severity="HIGH"),
            _make_finding("f3", "scan-200", severity="LOW"),
        ]

        resp = await client.get(
            "/api/v1/scans/scan-200/findings",
            params={"severity": "HIGH"},
        )

        assert resp.status_code == 200
        findings = resp.json()
        assert len(findings) == 1
        assert findings[0]["severity"] == "HIGH"

    async def test_findings_scan_not_found(
        self,
        client: httpx.AsyncClient,
        mock_db: AsyncMock,
    ) -> None:
        """Requesting findings for a missing scan should return 404."""
        mock_db.get_scan.return_value = None

        resp = await client.get("/api/v1/scans/no-such-scan/findings")

        assert resp.status_code == 404

    async def test_findings_severity_case_insensitive(
        self,
        client: httpx.AsyncClient,
        mock_db: AsyncMock,
    ) -> None:
        """Severity filter should be case-insensitive."""
        mock_db.get_scan.return_value = _make_scan("scan-200")
        mock_db.get_scan_findings.return_value = [
            _make_finding("f1", "scan-200", severity="CRITICAL"),
            _make_finding("f2", "scan-200", severity="HIGH"),
        ]

        resp = await client.get(
            "/api/v1/scans/scan-200/findings",
            params={"severity": "critical"},
        )

        assert resp.status_code == 200
        findings = resp.json()
        assert len(findings) == 1
        assert findings[0]["severity"] == "CRITICAL"


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------


class TestGenerateReports:
    """Tests for POST /api/v1/scans/{scan_id}/reports."""

    async def test_generate_report_json(
        self,
        client: httpx.AsyncClient,
        mock_db: AsyncMock,
        mock_settings: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Generating a JSON report should return the output path."""
        mock_settings.report_output_dir = tmp_path
        mock_db.get_scan.return_value = _make_scan("00000000-0000-0000-0000-000000000300")
        mock_db.get_scan_findings.return_value = [
            _make_finding("f1", "00000000-0000-0000-0000-000000000300"),
        ]

        resp = await client.post(
            "/api/v1/scans/00000000-0000-0000-0000-000000000300/reports",
            json={"formats": ["json"]},
        )

        assert resp.status_code == 200
        body = resp.json()
        assert body["scan_id"] == "00000000-0000-0000-0000-000000000300"
        assert len(body["reports"]) == 1
        assert body["reports"][0].endswith(".json")

    async def test_generate_report_invalid_format(
        self,
        client: httpx.AsyncClient,
        mock_db: AsyncMock,
    ) -> None:
        """An unsupported format should return 400."""
        resp = await client.post(
            "/api/v1/scans/00000000-0000-0000-0000-000000000300/reports",
            json={"formats": ["pdf"]},
        )

        assert resp.status_code == 400
        assert "Invalid format" in resp.json()["detail"]

    async def test_generate_report_scan_not_found(
        self,
        client: httpx.AsyncClient,
        mock_db: AsyncMock,
    ) -> None:
        """Report generation for a missing scan should return 404."""
        mock_db.get_scan.return_value = None

        resp = await client.post(
            "/api/v1/scans/00000000-0000-0000-0000-000000000999/reports",
            json={"formats": ["json"]},
        )

        assert resp.status_code == 404

    async def test_generate_report_default_format(
        self,
        client: httpx.AsyncClient,
        mock_db: AsyncMock,
        mock_settings: MagicMock,
        tmp_path: Path,
    ) -> None:
        """When no formats are specified the default (json) should be used."""
        mock_settings.report_output_dir = tmp_path
        mock_db.get_scan.return_value = _make_scan("00000000-0000-0000-0000-000000000400")
        mock_db.get_scan_findings.return_value = []

        resp = await client.post("/api/v1/scans/00000000-0000-0000-0000-000000000400/reports")

        assert resp.status_code == 200
        body = resp.json()
        assert len(body["reports"]) == 1
        assert body["reports"][0].endswith(".json")

    async def test_generate_report_multiple_formats(
        self,
        client: httpx.AsyncClient,
        mock_db: AsyncMock,
        mock_settings: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Multiple valid formats should each produce a report file."""
        mock_settings.report_output_dir = tmp_path
        mock_db.get_scan.return_value = _make_scan("00000000-0000-0000-0000-000000000500")
        mock_db.get_scan_findings.return_value = []

        resp = await client.post(
            "/api/v1/scans/00000000-0000-0000-0000-000000000500/reports",
            json={"formats": ["json", "csv"]},
        )

        assert resp.status_code == 200
        body = resp.json()
        assert len(body["reports"]) == 2
        extensions = {Path(r).suffix for r in body["reports"]}
        assert extensions == {".json", ".csv"}


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------


class TestApiKeyAuth:
    """Tests for API key authentication."""

    async def test_no_key_configured_allows_access(
        self,
        client: httpx.AsyncClient,
        mock_db: AsyncMock,
    ) -> None:
        """When no API key is configured all requests should pass."""
        mock_db.list_scans.return_value = []

        with patch.dict(os.environ, {}, clear=False):
            # Ensure the key is NOT in the environment
            os.environ.pop("SECURITY_SCANNER_API_KEY", None)
            resp = await client.get("/api/v1/scans")

        assert resp.status_code == 200

    async def test_key_configured_missing_header_returns_401(
        self,
        client: httpx.AsyncClient,
    ) -> None:
        """A missing X-API-Key header should yield 401 when auth is enabled."""
        with patch.dict(
            os.environ,
            {"SECURITY_SCANNER_API_KEY": "real-secret"},
        ):
            resp = await client.get("/api/v1/scans")

        assert resp.status_code == 401
        assert resp.json()["detail"] == "Missing API key"

    async def test_key_configured_wrong_key_returns_403(
        self,
        client: httpx.AsyncClient,
    ) -> None:
        """A wrong API key should yield 403."""
        with patch.dict(
            os.environ,
            {"SECURITY_SCANNER_API_KEY": "real-secret"},
        ):
            resp = await client.get(
                "/api/v1/scans",
                headers={"X-API-Key": "wrong-key"},
            )

        assert resp.status_code == 403
        assert resp.json()["detail"] == "Invalid API key"

    async def test_key_configured_correct_key_returns_200(
        self,
        client: httpx.AsyncClient,
        mock_db: AsyncMock,
    ) -> None:
        """The correct API key should grant access."""
        mock_db.list_scans.return_value = []

        with patch.dict(
            os.environ,
            {"SECURITY_SCANNER_API_KEY": "real-secret"},
        ):
            resp = await client.get(
                "/api/v1/scans",
                headers={"X-API-Key": "real-secret"},
            )

        assert resp.status_code == 200

    async def test_auth_applies_to_config_endpoint(
        self,
        client: httpx.AsyncClient,
    ) -> None:
        """Config validate should also be protected by the API key."""
        with patch.dict(
            os.environ,
            {"SECURITY_SCANNER_API_KEY": "key123"},
        ):
            resp = await client.get("/api/v1/config/validate")

        assert resp.status_code == 401

    async def test_auth_applies_to_create_scan(
        self,
        client: httpx.AsyncClient,
    ) -> None:
        """POST /scans should be protected by the API key."""
        with patch.dict(
            os.environ,
            {"SECURITY_SCANNER_API_KEY": "key123"},
        ):
            resp = await client.post(
                "/api/v1/scans",
                json={"domains": ["example.com"]},
            )

        assert resp.status_code == 401

    async def test_auth_applies_to_reports(
        self,
        client: httpx.AsyncClient,
    ) -> None:
        """POST /scans/{id}/reports should be protected by the API key."""
        with patch.dict(
            os.environ,
            {"SECURITY_SCANNER_API_KEY": "key123"},
        ):
            resp = await client.post(
                "/api/v1/scans/some-id/reports",
                json={"formats": ["json"]},
            )

        assert resp.status_code == 401
