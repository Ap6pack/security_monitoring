"""Unit tests for the web dashboard."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from fastapi import FastAPI

from security_scanner.api import dependencies as deps
from security_scanner.api.app import create_app
from security_scanner.dashboard.context import (
    format_duration,
    severity_color,
    status_color,
    time_ago,
    truncate,
)
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


MOCK_STATS: dict[str, object] = {
    "total_scans": 10,
    "running_scans": 1,
    "scans_last_24h": 3,
    "total_findings": 25,
    "findings_by_severity": {"CRITICAL": 5, "HIGH": 8, "MEDIUM": 7, "LOW": 5},
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clear_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SECURITY_SCANNER_API_KEY", raising=False)


@pytest.fixture
def mock_db() -> AsyncMock:
    db = AsyncMock()
    db.db_path = ":memory:"
    return db


@pytest.fixture
def mock_orchestrator() -> AsyncMock:
    return AsyncMock()


@pytest.fixture
def app() -> FastAPI:
    @asynccontextmanager
    async def _noop_lifespan(_application: FastAPI) -> AsyncGenerator[None, None]:
        yield

    test_app = create_app()
    test_app.router.lifespan_context = _noop_lifespan
    return test_app


@pytest.fixture
async def client(
    app: FastAPI,
    mock_db: AsyncMock,
    mock_orchestrator: AsyncMock,
) -> AsyncGenerator[httpx.AsyncClient, None]:
    mock_settings = MagicMock()
    mock_settings.database_path = "/tmp/test.db"
    mock_settings.log_level = "INFO"
    mock_settings.dns_nameservers = ["8.8.8.8"]
    mock_settings.subdomain_sources = ["crtsh"]
    mock_settings.report_output_dir = "/tmp/reports"
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
# Context helper tests
# ---------------------------------------------------------------------------


class TestSeverityColor:
    def test_critical(self) -> None:
        assert severity_color("CRITICAL") == "#dc3545"

    def test_high(self) -> None:
        assert severity_color("HIGH") == "#fd7e14"

    def test_medium(self) -> None:
        assert severity_color("MEDIUM") == "#ffc107"

    def test_low(self) -> None:
        assert severity_color("LOW") == "#198754"

    def test_unknown(self) -> None:
        assert severity_color("UNKNOWN") == "#6c757d"

    def test_case_insensitive(self) -> None:
        assert severity_color("critical") == "#dc3545"


class TestStatusColor:
    def test_running(self) -> None:
        assert status_color("running") == "#0d6efd"

    def test_completed(self) -> None:
        assert status_color("completed") == "#198754"

    def test_failed(self) -> None:
        assert status_color("failed") == "#dc3545"

    def test_unknown(self) -> None:
        assert status_color("pending") == "#6c757d"


class TestTimeAgo:
    def test_none(self) -> None:
        assert time_ago(None) == "—"

    def test_seconds(self) -> None:
        now = datetime.now(UTC)
        result = time_ago(now)
        assert result.endswith("s ago") or result == "just now"

    def test_naive_datetime(self) -> None:
        dt = datetime(2020, 1, 1, 0, 0, 0)
        result = time_ago(dt)
        assert "d ago" in result


class TestFormatDuration:
    def test_none(self) -> None:
        assert format_duration(None) == "—"

    def test_seconds(self) -> None:
        assert format_duration(45) == "45s"

    def test_minutes(self) -> None:
        assert format_duration(125) == "2m 5s"

    def test_hours(self) -> None:
        assert format_duration(3725) == "1h 2m"


class TestTruncate:
    def test_short_text(self) -> None:
        assert truncate("hello") == "hello"

    def test_long_text(self) -> None:
        result = truncate("a" * 100, length=20)
        assert len(result) == 20
        assert result.endswith("…")

    def test_exact_length(self) -> None:
        assert truncate("hello", length=5) == "hello"


# ---------------------------------------------------------------------------
# Full-page route tests
# ---------------------------------------------------------------------------


class TestDashboardOverview:
    async def test_overview_page(self, client: httpx.AsyncClient) -> None:
        with (
            patch(
                "security_scanner.dashboard.router.get_dashboard_stats",
                return_value=MOCK_STATS,
            ),
            patch(
                "security_scanner.dashboard.router.list_scans_paginated",
                return_value=([_make_scan()], 1),
            ),
        ):
            resp = await client.get("/dashboard/")
            assert resp.status_code == 200
            assert "Dashboard" in resp.text
            assert "Security Scanner" in resp.text

    async def test_overview_contains_stats(self, client: httpx.AsyncClient) -> None:
        with (
            patch(
                "security_scanner.dashboard.router.get_dashboard_stats",
                return_value=MOCK_STATS,
            ),
            patch(
                "security_scanner.dashboard.router.list_scans_paginated",
                return_value=([_make_scan()], 1),
            ),
        ):
            resp = await client.get("/dashboard/")
            assert "10" in resp.text  # total_scans
            assert "25" in resp.text  # total_findings


class TestScanList:
    async def test_scan_list_page(self, client: httpx.AsyncClient) -> None:
        with patch(
            "security_scanner.dashboard.router.list_scans_paginated",
            return_value=([_make_scan()], 1),
        ):
            resp = await client.get("/dashboard/scans")
            assert resp.status_code == 200
            assert "scan-001" in resp.text

    async def test_scan_list_empty(self, client: httpx.AsyncClient) -> None:
        with patch(
            "security_scanner.dashboard.router.list_scans_paginated",
            return_value=([], 0),
        ):
            resp = await client.get("/dashboard/scans")
            assert resp.status_code == 200
            assert "No scans" in resp.text

    async def test_scan_list_pagination(self, client: httpx.AsyncClient) -> None:
        with patch(
            "security_scanner.dashboard.router.list_scans_paginated",
            return_value=([_make_scan()], 50),
        ):
            resp = await client.get("/dashboard/scans?page=2&limit=20")
            assert resp.status_code == 200
            assert "Page 2" in resp.text


class TestScanDetail:
    async def test_scan_detail_page(self, client: httpx.AsyncClient, mock_db: AsyncMock) -> None:
        mock_db.get_scan.return_value = _make_scan()
        with patch(
            "security_scanner.dashboard.router.list_findings_filtered",
            return_value=([_make_finding()], 1),
        ):
            resp = await client.get("/dashboard/scans/scan-001")
            assert resp.status_code == 200
            assert "scan-001" in resp.text
            assert "example.com" in resp.text

    async def test_scan_detail_not_found(
        self, client: httpx.AsyncClient, mock_db: AsyncMock
    ) -> None:
        mock_db.get_scan.return_value = None
        resp = await client.get("/dashboard/scans/nonexistent")
        assert resp.status_code == 404

    async def test_scan_detail_severity_filter(
        self, client: httpx.AsyncClient, mock_db: AsyncMock
    ) -> None:
        mock_db.get_scan.return_value = _make_scan()
        with patch(
            "security_scanner.dashboard.router.list_findings_filtered",
            return_value=([_make_finding()], 1),
        ):
            resp = await client.get("/dashboard/scans/scan-001?severity=CRITICAL")
            assert resp.status_code == 200
            assert "CRITICAL" in resp.text


class TestNewScanForm:
    async def test_new_scan_page(self, client: httpx.AsyncClient) -> None:
        resp = await client.get("/dashboard/scans/new")
        assert resp.status_code == 200
        assert "Start New Scan" in resp.text
        assert "domains" in resp.text


class TestFindingsBrowser:
    async def test_findings_page(self, client: httpx.AsyncClient) -> None:
        with (
            patch(
                "security_scanner.dashboard.router.list_findings_filtered",
                return_value=([_make_finding()], 1),
            ),
            patch("aiosqlite.connect") as mock_connect,
        ):
            mock_conn = AsyncMock()
            mock_cursor = AsyncMock()
            mock_cursor.__aiter__ = lambda self: aiter_rows(["dangling_dns"])
            mock_conn.execute.return_value = mock_cursor
            mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
            mock_conn.__aexit__ = AsyncMock(return_value=False)
            mock_connect.return_value = mock_conn

            resp = await client.get("/dashboard/findings")
            assert resp.status_code == 200
            assert "Findings Browser" in resp.text


# ---------------------------------------------------------------------------
# HTMX partial route tests
# ---------------------------------------------------------------------------


class TestPartials:
    async def test_stats_partial(self, client: httpx.AsyncClient) -> None:
        with patch(
            "security_scanner.dashboard.router.get_dashboard_stats",
            return_value=MOCK_STATS,
        ):
            resp = await client.get("/dashboard/partials/stats")
            assert resp.status_code == 200
            assert "10" in resp.text

    async def test_scan_table_partial(self, client: httpx.AsyncClient) -> None:
        with patch(
            "security_scanner.dashboard.router.list_scans_paginated",
            return_value=([_make_scan()], 1),
        ):
            resp = await client.get("/dashboard/partials/scan-table")
            assert resp.status_code == 200
            assert "scan-001" in resp.text

    async def test_scan_status_partial(self, client: httpx.AsyncClient, mock_db: AsyncMock) -> None:
        mock_db.get_scan.return_value = _make_scan(status="running")
        resp = await client.get("/dashboard/partials/scan-status/scan-001")
        assert resp.status_code == 200
        assert "running" in resp.text

    async def test_scan_status_not_found(
        self, client: httpx.AsyncClient, mock_db: AsyncMock
    ) -> None:
        mock_db.get_scan.return_value = None
        resp = await client.get("/dashboard/partials/scan-status/nonexistent")
        assert resp.status_code == 404

    async def test_scan_findings_partial(
        self, client: httpx.AsyncClient, mock_db: AsyncMock
    ) -> None:
        with patch(
            "security_scanner.dashboard.router.list_findings_filtered",
            return_value=([_make_finding()], 1),
        ):
            resp = await client.get("/dashboard/partials/scan-findings/scan-001")
            assert resp.status_code == 200
            assert "CRITICAL" in resp.text

    async def test_findings_partial(self, client: httpx.AsyncClient) -> None:
        with patch(
            "security_scanner.dashboard.router.list_findings_filtered",
            return_value=([_make_finding()], 1),
        ):
            resp = await client.get("/dashboard/partials/findings")
            assert resp.status_code == 200
            assert "example.com" in resp.text


# ---------------------------------------------------------------------------
# Form handler tests
# ---------------------------------------------------------------------------


class TestCreateScan:
    async def test_create_scan_success(self, client: httpx.AsyncClient, mock_db: AsyncMock) -> None:
        mock_db.create_scan.return_value = "scan-new"
        resp = await client.post(
            "/dashboard/scans/new",
            data={"domains": "example.com\ntest.com"},
        )
        assert resp.status_code == 200
        assert "scan-new" in resp.text
        assert "Scan started" in resp.text

    async def test_create_scan_empty_domains(self, client: httpx.AsyncClient) -> None:
        resp = await client.post(
            "/dashboard/scans/new",
            data={"domains": "   \n   "},
        )
        assert resp.status_code == 200
        assert "No domains provided" in resp.text

    async def test_create_scan_invalid_domain(
        self,
        client: httpx.AsyncClient,
    ) -> None:
        resp = await client.post(
            "/dashboard/scans/new",
            data={"domains": "not a valid domain!!!"},
        )
        assert resp.status_code == 200
        assert "Invalid domain" in resp.text


# ---------------------------------------------------------------------------
# Query integration tests (in-memory SQLite)
# ---------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE scans (
    id TEXT PRIMARY KEY,
    start_time TIMESTAMP NOT NULL,
    end_time TIMESTAMP,
    duration_seconds INTEGER,
    domains_scanned TEXT NOT NULL,
    status TEXT NOT NULL,
    scanner_version TEXT NOT NULL,
    total_findings INTEGER DEFAULT 0,
    critical_findings INTEGER DEFAULT 0,
    high_findings INTEGER DEFAULT 0,
    medium_findings INTEGER DEFAULT 0,
    low_findings INTEGER DEFAULT 0
);
CREATE TABLE findings (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    type TEXT NOT NULL,
    domain TEXT NOT NULL,
    record_type TEXT,
    target TEXT,
    description TEXT NOT NULL,
    cvss_score REAL,
    remediation TEXT NOT NULL,
    raw_data TEXT NOT NULL,
    detected_at TIMESTAMP NOT NULL,
    first_seen TIMESTAMP NOT NULL,
    alerted BOOLEAN DEFAULT 0,
    platform TEXT,
    confidence REAL DEFAULT 1.0,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
"""


@pytest.fixture
async def query_db(tmp_path: Any) -> AsyncGenerator[MagicMock, None]:
    """Create a real SQLite database for query tests."""
    import aiosqlite

    db_path = tmp_path / "test_queries.db"
    async with aiosqlite.connect(db_path) as conn:
        await conn.executescript(SCHEMA)
        now = datetime.now(UTC).isoformat()
        await conn.execute(
            "INSERT INTO scans VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            ("s1", now, now, 120, '["example.com"]', "completed", "0.1.0", 2, 1, 1, 0, 0),
        )
        await conn.execute(
            "INSERT INTO scans VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            ("s2", now, None, None, '["test.com"]', "running", "0.1.0", 0, 0, 0, 0, 0),
        )
        await conn.execute(
            "INSERT INTO findings VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "f1",
                "s1",
                "CRITICAL",
                "dangling_dns",
                "example.com",
                "CNAME",
                "old.cdn.example.com",
                "Dangling CNAME",
                9.8,
                "Remove record",
                "{}",
                now,
                now,
                0,
                "aws",
                0.95,
            ),
        )
        await conn.execute(
            "INSERT INTO findings VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "f2",
                "s1",
                "HIGH",
                "cert_risk",
                "example.com",
                "A",
                "1.2.3.4",
                "Certificate issue",
                7.5,
                "Renew cert",
                "{}",
                now,
                now,
                0,
                "aws",
                0.9,
            ),
        )
        await conn.commit()

    fake_db = MagicMock()
    fake_db.db_path = db_path
    yield fake_db


class TestDashboardQueries:
    async def test_get_dashboard_stats(self, query_db: MagicMock) -> None:
        from security_scanner.dashboard.queries import get_dashboard_stats

        stats = await get_dashboard_stats(query_db)
        assert stats["total_scans"] == 2
        assert stats["running_scans"] == 1
        assert stats["total_findings"] == 2
        severity = stats["findings_by_severity"]
        assert isinstance(severity, dict)
        assert severity["CRITICAL"] == 1
        assert severity["HIGH"] == 1

    async def test_list_scans_paginated(self, query_db: MagicMock) -> None:
        from security_scanner.dashboard.queries import list_scans_paginated

        scans, total = await list_scans_paginated(query_db, limit=10, offset=0)
        assert total == 2
        assert len(scans) == 2
        assert scans[0].id in ("s1", "s2")

    async def test_list_scans_paginated_offset(self, query_db: MagicMock) -> None:
        from security_scanner.dashboard.queries import list_scans_paginated

        scans, total = await list_scans_paginated(query_db, limit=1, offset=1)
        assert total == 2
        assert len(scans) == 1

    async def test_list_findings_filtered_no_filter(self, query_db: MagicMock) -> None:
        from security_scanner.dashboard.queries import list_findings_filtered

        findings, total = await list_findings_filtered(query_db)
        assert total == 2
        assert len(findings) == 2

    async def test_list_findings_filtered_by_severity(self, query_db: MagicMock) -> None:
        from security_scanner.dashboard.queries import list_findings_filtered

        findings, total = await list_findings_filtered(query_db, severity="CRITICAL")
        assert total == 1
        assert findings[0].severity == "CRITICAL"

    async def test_list_findings_filtered_by_domain(self, query_db: MagicMock) -> None:
        from security_scanner.dashboard.queries import list_findings_filtered

        findings, total = await list_findings_filtered(query_db, domain="example")
        assert total == 2

    async def test_list_findings_filtered_by_type(self, query_db: MagicMock) -> None:
        from security_scanner.dashboard.queries import list_findings_filtered

        findings, total = await list_findings_filtered(query_db, finding_type="dangling_dns")
        assert total == 1
        assert findings[0].type == "dangling_dns"

    async def test_list_findings_filtered_by_scan_id(self, query_db: MagicMock) -> None:
        from security_scanner.dashboard.queries import list_findings_filtered

        findings, total = await list_findings_filtered(query_db, scan_id="s1")
        assert total == 2

    async def test_list_findings_filtered_no_match(self, query_db: MagicMock) -> None:
        from security_scanner.dashboard.queries import list_findings_filtered

        findings, total = await list_findings_filtered(query_db, severity="LOW")
        assert total == 0
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Helper for async iteration in mocks
# ---------------------------------------------------------------------------


async def aiter_rows(values: list[Any]) -> AsyncGenerator[tuple[Any], None]:
    for v in values:
        yield (v,)
