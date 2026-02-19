# Copyright (c) 2024 Veritas Aequitas Holdings LLC
# All rights reserved.

"""Unit tests for CLI interface (main.py)."""

import asyncio
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from security_scanner.main import app
from security_scanner.storage.models import Scan

runner = CliRunner()


def _mock_asyncio_run(coro):
    """Helper to properly close a coroutine passed to a mocked asyncio.run.

    When we mock asyncio.run, the real coroutine is still created by the
    caller.  If we just discard it, Python emits 'coroutine was never
    awaited' warnings that pytest turns into hard errors.  This helper
    closes the coroutine cleanly so no warnings are raised.
    """
    if asyncio.iscoroutine(coro):
        coro.close()
    return None


# ---------------------------------------------------------------------------
# Version flag
# ---------------------------------------------------------------------------


class TestVersionFlag:
    """Tests for the --version flag."""

    def test_version_flag_shows_version(self) -> None:
        """Test that --version prints the version string and exits."""
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "Security Scanner v" in result.output

    def test_version_short_flag(self) -> None:
        """Test that -v prints the version string and exits."""
        result = runner.invoke(app, ["-v"])
        assert result.exit_code == 0
        assert "Security Scanner v" in result.output

    def test_version_contains_semver(self) -> None:
        """Test that version output contains a semantic version number."""
        from security_scanner import __version__

        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert __version__ in result.output


# ---------------------------------------------------------------------------
# Scan command
# ---------------------------------------------------------------------------


class TestScanCommand:
    """Tests for the scan command."""

    @patch("security_scanner.main.load_settings")
    def test_scan_no_domains_shows_error(self, mock_load_settings: MagicMock) -> None:
        """Test that scan with no domains shows an error message."""
        mock_settings = MagicMock()
        mock_settings.log_level = "INFO"
        mock_settings.log_file = None
        mock_settings.log_format = "console"
        mock_settings.debug = False
        mock_load_settings.return_value = mock_settings

        result = runner.invoke(app, ["scan"])
        assert result.exit_code == 1
        assert "No domains specified" in result.output

    @patch("security_scanner.main.asyncio")
    @patch("security_scanner.main.load_settings")
    def test_scan_with_single_domain(
        self, mock_load_settings: MagicMock, mock_asyncio: MagicMock
    ) -> None:
        """Test scan command with a single --domain option."""
        mock_settings = MagicMock()
        mock_settings.log_level = "INFO"
        mock_settings.log_file = None
        mock_settings.log_format = "console"
        mock_settings.debug = False
        mock_load_settings.return_value = mock_settings
        mock_asyncio.run.side_effect = _mock_asyncio_run

        result = runner.invoke(app, ["scan", "--domain", "example.com"])
        assert result.exit_code == 0
        assert "Scanning 1 domain(s)" in result.output
        mock_asyncio.run.assert_called_once()

    @patch("security_scanner.main.asyncio")
    @patch("security_scanner.main.load_settings")
    def test_scan_with_multiple_domains(
        self, mock_load_settings: MagicMock, mock_asyncio: MagicMock
    ) -> None:
        """Test scan command with multiple --domain options."""
        mock_settings = MagicMock()
        mock_settings.log_level = "INFO"
        mock_settings.log_file = None
        mock_settings.log_format = "console"
        mock_settings.debug = False
        mock_load_settings.return_value = mock_settings
        mock_asyncio.run.side_effect = _mock_asyncio_run

        result = runner.invoke(app, ["scan", "--domain", "example.com", "--domain", "test.com"])
        assert result.exit_code == 0
        assert "Scanning 2 domain(s)" in result.output

    @patch("security_scanner.main.asyncio")
    @patch("security_scanner.main.load_settings")
    def test_scan_with_domains_file(
        self, mock_load_settings: MagicMock, mock_asyncio: MagicMock, tmp_path: Path
    ) -> None:
        """Test scan command with --domains-file option."""
        mock_settings = MagicMock()
        mock_settings.log_level = "INFO"
        mock_settings.log_file = None
        mock_settings.log_format = "console"
        mock_settings.debug = False
        mock_load_settings.return_value = mock_settings
        mock_asyncio.run.side_effect = _mock_asyncio_run

        domains_file = tmp_path / "domains.txt"
        domains_file.write_text("example.com\ntest.com\n# comment line\n\nextra.com\n")

        result = runner.invoke(app, ["scan", "--domains-file", str(domains_file)])
        assert result.exit_code == 0
        assert "Scanning 3 domain(s)" in result.output

    @patch("security_scanner.main.load_settings")
    def test_scan_with_nonexistent_domains_file(
        self, mock_load_settings: MagicMock, tmp_path: Path
    ) -> None:
        """Test scan command with a domains file that does not exist."""
        mock_settings = MagicMock()
        mock_settings.log_level = "INFO"
        mock_settings.log_file = None
        mock_settings.log_format = "console"
        mock_settings.debug = False
        mock_load_settings.return_value = mock_settings

        nonexistent_file = tmp_path / "nonexistent.txt"

        result = runner.invoke(app, ["scan", "--domains-file", str(nonexistent_file)])
        assert result.exit_code == 1
        assert "Domains file not found" in result.output

    @patch("security_scanner.main.asyncio")
    @patch("security_scanner.main.load_settings")
    def test_scan_with_domain_and_domains_file(
        self, mock_load_settings: MagicMock, mock_asyncio: MagicMock, tmp_path: Path
    ) -> None:
        """Test scan with both --domain and --domains-file combines them."""
        mock_settings = MagicMock()
        mock_settings.log_level = "INFO"
        mock_settings.log_file = None
        mock_settings.log_format = "console"
        mock_settings.debug = False
        mock_load_settings.return_value = mock_settings
        mock_asyncio.run.side_effect = _mock_asyncio_run

        domains_file = tmp_path / "domains.txt"
        domains_file.write_text("file-domain.com\n")

        result = runner.invoke(
            app,
            [
                "scan",
                "--domain",
                "cli-domain.com",
                "--domains-file",
                str(domains_file),
            ],
        )
        assert result.exit_code == 0
        assert "Scanning 2 domain(s)" in result.output

    @patch("security_scanner.main.load_settings")
    def test_scan_with_empty_domains_file(
        self, mock_load_settings: MagicMock, tmp_path: Path
    ) -> None:
        """Test scan with a domains file that contains only comments and blank lines."""
        mock_settings = MagicMock()
        mock_settings.log_level = "INFO"
        mock_settings.log_file = None
        mock_settings.log_format = "console"
        mock_settings.debug = False
        mock_load_settings.return_value = mock_settings

        domains_file = tmp_path / "empty_domains.txt"
        domains_file.write_text("# only comments\n\n# another comment\n")

        result = runner.invoke(app, ["scan", "--domains-file", str(domains_file)])
        assert result.exit_code == 1
        assert "No domains specified" in result.output

    @patch("security_scanner.main.asyncio")
    @patch("security_scanner.main.load_settings")
    def test_scan_exception_shows_error(
        self, mock_load_settings: MagicMock, mock_asyncio: MagicMock
    ) -> None:
        """Test that scan handles exceptions from _run_scan gracefully."""
        mock_settings = MagicMock()
        mock_settings.log_level = "INFO"
        mock_settings.log_file = None
        mock_settings.log_format = "console"
        mock_settings.debug = False
        mock_load_settings.return_value = mock_settings

        def _raise_after_close(coro):
            if asyncio.iscoroutine(coro):
                coro.close()
            raise RuntimeError("Connection failed")

        mock_asyncio.run.side_effect = _raise_after_close

        result = runner.invoke(app, ["scan", "--domain", "example.com"])
        assert result.exit_code == 1
        assert "Connection failed" in result.output

    @patch("security_scanner.main.asyncio")
    @patch("security_scanner.main.load_settings")
    def test_scan_keyboard_interrupt(
        self, mock_load_settings: MagicMock, mock_asyncio: MagicMock
    ) -> None:
        """Test that scan handles KeyboardInterrupt gracefully."""
        mock_settings = MagicMock()
        mock_settings.log_level = "INFO"
        mock_settings.log_file = None
        mock_settings.log_format = "console"
        mock_settings.debug = False
        mock_load_settings.return_value = mock_settings

        def _interrupt_after_close(coro):
            if asyncio.iscoroutine(coro):
                coro.close()
            raise KeyboardInterrupt()

        mock_asyncio.run.side_effect = _interrupt_after_close

        result = runner.invoke(app, ["scan", "--domain", "example.com"])
        assert result.exit_code == 130
        assert "interrupted by user" in result.output

    @patch("security_scanner.main.asyncio")
    @patch("security_scanner.main.load_settings")
    def test_scan_verbose_flag(
        self, mock_load_settings: MagicMock, mock_asyncio: MagicMock
    ) -> None:
        """Test scan with --verbose flag sets up debug logging."""
        mock_settings = MagicMock()
        mock_settings.log_level = "INFO"
        mock_settings.log_file = None
        mock_settings.log_format = "console"
        mock_settings.debug = False
        mock_load_settings.return_value = mock_settings
        mock_asyncio.run.side_effect = _mock_asyncio_run

        result = runner.invoke(app, ["scan", "--domain", "example.com", "--verbose"])
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# Init-db command
# ---------------------------------------------------------------------------


class TestInitDbCommand:
    """Tests for the init-db command."""

    @patch("security_scanner.main.asyncio")
    @patch("security_scanner.main.DatabaseManager")
    @patch("security_scanner.main.load_settings")
    def test_init_db_success(
        self,
        mock_load_settings: MagicMock,
        mock_db_class: MagicMock,
        mock_asyncio: MagicMock,
    ) -> None:
        """Test successful database initialization."""
        mock_settings = MagicMock()
        mock_settings.database_path = Path("/tmp/test.db")
        mock_load_settings.return_value = mock_settings
        mock_asyncio.run.side_effect = _mock_asyncio_run

        result = runner.invoke(app, ["init-db"])
        assert result.exit_code == 0
        assert "Initializing database" in result.output
        assert "Database initialized" in result.output

    @patch("security_scanner.main.asyncio")
    @patch("security_scanner.main.DatabaseManager")
    @patch("security_scanner.main.load_settings")
    def test_init_db_error(
        self,
        mock_load_settings: MagicMock,
        mock_db_class: MagicMock,
        mock_asyncio: MagicMock,
    ) -> None:
        """Test database initialization failure shows error."""
        mock_settings = MagicMock()
        mock_settings.database_path = Path("/tmp/test.db")
        mock_load_settings.return_value = mock_settings

        def _raise_after_close(coro):
            if asyncio.iscoroutine(coro):
                coro.close()
            raise PermissionError("Permission denied")

        mock_asyncio.run.side_effect = _raise_after_close

        result = runner.invoke(app, ["init-db"])
        assert result.exit_code == 1
        assert "Permission denied" in result.output

    @patch("security_scanner.main.DatabaseManager")
    @patch("security_scanner.main.load_settings")
    def test_init_db_constructor_error(
        self,
        mock_load_settings: MagicMock,
        mock_db_class: MagicMock,
    ) -> None:
        """Test database initialization when constructor raises."""
        mock_settings = MagicMock()
        mock_settings.database_path = Path("/tmp/test.db")
        mock_load_settings.return_value = mock_settings
        mock_db_class.side_effect = ValueError("Invalid path")

        result = runner.invoke(app, ["init-db"])
        assert result.exit_code == 1
        assert "Invalid path" in result.output


# ---------------------------------------------------------------------------
# List-scans command
# ---------------------------------------------------------------------------


class TestListScansCommand:
    """Tests for the list-scans command."""

    @patch("security_scanner.main.asyncio")
    @patch("security_scanner.main.DatabaseManager")
    @patch("security_scanner.main.load_settings")
    def test_list_scans_with_results(
        self,
        mock_load_settings: MagicMock,
        mock_db_class: MagicMock,
        mock_asyncio: MagicMock,
    ) -> None:
        """Test list-scans displays scan records in a table."""
        mock_settings = MagicMock()
        mock_settings.database_path = Path("/tmp/test.db")
        mock_load_settings.return_value = mock_settings

        scan = Scan(
            id="abcdefgh-1234-5678-9012-abcdefghijkl",
            start_time=datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC),
            status="completed",
            domains_scanned=["example.com", "test.com"],
            total_findings=5,
        )
        mock_asyncio.run.return_value = [scan]

        result = runner.invoke(app, ["list-scans"])
        assert result.exit_code == 0
        assert "abcdefgh" in result.output
        assert "completed" in result.output

    @patch("security_scanner.main.asyncio")
    @patch("security_scanner.main.DatabaseManager")
    @patch("security_scanner.main.load_settings")
    def test_list_scans_empty(
        self,
        mock_load_settings: MagicMock,
        mock_db_class: MagicMock,
        mock_asyncio: MagicMock,
    ) -> None:
        """Test list-scans with no scans found."""
        mock_settings = MagicMock()
        mock_settings.database_path = Path("/tmp/test.db")
        mock_load_settings.return_value = mock_settings
        mock_asyncio.run.return_value = []

        result = runner.invoke(app, ["list-scans"])
        assert result.exit_code == 0
        assert "No scans found" in result.output

    @patch("security_scanner.main.asyncio")
    @patch("security_scanner.main.DatabaseManager")
    @patch("security_scanner.main.load_settings")
    def test_list_scans_with_custom_limit(
        self,
        mock_load_settings: MagicMock,
        mock_db_class: MagicMock,
        mock_asyncio: MagicMock,
    ) -> None:
        """Test list-scans with a custom --limit option."""
        mock_settings = MagicMock()
        mock_settings.database_path = Path("/tmp/test.db")
        mock_load_settings.return_value = mock_settings

        scan = Scan(
            id="abcdefgh-1234-5678-9012-abcdefghijkl",
            start_time=datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC),
            status="completed",
            domains_scanned=["example.com"],
            total_findings=3,
        )
        mock_asyncio.run.return_value = [scan]

        result = runner.invoke(app, ["list-scans", "--limit", "5"])
        assert result.exit_code == 0
        assert "Last 5" in result.output

    @patch("security_scanner.main.asyncio")
    @patch("security_scanner.main.DatabaseManager")
    @patch("security_scanner.main.load_settings")
    def test_list_scans_error(
        self,
        mock_load_settings: MagicMock,
        mock_db_class: MagicMock,
        mock_asyncio: MagicMock,
    ) -> None:
        """Test list-scans handles database errors."""
        mock_settings = MagicMock()
        mock_settings.database_path = Path("/tmp/test.db")
        mock_load_settings.return_value = mock_settings
        mock_asyncio.run.side_effect = RuntimeError("Database corrupted")

        result = runner.invoke(app, ["list-scans"])
        assert result.exit_code == 1
        assert "Database corrupted" in result.output

    @patch("security_scanner.main.asyncio")
    @patch("security_scanner.main.DatabaseManager")
    @patch("security_scanner.main.load_settings")
    def test_list_scans_multiple_results(
        self,
        mock_load_settings: MagicMock,
        mock_db_class: MagicMock,
        mock_asyncio: MagicMock,
    ) -> None:
        """Test list-scans with multiple scan records."""
        mock_settings = MagicMock()
        mock_settings.database_path = Path("/tmp/test.db")
        mock_load_settings.return_value = mock_settings

        scans = [
            Scan(
                id="aaaaaaaa-1111-2222-3333-aaaaaaaaaaaa",
                start_time=datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC),
                status="completed",
                domains_scanned=["example.com"],
                total_findings=5,
            ),
            Scan(
                id="bbbbbbbb-4444-5555-6666-bbbbbbbbbbbb",
                start_time=datetime(2024, 1, 14, 8, 0, 0, tzinfo=UTC),
                status="running",
                domains_scanned=["test.com", "other.com"],
                total_findings=0,
            ),
        ]
        mock_asyncio.run.return_value = scans

        result = runner.invoke(app, ["list-scans"])
        assert result.exit_code == 0
        assert "aaaaaaaa" in result.output
        assert "bbbbbbbb" in result.output


# ---------------------------------------------------------------------------
# Report command
# ---------------------------------------------------------------------------


class TestReportCommand:
    """Tests for the report command."""

    @patch("security_scanner.main.asyncio")
    @patch("security_scanner.main.load_settings")
    def test_report_success(
        self, mock_load_settings: MagicMock, mock_asyncio: MagicMock, tmp_path: Path
    ) -> None:
        """Test successful report generation."""
        mock_settings = MagicMock()
        mock_settings.report_output_dir = tmp_path / "reports"
        mock_load_settings.return_value = mock_settings
        mock_asyncio.run.side_effect = _mock_asyncio_run

        result = runner.invoke(
            app,
            ["report", "--scan-id", "test-scan-123", "--output", str(tmp_path)],
        )
        assert result.exit_code == 0

    @patch("security_scanner.main.asyncio")
    @patch("security_scanner.main.load_settings")
    def test_report_with_default_output_dir(
        self, mock_load_settings: MagicMock, mock_asyncio: MagicMock, tmp_path: Path
    ) -> None:
        """Test report generation uses settings output dir when not specified."""
        mock_settings = MagicMock()
        mock_settings.report_output_dir = tmp_path / "default_reports"
        mock_load_settings.return_value = mock_settings
        mock_asyncio.run.side_effect = _mock_asyncio_run

        result = runner.invoke(app, ["report", "--scan-id", "test-scan-123"])
        assert result.exit_code == 0

    @patch("security_scanner.main.load_settings")
    def test_report_invalid_format(self, mock_load_settings: MagicMock, tmp_path: Path) -> None:
        """Test report with invalid format shows error."""
        mock_settings = MagicMock()
        mock_settings.report_output_dir = tmp_path / "reports"
        mock_load_settings.return_value = mock_settings

        result = runner.invoke(
            app,
            [
                "report",
                "--scan-id",
                "test-scan-123",
                "--format",
                "pdf",
                "--output",
                str(tmp_path),
            ],
        )
        assert result.exit_code == 1
        assert "Invalid format" in result.output
        assert "pdf" in result.output

    @patch("security_scanner.main.load_settings")
    def test_report_multiple_invalid_formats(
        self, mock_load_settings: MagicMock, tmp_path: Path
    ) -> None:
        """Test report with multiple invalid formats lists all of them."""
        mock_settings = MagicMock()
        mock_settings.report_output_dir = tmp_path / "reports"
        mock_load_settings.return_value = mock_settings

        result = runner.invoke(
            app,
            [
                "report",
                "--scan-id",
                "test-scan-123",
                "--format",
                "pdf,docx",
                "--output",
                str(tmp_path),
            ],
        )
        assert result.exit_code == 1
        assert "Invalid format" in result.output

    @patch("security_scanner.main.asyncio")
    @patch("security_scanner.main.load_settings")
    def test_report_error_during_generation(
        self, mock_load_settings: MagicMock, mock_asyncio: MagicMock, tmp_path: Path
    ) -> None:
        """Test report handles errors during generation."""
        mock_settings = MagicMock()
        mock_settings.report_output_dir = tmp_path / "reports"
        mock_load_settings.return_value = mock_settings

        def _raise_after_close(coro):
            if asyncio.iscoroutine(coro):
                coro.close()
            raise RuntimeError("Scan not found in database")

        mock_asyncio.run.side_effect = _raise_after_close

        result = runner.invoke(
            app,
            ["report", "--scan-id", "nonexistent-id", "--output", str(tmp_path)],
        )
        assert result.exit_code == 1
        assert "Scan not found in database" in result.output

    def test_report_missing_scan_id(self) -> None:
        """Test report command requires --scan-id option."""
        result = runner.invoke(app, ["report"])
        assert result.exit_code == 2

    @patch("security_scanner.main.asyncio")
    @patch("security_scanner.main.load_settings")
    def test_report_valid_formats(
        self, mock_load_settings: MagicMock, mock_asyncio: MagicMock, tmp_path: Path
    ) -> None:
        """Test report with all valid format types."""
        mock_settings = MagicMock()
        mock_settings.report_output_dir = tmp_path / "reports"
        mock_load_settings.return_value = mock_settings
        mock_asyncio.run.side_effect = _mock_asyncio_run

        result = runner.invoke(
            app,
            [
                "report",
                "--scan-id",
                "test-scan-123",
                "--format",
                "html,json,markdown,csv",
                "--output",
                str(tmp_path),
            ],
        )
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# Validate-config command
# ---------------------------------------------------------------------------


class TestValidateConfigCommand:
    """Tests for the validate-config command."""

    @patch("security_scanner.main.load_settings")
    def test_validate_config_success(self, mock_load_settings: MagicMock) -> None:
        """Test validate-config with valid configuration."""
        mock_settings = MagicMock()
        mock_settings.database_path = Path("/tmp/test.db")
        mock_settings.log_level = "INFO"
        mock_settings.dns_nameservers = ["8.8.8.8", "1.1.1.1"]
        mock_settings.subdomain_sources = ["crtsh", "subfinder"]
        mock_load_settings.return_value = mock_settings

        result = runner.invoke(app, ["validate-config"])
        assert result.exit_code == 0
        assert "Configuration is valid" in result.output
        assert "Database" in result.output
        assert "Log level" in result.output
        assert "DNS nameservers" in result.output
        assert "Subdomain sources" in result.output

    @patch("security_scanner.main.load_settings")
    def test_validate_config_shows_settings_values(self, mock_load_settings: MagicMock) -> None:
        """Test validate-config displays actual settings values."""
        mock_settings = MagicMock()
        mock_settings.database_path = Path("data/security_scanner.db")
        mock_settings.log_level = "DEBUG"
        mock_settings.dns_nameservers = ["8.8.8.8"]
        mock_settings.subdomain_sources = ["crtsh"]
        mock_load_settings.return_value = mock_settings

        result = runner.invoke(app, ["validate-config"])
        assert result.exit_code == 0
        assert "DEBUG" in result.output
        assert "8.8.8.8" in result.output
        assert "crtsh" in result.output

    @patch("security_scanner.main.load_settings")
    def test_validate_config_error(self, mock_load_settings: MagicMock) -> None:
        """Test validate-config with invalid configuration shows error."""
        mock_load_settings.side_effect = ValueError("Invalid DNS nameserver format")

        result = runner.invoke(app, ["validate-config"])
        assert result.exit_code == 1
        assert "Configuration error" in result.output
        assert "Invalid DNS nameserver format" in result.output

    @patch("security_scanner.main.load_settings")
    def test_validate_config_file_not_found(self, mock_load_settings: MagicMock) -> None:
        """Test validate-config when config file cannot be loaded."""
        mock_load_settings.side_effect = FileNotFoundError("Config file not found")

        result = runner.invoke(app, ["validate-config"])
        assert result.exit_code == 1
        assert "Configuration error" in result.output


# ---------------------------------------------------------------------------
# Help output
# ---------------------------------------------------------------------------


class TestHelpOutput:
    """Tests for help text output."""

    def test_main_help(self) -> None:
        """Test that main --help shows app description."""
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "security" in result.output.lower()

    def test_scan_help(self) -> None:
        """Test that scan --help shows command description."""
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0
        assert "domain" in result.output.lower()

    def test_report_help(self) -> None:
        """Test that report --help shows command description."""
        result = runner.invoke(app, ["report", "--help"])
        assert result.exit_code == 0
        assert "report" in result.output.lower()

    def test_init_db_help(self) -> None:
        """Test that init-db --help shows command description."""
        result = runner.invoke(app, ["init-db", "--help"])
        assert result.exit_code == 0
        assert "database" in result.output.lower()

    def test_list_scans_help(self) -> None:
        """Test that list-scans --help shows command description."""
        result = runner.invoke(app, ["list-scans", "--help"])
        assert result.exit_code == 0
        assert "scan" in result.output.lower()

    def test_validate_config_help(self) -> None:
        """Test that validate-config --help shows command description."""
        result = runner.invoke(app, ["validate-config", "--help"])
        assert result.exit_code == 0
        assert "config" in result.output.lower()
