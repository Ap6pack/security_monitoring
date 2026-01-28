"""Unit tests for reporters."""

from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

from security_scanner.reporters import (
    CSVReporter,
    HTMLReporter,
    JSONReporter,
    MarkdownReporter,
)


class MockFinding:
    """Mock finding for testing."""

    def __init__(self, severity: str = "HIGH", domain: str = "test.example.com") -> None:
        self.id = "test-finding-1"
        self.severity = severity
        self.type = "DANGLING_DNS"
        self.domain = domain
        self.title = "Test Finding"
        self.description = "This is a test finding description"
        self.cvss_score = 7.5
        self.remediation = "Fix the issue"
        self.detected_at = datetime.now()
        self.raw_data = {"test": "data"}


@pytest.fixture
def sample_scan_results() -> dict[str, Any]:
    """Create sample scan results for testing."""
    return {
        "scan_id": "test-scan-123",
        "domains": ["example.com", "test.com"],
        "findings": [
            MockFinding("CRITICAL", "api.example.com"),
            MockFinding("HIGH", "www.example.com"),
            MockFinding("MEDIUM", "test.com"),
        ],
        "summary": {
            "CRITICAL": 1,
            "HIGH": 1,
            "MEDIUM": 1,
            "LOW": 0,
        },
    }


class TestJSONReporter:
    """Test JSON reporter."""

    def test_get_file_extension(self) -> None:
        """Test file extension."""
        reporter = JSONReporter()
        assert reporter.get_file_extension() == ".json"

    def test_generate(self, sample_scan_results: dict[str, Any], tmp_path: Path) -> None:
        """Test JSON report generation."""
        reporter = JSONReporter()
        output_file = tmp_path / "report.json"

        reporter.generate(sample_scan_results, output_file)

        assert output_file.exists()
        content = output_file.read_text()
        assert "test-scan-123" in content
        assert "example.com" in content
        assert "CRITICAL" in content


class TestCSVReporter:
    """Test CSV reporter."""

    def test_get_file_extension(self) -> None:
        """Test file extension."""
        reporter = CSVReporter()
        assert reporter.get_file_extension() == ".csv"

    def test_generate(self, sample_scan_results: dict[str, Any], tmp_path: Path) -> None:
        """Test CSV report generation."""
        reporter = CSVReporter()
        output_file = tmp_path / "report.csv"

        reporter.generate(sample_scan_results, output_file)

        assert output_file.exists()
        content = output_file.read_text()
        assert "Severity" in content
        assert "CRITICAL" in content
        assert "api.example.com" in content


class TestMarkdownReporter:
    """Test Markdown reporter."""

    def test_get_file_extension(self) -> None:
        """Test file extension."""
        reporter = MarkdownReporter()
        assert reporter.get_file_extension() == ".md"

    def test_generate(self, sample_scan_results: dict[str, Any], tmp_path: Path) -> None:
        """Test Markdown report generation."""
        reporter = MarkdownReporter()
        output_file = tmp_path / "report.md"

        reporter.generate(sample_scan_results, output_file)

        assert output_file.exists()
        content = output_file.read_text()
        assert "# Security Scan Report" in content
        assert "test-scan-123" in content
        assert "CRITICAL" in content


class TestHTMLReporter:
    """Test HTML reporter."""

    def test_get_file_extension(self) -> None:
        """Test file extension."""
        reporter = HTMLReporter()
        assert reporter.get_file_extension() == ".html"

    def test_generate(self, sample_scan_results: dict[str, Any], tmp_path: Path) -> None:
        """Test HTML report generation."""
        reporter = HTMLReporter()
        output_file = tmp_path / "report.html"

        reporter.generate(sample_scan_results, output_file)

        assert output_file.exists()
        content = output_file.read_text()
        assert "<!DOCTYPE html>" in content
        assert "test-scan-123" in content
        assert "CRITICAL" in content
