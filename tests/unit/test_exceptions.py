"""Unit tests for exceptions module."""

import pytest

from security_scanner.utils.exceptions import (
    AlerterError,
    APIError,
    ConfigurationError,
    DatabaseError,
    DetectorError,
    DNSError,
    NetworkError,
    ReporterError,
    ScannerError,
    SecurityScannerError,
    ValidationError,
)


class TestSecurityScannerError:
    """Test SecurityScannerError base class."""

    def test_init_with_message(self) -> None:
        """Test initialization with message only."""
        error = SecurityScannerError("something went wrong")
        assert error.message == "something went wrong"
        assert error.details == {}

    def test_init_with_details(self) -> None:
        """Test initialization with message and details."""
        details = {"key": "value", "count": 42}
        error = SecurityScannerError("something went wrong", details=details)
        assert error.message == "something went wrong"
        assert error.details == {"key": "value", "count": 42}

    def test_str_without_details(self) -> None:
        """Test string representation without details."""
        error = SecurityScannerError("something went wrong")
        assert str(error) == "something went wrong"

    def test_str_with_details(self) -> None:
        """Test string representation includes details."""
        details = {"key": "value"}
        error = SecurityScannerError("something went wrong", details=details)
        result = str(error)
        assert "something went wrong" in result
        assert "Details:" in result
        assert "key" in result

    def test_str_with_empty_details(self) -> None:
        """Test string representation with empty details dict."""
        error = SecurityScannerError("something went wrong", details={})
        assert str(error) == "something went wrong"

    def test_is_exception(self) -> None:
        """Test that SecurityScannerError is an Exception."""
        error = SecurityScannerError("test")
        assert isinstance(error, Exception)

    def test_can_be_raised_and_caught(self) -> None:
        """Test that the error can be raised and caught."""
        with pytest.raises(SecurityScannerError, match="test error"):
            raise SecurityScannerError("test error")

    def test_details_default_to_empty_dict(self) -> None:
        """Test that details defaults to empty dict when None."""
        error = SecurityScannerError("test", details=None)
        assert error.details == {}


class TestNetworkError:
    """Test NetworkError class."""

    def test_init_default_retry_count(self) -> None:
        """Test initialization with default retry count."""
        error = NetworkError("connection failed")
        assert error.message == "connection failed"
        assert error.retry_count == 0
        assert error.details == {}

    def test_init_with_retry_count(self) -> None:
        """Test initialization with custom retry count."""
        error = NetworkError("connection failed", retry_count=3)
        assert error.retry_count == 3

    def test_init_with_details_and_retry(self) -> None:
        """Test initialization with details and retry count."""
        details = {"host": "example.com"}
        error = NetworkError("timeout", details=details, retry_count=5)
        assert error.message == "timeout"
        assert error.details == {"host": "example.com"}
        assert error.retry_count == 5

    def test_is_security_scanner_error(self) -> None:
        """Test that NetworkError is a SecurityScannerError."""
        error = NetworkError("test")
        assert isinstance(error, SecurityScannerError)

    def test_is_exception(self) -> None:
        """Test that NetworkError is an Exception."""
        error = NetworkError("test")
        assert isinstance(error, Exception)


class TestDNSError:
    """Test DNSError class."""

    def test_init_with_required_params(self) -> None:
        """Test initialization with required parameters."""
        error = DNSError("resolution failed", domain="example.com")
        assert error.message == "resolution failed"
        assert error.domain == "example.com"
        assert error.query_type == "A"  # default

    def test_init_with_all_params(self) -> None:
        """Test initialization with all parameters."""
        error = DNSError(
            "resolution failed",
            domain="example.com",
            query_type="AAAA",
            details={"resolver": "8.8.8.8"},
        )
        assert error.domain == "example.com"
        assert error.query_type == "AAAA"
        assert "domain" in error.details
        assert "query_type" in error.details
        assert "resolver" in error.details

    def test_details_include_domain_and_query_type(self) -> None:
        """Test that details are populated with domain and query type."""
        error = DNSError("failed", domain="test.com", query_type="MX")
        assert error.details["domain"] == "test.com"
        assert error.details["query_type"] == "MX"

    def test_is_network_error(self) -> None:
        """Test that DNSError is a NetworkError."""
        error = DNSError("test", domain="test.com")
        assert isinstance(error, NetworkError)

    def test_is_security_scanner_error(self) -> None:
        """Test that DNSError is a SecurityScannerError."""
        error = DNSError("test", domain="test.com")
        assert isinstance(error, SecurityScannerError)

    def test_default_query_type_is_a(self) -> None:
        """Test that default query_type is 'A'."""
        error = DNSError("test", domain="test.com")
        assert error.query_type == "A"

    def test_details_merge_with_provided(self) -> None:
        """Test that provided details are merged with domain/query_type."""
        error = DNSError(
            "test",
            domain="test.com",
            query_type="CNAME",
            details={"extra": "info"},
        )
        assert error.details["extra"] == "info"
        assert error.details["domain"] == "test.com"
        assert error.details["query_type"] == "CNAME"

    def test_details_none_creates_new_dict(self) -> None:
        """Test that None details creates a new dict with domain info."""
        error = DNSError("test", domain="test.com", details=None)
        assert error.details == {"domain": "test.com", "query_type": "A"}


class TestAPIError:
    """Test APIError class."""

    def test_init_minimal(self) -> None:
        """Test initialization with minimal parameters."""
        error = APIError("api failed", api_name="shodan")
        assert error.message == "api failed"
        assert error.api_name == "shodan"
        assert error.status_code is None
        assert error.response_body is None

    def test_init_with_status_code(self) -> None:
        """Test initialization with HTTP status code."""
        error = APIError("rate limited", api_name="shodan", status_code=429)
        assert error.status_code == 429

    def test_init_with_response_body(self) -> None:
        """Test initialization with response body."""
        error = APIError(
            "api failed",
            api_name="crtsh",
            response_body='{"error": "not found"}',
        )
        assert error.response_body == '{"error": "not found"}'

    def test_init_with_all_params(self) -> None:
        """Test initialization with all parameters."""
        error = APIError(
            "api failed",
            api_name="shodan",
            status_code=500,
            response_body="Internal Server Error",
            details={"endpoint": "/search"},
        )
        assert error.api_name == "shodan"
        assert error.status_code == 500
        assert error.response_body == "Internal Server Error"
        assert "endpoint" in error.details
        assert "api_name" in error.details

    def test_details_include_api_info(self) -> None:
        """Test that details are populated with API information."""
        error = APIError(
            "failed", api_name="test_api", status_code=404, response_body="not found"
        )
        assert error.details["api_name"] == "test_api"
        assert error.details["status_code"] == 404
        assert error.details["response_body"] == "not found"

    def test_is_network_error(self) -> None:
        """Test that APIError is a NetworkError."""
        error = APIError("test", api_name="test")
        assert isinstance(error, NetworkError)

    def test_is_security_scanner_error(self) -> None:
        """Test that APIError is a SecurityScannerError."""
        error = APIError("test", api_name="test")
        assert isinstance(error, SecurityScannerError)

    def test_without_status_code(self) -> None:
        """Test that status_code defaults to None."""
        error = APIError("test", api_name="test")
        assert error.status_code is None
        assert error.details["status_code"] is None

    def test_without_response_body(self) -> None:
        """Test that response_body defaults to None."""
        error = APIError("test", api_name="test")
        assert error.response_body is None
        assert error.details["response_body"] is None


class TestValidationError:
    """Test ValidationError class."""

    def test_init_minimal(self) -> None:
        """Test initialization with message only."""
        error = ValidationError("invalid input")
        assert error.message == "invalid input"
        assert error.field is None
        assert error.value is None

    def test_init_with_field(self) -> None:
        """Test initialization with field name."""
        error = ValidationError("invalid", field="domain")
        assert error.field == "domain"
        assert error.details["field"] == "domain"

    def test_init_with_value(self) -> None:
        """Test initialization with invalid value."""
        error = ValidationError("invalid", value="not-a-domain")
        assert error.value == "not-a-domain"
        assert error.details["value"] == "not-a-domain"

    def test_init_with_field_and_value(self) -> None:
        """Test initialization with both field and value."""
        error = ValidationError("invalid", field="domain", value="bad..")
        assert error.field == "domain"
        assert error.value == "bad.."
        assert error.details["field"] == "domain"
        assert error.details["value"] == "bad.."

    def test_init_with_neither_field_nor_value(self) -> None:
        """Test initialization with neither field nor value."""
        error = ValidationError("invalid input")
        assert error.field is None
        assert error.value is None
        assert "field" not in error.details
        assert "value" not in error.details

    def test_value_converted_to_string_in_details(self) -> None:
        """Test that value is converted to string in details."""
        error = ValidationError("invalid", value=42)
        assert error.details["value"] == "42"
        assert error.value == 42  # Original value is preserved

    def test_value_none_not_in_details(self) -> None:
        """Test that None value is not added to details."""
        error = ValidationError("invalid", value=None)
        assert "value" not in error.details

    def test_is_security_scanner_error(self) -> None:
        """Test that ValidationError is a SecurityScannerError."""
        error = ValidationError("test")
        assert isinstance(error, SecurityScannerError)

    def test_is_not_network_error(self) -> None:
        """Test that ValidationError is NOT a NetworkError."""
        error = ValidationError("test")
        assert not isinstance(error, NetworkError)

    def test_with_details(self) -> None:
        """Test initialization with explicit details dict."""
        error = ValidationError("invalid", field="domain", details={"extra": "info"})
        assert error.details["extra"] == "info"
        assert error.details["field"] == "domain"


class TestConfigurationError:
    """Test ConfigurationError class."""

    def test_init(self) -> None:
        """Test initialization."""
        error = ConfigurationError("bad config")
        assert error.message == "bad config"

    def test_is_security_scanner_error(self) -> None:
        """Test inheritance."""
        error = ConfigurationError("test")
        assert isinstance(error, SecurityScannerError)

    def test_is_not_network_error(self) -> None:
        """Test that it is not a NetworkError."""
        error = ConfigurationError("test")
        assert not isinstance(error, NetworkError)

    def test_with_details(self) -> None:
        """Test with details dict."""
        error = ConfigurationError("bad config", details={"file": "config.yaml"})
        assert error.details["file"] == "config.yaml"


class TestDatabaseError:
    """Test DatabaseError class."""

    def test_init(self) -> None:
        """Test initialization."""
        error = DatabaseError("db failed")
        assert error.message == "db failed"

    def test_is_security_scanner_error(self) -> None:
        """Test inheritance."""
        error = DatabaseError("test")
        assert isinstance(error, SecurityScannerError)

    def test_with_details(self) -> None:
        """Test with details."""
        error = DatabaseError("query failed", details={"query": "SELECT *"})
        assert error.details["query"] == "SELECT *"


class TestScannerError:
    """Test ScannerError class."""

    def test_init(self) -> None:
        """Test initialization."""
        error = ScannerError("scan failed")
        assert error.message == "scan failed"

    def test_is_security_scanner_error(self) -> None:
        """Test inheritance."""
        error = ScannerError("test")
        assert isinstance(error, SecurityScannerError)


class TestDetectorError:
    """Test DetectorError class."""

    def test_init(self) -> None:
        """Test initialization."""
        error = DetectorError("detection failed")
        assert error.message == "detection failed"

    def test_is_security_scanner_error(self) -> None:
        """Test inheritance."""
        error = DetectorError("test")
        assert isinstance(error, SecurityScannerError)


class TestReporterError:
    """Test ReporterError class."""

    def test_init(self) -> None:
        """Test initialization."""
        error = ReporterError("report failed")
        assert error.message == "report failed"

    def test_is_security_scanner_error(self) -> None:
        """Test inheritance."""
        error = ReporterError("test")
        assert isinstance(error, SecurityScannerError)


class TestAlerterError:
    """Test AlerterError class."""

    def test_init(self) -> None:
        """Test initialization."""
        error = AlerterError("alert failed")
        assert error.message == "alert failed"

    def test_is_security_scanner_error(self) -> None:
        """Test inheritance."""
        error = AlerterError("test")
        assert isinstance(error, SecurityScannerError)


class TestExceptionHierarchy:
    """Test the complete exception hierarchy via isinstance checks."""

    def test_all_errors_are_exceptions(self) -> None:
        """Test all custom errors are standard Exceptions."""
        errors = [
            SecurityScannerError("test"),
            ConfigurationError("test"),
            NetworkError("test"),
            DNSError("test", domain="test.com"),
            APIError("test", api_name="test"),
            ValidationError("test"),
            DatabaseError("test"),
            ScannerError("test"),
            DetectorError("test"),
            ReporterError("test"),
            AlerterError("test"),
        ]
        for error in errors:
            assert isinstance(error, Exception), f"{type(error).__name__} is not an Exception"

    def test_all_errors_are_security_scanner_errors(self) -> None:
        """Test all custom errors derive from SecurityScannerError."""
        errors = [
            ConfigurationError("test"),
            NetworkError("test"),
            DNSError("test", domain="test.com"),
            APIError("test", api_name="test"),
            ValidationError("test"),
            DatabaseError("test"),
            ScannerError("test"),
            DetectorError("test"),
            ReporterError("test"),
            AlerterError("test"),
        ]
        for error in errors:
            assert isinstance(
                error, SecurityScannerError
            ), f"{type(error).__name__} is not a SecurityScannerError"

    def test_dns_error_is_network_error(self) -> None:
        """Test DNSError inherits from NetworkError."""
        error = DNSError("test", domain="test.com")
        assert isinstance(error, NetworkError)

    def test_api_error_is_network_error(self) -> None:
        """Test APIError inherits from NetworkError."""
        error = APIError("test", api_name="test")
        assert isinstance(error, NetworkError)

    def test_non_network_errors_are_not_network_errors(self) -> None:
        """Test that non-network errors are not NetworkError instances."""
        non_network = [
            ConfigurationError("test"),
            ValidationError("test"),
            DatabaseError("test"),
            ScannerError("test"),
            DetectorError("test"),
            ReporterError("test"),
            AlerterError("test"),
        ]
        for error in non_network:
            assert not isinstance(
                error, NetworkError
            ), f"{type(error).__name__} should not be a NetworkError"

    def test_catch_base_catches_all(self) -> None:
        """Test catching SecurityScannerError catches all custom errors."""
        with pytest.raises(SecurityScannerError):
            raise ConfigurationError("test")

        with pytest.raises(SecurityScannerError):
            raise DNSError("test", domain="test.com")

        with pytest.raises(SecurityScannerError):
            raise ValidationError("test")
