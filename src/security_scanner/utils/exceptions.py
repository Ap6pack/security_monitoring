"""Custom exception hierarchy for the security scanner."""


class SecurityScannerError(Exception):
    """Base exception for all security scanner errors."""

    def __init__(self, message: str, details: dict[str, object] | None = None) -> None:
        """
        Initialize the exception.

        Args:
            message: Human-readable error message
            details: Additional context information
        """
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def __str__(self) -> str:
        """Return string representation of the error."""
        if self.details:
            return f"{self.message} | Details: {self.details}"
        return self.message


class ConfigurationError(SecurityScannerError):
    """Raised when there are configuration-related errors."""

    pass


class NetworkError(SecurityScannerError):
    """Raised when network operations fail."""

    def __init__(
        self,
        message: str,
        details: dict[str, object] | None = None,
        retry_count: int = 0,
    ) -> None:
        """
        Initialize network error.

        Args:
            message: Error message
            details: Additional context
            retry_count: Number of retries attempted
        """
        super().__init__(message, details)
        self.retry_count = retry_count


class DNSError(NetworkError):
    """Raised when DNS resolution fails."""

    def __init__(
        self,
        message: str,
        domain: str,
        query_type: str = "A",
        details: dict[str, object] | None = None,
    ) -> None:
        """
        Initialize DNS error.

        Args:
            message: Error message
            domain: The domain that failed to resolve
            query_type: Type of DNS query (A, AAAA, CNAME, etc.)
            details: Additional context
        """
        details = details or {}
        details.update({"domain": domain, "query_type": query_type})
        super().__init__(message, details)
        self.domain = domain
        self.query_type = query_type


class APIError(NetworkError):
    """Raised when external API calls fail."""

    def __init__(
        self,
        message: str,
        api_name: str,
        status_code: int | None = None,
        response_body: str | None = None,
        details: dict[str, object] | None = None,
    ) -> None:
        """
        Initialize API error.

        Args:
            message: Error message
            api_name: Name of the API that failed
            status_code: HTTP status code if applicable
            response_body: Response body from the API
            details: Additional context
        """
        details = details or {}
        details.update(
            {
                "api_name": api_name,
                "status_code": status_code,
                "response_body": response_body,
            }
        )
        super().__init__(message, details)
        self.api_name = api_name
        self.status_code = status_code
        self.response_body = response_body


class ValidationError(SecurityScannerError):
    """Raised when input validation fails."""

    def __init__(
        self,
        message: str,
        field: str | None = None,
        value: object = None,
        details: dict[str, object] | None = None,
    ) -> None:
        """
        Initialize validation error.

        Args:
            message: Error message
            field: Name of the field that failed validation
            value: The invalid value
            details: Additional context
        """
        details = details or {}
        if field:
            details["field"] = field
        if value is not None:
            details["value"] = str(value)
        super().__init__(message, details)
        self.field = field
        self.value = value


class DatabaseError(SecurityScannerError):
    """Raised when database operations fail."""

    pass


class ScannerError(SecurityScannerError):
    """Raised when scanner operations fail."""

    pass


class DetectorError(SecurityScannerError):
    """Raised when detector operations fail."""

    pass


class ReporterError(SecurityScannerError):
    """Raised when report generation fails."""

    pass


class AlerterError(SecurityScannerError):
    """Raised when alert sending fails."""

    pass
