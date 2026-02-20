"""Template context helpers for the dashboard."""

from datetime import UTC, datetime

SEVERITY_COLORS: dict[str, str] = {
    "CRITICAL": "#dc3545",
    "HIGH": "#fd7e14",
    "MEDIUM": "#ffc107",
    "LOW": "#198754",
}

STATUS_COLORS: dict[str, str] = {
    "running": "#0d6efd",
    "completed": "#198754",
    "failed": "#dc3545",
}


def severity_color(severity: str) -> str:
    """Return CSS color for a severity level."""
    return SEVERITY_COLORS.get(severity.upper(), "#6c757d")


def status_color(status: str) -> str:
    """Return CSS color for a scan status."""
    return STATUS_COLORS.get(status.lower(), "#6c757d")


def time_ago(dt: datetime | None) -> str:
    """Format a datetime as a human-readable relative time string."""
    if dt is None:
        return "—"
    now = datetime.now(UTC)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    delta = now - dt
    seconds = int(delta.total_seconds())
    if seconds < 0:
        return "just now"
    if seconds < 60:
        return f"{seconds}s ago"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes}m ago"
    hours = minutes // 60
    if hours < 24:
        return f"{hours}h ago"
    days = hours // 24
    return f"{days}d ago"


def format_duration(seconds: int | None) -> str:
    """Format duration in seconds to a human-readable string."""
    if seconds is None:
        return "—"
    if seconds < 60:
        return f"{seconds}s"
    minutes = seconds // 60
    remaining = seconds % 60
    if minutes < 60:
        return f"{minutes}m {remaining}s"
    hours = minutes // 60
    remaining_min = minutes % 60
    return f"{hours}h {remaining_min}m"


def truncate(text: str, length: int = 80) -> str:
    """Truncate text to a maximum length with ellipsis."""
    if len(text) <= length:
        return text
    return text[: length - 1] + "…"
