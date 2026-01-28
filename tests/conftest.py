"""Pytest configuration and fixtures."""

from pathlib import Path

import pytest

from security_scanner.config import Settings
from security_scanner.storage.database import DatabaseManager


@pytest.fixture
def test_settings() -> Settings:
    """Create test settings."""
    return Settings(
        database_path=Path("data/test_security_scanner.db"),
        log_level="DEBUG",
        log_format="console",
        dns_nameservers=["8.8.8.8"],
        enable_cache=True,
    )


@pytest.fixture
async def test_db(tmp_path: Path) -> DatabaseManager:
    """Create test database."""
    db_path = tmp_path / "test.db"
    db = DatabaseManager(db_path)
    await db.initialize()
    return db
