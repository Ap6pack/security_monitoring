"""FastAPI dependency injection for shared resources."""

from collections.abc import AsyncGenerator
from contextlib import AsyncExitStack, asynccontextmanager

from security_scanner.config import Settings, load_settings
from security_scanner.orchestrator import ScanOrchestrator
from security_scanner.storage.database import DatabaseManager


class AppState:
    """Shared application state managed across the API lifecycle."""

    def __init__(self) -> None:
        self.settings: Settings | None = None
        self.db: DatabaseManager | None = None
        self.orchestrator: ScanOrchestrator | None = None


app_state = AppState()


@asynccontextmanager
async def lifespan(_app: object) -> AsyncGenerator[None, None]:
    """Manage application startup and shutdown."""
    settings = load_settings()
    settings.ensure_directories()

    db = DatabaseManager(settings.database_path)
    await db.initialize()

    async with AsyncExitStack() as stack:
        orchestrator = ScanOrchestrator(settings=settings, db=db)
        await stack.enter_async_context(orchestrator)

        app_state.settings = settings
        app_state.db = db
        app_state.orchestrator = orchestrator

        yield

    app_state.settings = None
    app_state.db = None
    app_state.orchestrator = None


def get_settings() -> Settings:
    """Get application settings."""
    if app_state.settings is None:
        raise RuntimeError("App not initialized")
    return app_state.settings


def get_db() -> DatabaseManager:
    """Get database manager."""
    if app_state.db is None:
        raise RuntimeError("App not initialized")
    return app_state.db


def get_orchestrator() -> ScanOrchestrator:
    """Get scan orchestrator."""
    if app_state.orchestrator is None:
        raise RuntimeError("App not initialized")
    return app_state.orchestrator
