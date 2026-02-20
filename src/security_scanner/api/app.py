"""FastAPI application factory."""

from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from security_scanner import __version__
from security_scanner.api.dependencies import lifespan
from security_scanner.api.routes import health, reports, scans
from security_scanner.dashboard.router import router as dashboard_router


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="Security Scanner API",
        description="REST API for cross-origin web attack vulnerability scanning",
        version=__version__,
        lifespan=lifespan,
    )

    app.include_router(scans.router, prefix="/api/v1")
    app.include_router(reports.router, prefix="/api/v1")
    app.include_router(health.router, prefix="/api/v1")

    # Web dashboard
    app.include_router(dashboard_router)
    static_dir = Path(__file__).resolve().parent.parent / "dashboard" / "static"
    app.mount("/dashboard/static", StaticFiles(directory=str(static_dir)), name="dashboard-static")

    return app
