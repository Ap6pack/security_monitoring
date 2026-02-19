"""FastAPI application factory."""

from fastapi import FastAPI

from security_scanner import __version__
from security_scanner.api.dependencies import lifespan
from security_scanner.api.routes import health, reports, scans


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

    return app
