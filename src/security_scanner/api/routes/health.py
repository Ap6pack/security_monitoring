"""Health check and configuration endpoints."""

from fastapi import APIRouter, Depends

from security_scanner import __version__
from security_scanner.api.auth import verify_api_key
from security_scanner.api.dependencies import get_db, get_settings
from security_scanner.api.models import ConfigValidationResponse, HealthResponse
from security_scanner.config import Settings
from security_scanner.storage.database import DatabaseManager
from security_scanner.utils.logger import get_logger

logger = get_logger(__name__)

router = APIRouter(
    tags=["health"],
)


@router.get(
    "/health",
    response_model=HealthResponse,
)
async def health_check(
    db: DatabaseManager = Depends(get_db),
) -> HealthResponse:
    """Health check endpoint (no auth required)."""
    db_status = "connected"
    try:
        await db.list_scans(limit=1)
    except Exception:
        logger.warning("Health check: database unreachable")
        db_status = "unavailable"

    return HealthResponse(
        status="healthy" if db_status == "connected" else "degraded",
        version=__version__,
        database=db_status,
    )


@router.get(
    "/config/validate",
    response_model=ConfigValidationResponse,
    dependencies=[Depends(verify_api_key)],
)
async def validate_config(
    settings: Settings = Depends(get_settings),
) -> ConfigValidationResponse:
    """Validate current configuration."""
    return ConfigValidationResponse(
        valid=True,
        database_path=str(settings.database_path),
        log_level=settings.log_level,
        dns_nameservers=settings.dns_nameservers,
        subdomain_sources=settings.subdomain_sources,
    )
