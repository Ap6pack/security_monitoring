"""API key authentication middleware."""

import os
import secrets

from fastapi import Depends, HTTPException, status
from fastapi.security import APIKeyHeader

API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)


def get_api_key() -> str | None:
    """Get the configured API key from environment.

    Returns None if no key is configured (auth disabled).
    """
    return os.environ.get("SECURITY_SCANNER_API_KEY")


async def verify_api_key(
    api_key: str | None = Depends(API_KEY_HEADER),
) -> str | None:
    """Verify the API key if authentication is enabled.

    When SECURITY_SCANNER_API_KEY is not set, all requests are allowed.
    When set, requests must include a valid X-API-Key header.
    """
    expected_key = get_api_key()

    if expected_key is None:
        return None

    if api_key is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key",
        )

    if not secrets.compare_digest(api_key, expected_key):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid API key",
        )

    return api_key
