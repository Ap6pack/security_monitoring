"""Async HTTP client with retry logic and rate limiting."""

import asyncio
from typing import Any

import aiohttp
from aiohttp import ClientSession, ClientTimeout, TCPConnector
from tenacity import (
    AsyncRetrying,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from security_scanner.utils.exceptions import APIError, NetworkError
from security_scanner.utils.logger import get_logger
from security_scanner.utils.rate_limiter import RateLimiter

logger = get_logger(__name__)


class HTTPClient:
    """
    Async HTTP client with connection pooling, retry logic, and rate limiting.

    Features:
    - Connection pooling for efficient resource usage
    - Automatic retry with exponential backoff
    - Rate limiting to respect API limits
    - Timeout configuration
    - Custom headers and user agent
    """

    def __init__(
        self,
        timeout: int = 10,
        max_retries: int = 3,
        max_connections: int = 100,
        rate_limit: float = 2.0,
        rate_burst: int = 5,
        user_agent: str = "SecurityScanner/0.1.0",
    ) -> None:
        """
        Initialize the HTTP client.

        Args:
            timeout: Request timeout in seconds
            max_retries: Maximum number of retry attempts
            max_connections: Maximum concurrent connections
            rate_limit: Maximum requests per second
            rate_burst: Burst capacity for rate limiter
            user_agent: User agent string for requests
        """
        self.timeout = ClientTimeout(total=timeout)
        self.max_retries = max_retries
        self.user_agent = user_agent

        self._connector = TCPConnector(
            limit=max_connections,
            limit_per_host=10,
            ttl_dns_cache=300,
        )
        self._session: ClientSession | None = None
        self._rate_limiter = RateLimiter(rate=rate_limit, burst=rate_burst)

    async def __aenter__(self) -> "HTTPClient":
        """Async context manager entry."""
        await self._ensure_session()
        return self

    async def __aexit__(self, *args: Any) -> None:
        """Async context manager exit."""
        await self.close()

    async def _ensure_session(self) -> None:
        """Ensure the session is initialized."""
        if self._session is None or self._session.closed:
            self._session = ClientSession(
                connector=self._connector,
                timeout=self.timeout,
                headers={"User-Agent": self.user_agent},
            )

    async def close(self) -> None:
        """Close the HTTP session and cleanup resources."""
        if self._session and not self._session.closed:
            await self._session.close()
            # Wait for connections to close properly
            await asyncio.sleep(0.25)

    async def get(  # type: ignore[return]
        self,
        url: str,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        rate_limit: bool = True,
    ) -> dict[str, Any]:
        """
        Make a GET request.

        Args:
            url: URL to request
            params: Query parameters
            headers: Additional headers
            rate_limit: Whether to apply rate limiting

        Returns:
            JSON response as dictionary

        Raises:
            APIError: If the request fails after retries
            NetworkError: For network-related errors
        """
        await self._ensure_session()

        if rate_limit:
            await self._rate_limiter.acquire()

        async def _make_request() -> dict[str, Any]:
            try:
                assert self._session is not None
                async with self._session.get(
                    url,
                    params=params,
                    headers=headers,
                ) as response:
                    response.raise_for_status()
                    return await response.json()  # type: ignore[no-any-return]
            except aiohttp.ClientResponseError as e:
                logger.warning(
                    "HTTP request failed",
                    url=url,
                    status=e.status,
                    message=str(e),
                )
                raise APIError(
                    message=f"HTTP {e.status} error for {url}",
                    api_name=url,
                    status_code=e.status,
                    response_body=str(e),
                ) from e
            except aiohttp.ClientError as e:
                logger.warning("Network error", url=url, error=str(e))
                raise NetworkError(f"Network error for {url}: {e}") from e
            except TimeoutError:
                logger.warning("Request timeout", url=url)
                raise NetworkError(f"Timeout requesting {url}") from None

        try:
            async for attempt in AsyncRetrying(
                stop=stop_after_attempt(self.max_retries),
                wait=wait_exponential(multiplier=1, min=2, max=10),
                retry=retry_if_exception_type((NetworkError, APIError)),
                reraise=True,
            ):
                with attempt:
                    return await _make_request()
        except Exception:
            # Should never reach here due to reraise=True
            raise

    async def post(  # type: ignore[return]
        self,
        url: str,
        data: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        rate_limit: bool = True,
    ) -> dict[str, Any]:
        """
        Make a POST request.

        Args:
            url: URL to request
            data: Form data
            json: JSON data
            headers: Additional headers
            rate_limit: Whether to apply rate limiting

        Returns:
            JSON response as dictionary

        Raises:
            APIError: If the request fails after retries
            NetworkError: For network-related errors
        """
        await self._ensure_session()

        if rate_limit:
            await self._rate_limiter.acquire()

        async def _make_request() -> dict[str, Any]:
            try:
                assert self._session is not None
                async with self._session.post(
                    url,
                    data=data,
                    json=json,
                    headers=headers,
                ) as response:
                    response.raise_for_status()
                    return await response.json()  # type: ignore[no-any-return]
            except aiohttp.ClientResponseError as e:
                logger.warning(
                    "HTTP POST failed",
                    url=url,
                    status=e.status,
                    message=str(e),
                )
                raise APIError(
                    message=f"HTTP {e.status} error for {url}",
                    api_name=url,
                    status_code=e.status,
                    response_body=str(e),
                ) from e
            except aiohttp.ClientError as e:
                logger.warning("Network error on POST", url=url, error=str(e))
                raise NetworkError(f"Network error for {url}: {e}") from e
            except TimeoutError:
                logger.warning("POST request timeout", url=url)
                raise NetworkError(f"Timeout requesting {url}") from None

        try:
            async for attempt in AsyncRetrying(
                stop=stop_after_attempt(self.max_retries),
                wait=wait_exponential(multiplier=1, min=2, max=10),
                retry=retry_if_exception_type((NetworkError, APIError)),
                reraise=True,
            ):
                with attempt:
                    return await _make_request()
        except Exception:
            raise

    async def fetch_text(  # type: ignore[return]
        self,
        url: str,
        headers: dict[str, str] | None = None,
        rate_limit: bool = True,
    ) -> str:
        """
        Fetch URL content as text.

        Args:
            url: URL to fetch
            headers: Additional headers
            rate_limit: Whether to apply rate limiting

        Returns:
            Response text

        Raises:
            APIError: If the request fails after retries
            NetworkError: For network-related errors
        """
        await self._ensure_session()

        if rate_limit:
            await self._rate_limiter.acquire()

        async def _make_request() -> str:
            try:
                assert self._session is not None
                async with self._session.get(url, headers=headers) as response:
                    response.raise_for_status()
                    return await response.text()
            except aiohttp.ClientResponseError as e:
                raise APIError(
                    message=f"HTTP {e.status} error for {url}",
                    api_name=url,
                    status_code=e.status,
                    response_body=str(e),
                ) from e
            except aiohttp.ClientError as e:
                raise NetworkError(f"Network error for {url}: {e}") from e
            except TimeoutError:
                raise NetworkError(f"Timeout requesting {url}") from None

        try:
            async for attempt in AsyncRetrying(
                stop=stop_after_attempt(self.max_retries),
                wait=wait_exponential(multiplier=1, min=2, max=10),
                retry=retry_if_exception_type((NetworkError, APIError)),
                reraise=True,
            ):
                with attempt:
                    return await _make_request()
        except Exception:
            raise
