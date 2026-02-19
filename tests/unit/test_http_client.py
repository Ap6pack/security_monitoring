# Copyright (c) 2024 Veritas Aequitas Holdings LLC. All rights reserved.
"""Unit tests for HTTP client."""

from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest

from security_scanner.utils.exceptions import APIError, NetworkError
from security_scanner.utils.http_client import HTTPClient


def _make_mock_response(
    status: int = 200,
    json_data: dict | None = None,
    text_data: str = "",
    raise_for_status: Exception | None = None,
) -> MagicMock:
    """Create a mock aiohttp response used as an async context manager."""
    mock_resp = MagicMock()
    mock_resp.status = status
    mock_resp.json = AsyncMock(return_value=json_data if json_data is not None else {})
    mock_resp.text = AsyncMock(return_value=text_data)

    if raise_for_status:
        mock_resp.raise_for_status = MagicMock(side_effect=raise_for_status)
    else:
        mock_resp.raise_for_status = MagicMock()

    # Make the response work as an async context manager
    mock_ctx = MagicMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_ctx.__aexit__ = AsyncMock(return_value=False)
    return mock_ctx


class TestHTTPClientInit:
    """Test HTTPClient initialization."""

    async def test_default_parameters(self) -> None:
        """Test that default parameters are set correctly."""
        client = HTTPClient()
        assert client.timeout.total == 10
        assert client.max_retries == 3
        assert client.user_agent == "SecurityScanner/0.1.0"
        assert client._session is None

    async def test_custom_parameters(self) -> None:
        """Test initialization with custom parameters."""
        client = HTTPClient(
            timeout=30,
            max_retries=5,
            max_connections=50,
            rate_limit=1.0,
            rate_burst=3,
            user_agent="TestAgent/1.0",
        )
        assert client.timeout.total == 30
        assert client.max_retries == 5
        assert client.user_agent == "TestAgent/1.0"
        assert client._rate_limiter.rate == 1.0
        assert client._rate_limiter.burst == 3


class TestEnsureSession:
    """Test _ensure_session() method."""

    async def test_creates_session_when_none(self) -> None:
        """Test that a new session is created when none exists."""
        client = HTTPClient()
        assert client._session is None

        with patch("security_scanner.utils.http_client.ClientSession") as mock_cls:
            mock_session = MagicMock()
            mock_session.closed = False
            mock_cls.return_value = mock_session

            await client._ensure_session()

            mock_cls.assert_called_once()
            assert client._session is mock_session

    async def test_reuses_existing_open_session(self) -> None:
        """Test that an open session is reused."""
        client = HTTPClient()

        mock_session = MagicMock()
        mock_session.closed = False
        client._session = mock_session

        with patch("security_scanner.utils.http_client.ClientSession") as mock_cls:
            await client._ensure_session()
            mock_cls.assert_not_called()
            assert client._session is mock_session

    async def test_reopens_closed_session(self) -> None:
        """Test that a new session is created if the old one was closed."""
        client = HTTPClient()

        closed_session = MagicMock()
        closed_session.closed = True
        client._session = closed_session

        with patch("security_scanner.utils.http_client.ClientSession") as mock_cls:
            new_session = MagicMock()
            new_session.closed = False
            mock_cls.return_value = new_session

            await client._ensure_session()

            mock_cls.assert_called_once()
            assert client._session is new_session


class TestClose:
    """Test close() method."""

    async def test_close_active_session(self) -> None:
        """Test closing an active session."""
        client = HTTPClient()

        mock_session = MagicMock()
        mock_session.closed = False
        mock_session.close = AsyncMock()
        client._session = mock_session

        with patch("asyncio.sleep", new_callable=AsyncMock):
            await client.close()

        mock_session.close.assert_awaited_once()

    async def test_close_already_closed_session(self) -> None:
        """Test closing an already-closed session is a no-op."""
        client = HTTPClient()

        mock_session = MagicMock()
        mock_session.closed = True
        mock_session.close = AsyncMock()
        client._session = mock_session

        await client.close()
        mock_session.close.assert_not_awaited()

    async def test_close_no_session(self) -> None:
        """Test closing when no session was ever created."""
        client = HTTPClient()
        assert client._session is None
        await client.close()  # Should not raise


class TestGet:
    """Test get() method."""

    async def test_successful_json_response(self) -> None:
        """Test a successful GET request returning JSON."""
        client = HTTPClient(max_retries=1)
        expected = {"status": "ok", "data": [1, 2, 3]}

        mock_session = MagicMock()
        mock_session.closed = False
        mock_session.get = MagicMock(
            return_value=_make_mock_response(status=200, json_data=expected)
        )
        client._session = mock_session
        client._rate_limiter = MagicMock()
        client._rate_limiter.acquire = AsyncMock()

        result = await client.get("https://api.example.com/data", params={"key": "value"})

        assert result == expected
        mock_session.get.assert_called_once_with(
            "https://api.example.com/data",
            params={"key": "value"},
            headers=None,
        )
        client._rate_limiter.acquire.assert_awaited_once()

    async def test_http_error_raises_api_error(self) -> None:
        """Test that HTTP errors (4xx/5xx) raise APIError."""
        client = HTTPClient(max_retries=1)

        error = aiohttp.ClientResponseError(
            request_info=MagicMock(),
            history=(),
            status=404,
            message="Not Found",
        )

        mock_session = MagicMock()
        mock_session.closed = False
        mock_session.get = MagicMock(
            return_value=_make_mock_response(status=404, raise_for_status=error)
        )
        client._session = mock_session
        client._rate_limiter = MagicMock()
        client._rate_limiter.acquire = AsyncMock()

        with pytest.raises(APIError) as exc_info:
            await client.get("https://api.example.com/missing")

        assert exc_info.value.status_code == 404
        assert "404" in str(exc_info.value)

    async def test_http_500_raises_api_error(self) -> None:
        """Test that 5xx errors raise APIError."""
        client = HTTPClient(max_retries=1)

        error = aiohttp.ClientResponseError(
            request_info=MagicMock(),
            history=(),
            status=500,
            message="Internal Server Error",
        )

        mock_session = MagicMock()
        mock_session.closed = False
        mock_session.get = MagicMock(
            return_value=_make_mock_response(status=500, raise_for_status=error)
        )
        client._session = mock_session
        client._rate_limiter = MagicMock()
        client._rate_limiter.acquire = AsyncMock()

        with pytest.raises(APIError) as exc_info:
            await client.get("https://api.example.com/error")

        assert exc_info.value.status_code == 500

    async def test_network_error_raises_network_error(self) -> None:
        """Test that network connectivity errors raise NetworkError."""
        client = HTTPClient(max_retries=1)

        mock_ctx = MagicMock()
        mock_ctx.__aenter__ = AsyncMock(
            side_effect=aiohttp.ClientConnectionError("Connection refused")
        )
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.closed = False
        mock_session.get = MagicMock(return_value=mock_ctx)
        client._session = mock_session
        client._rate_limiter = MagicMock()
        client._rate_limiter.acquire = AsyncMock()

        with pytest.raises(NetworkError) as exc_info:
            await client.get("https://api.example.com/unreachable")

        assert "Network error" in str(exc_info.value)

    async def test_timeout_raises_network_error(self) -> None:
        """Test that a timeout raises NetworkError."""
        client = HTTPClient(max_retries=1)

        mock_ctx = MagicMock()
        mock_ctx.__aenter__ = AsyncMock(side_effect=TimeoutError())
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.closed = False
        mock_session.get = MagicMock(return_value=mock_ctx)
        client._session = mock_session
        client._rate_limiter = MagicMock()
        client._rate_limiter.acquire = AsyncMock()

        with pytest.raises(NetworkError) as exc_info:
            await client.get("https://api.example.com/slow")

        assert "Timeout" in str(exc_info.value)

    async def test_rate_limiter_called_when_enabled(self) -> None:
        """Test that the rate limiter is invoked when rate_limit=True."""
        client = HTTPClient(max_retries=1)
        mock_session = MagicMock()
        mock_session.closed = False
        mock_session.get = MagicMock(
            return_value=_make_mock_response(status=200, json_data={"ok": True})
        )
        client._session = mock_session
        client._rate_limiter = MagicMock()
        client._rate_limiter.acquire = AsyncMock()

        await client.get("https://api.example.com/data", rate_limit=True)

        client._rate_limiter.acquire.assert_awaited_once()

    async def test_rate_limiter_not_called_when_disabled(self) -> None:
        """Test that the rate limiter is skipped when rate_limit=False."""
        client = HTTPClient(max_retries=1)
        mock_session = MagicMock()
        mock_session.closed = False
        mock_session.get = MagicMock(
            return_value=_make_mock_response(status=200, json_data={"ok": True})
        )
        client._session = mock_session
        client._rate_limiter = MagicMock()
        client._rate_limiter.acquire = AsyncMock()

        await client.get("https://api.example.com/data", rate_limit=False)

        client._rate_limiter.acquire.assert_not_awaited()

    async def test_custom_headers_passed(self) -> None:
        """Test that custom headers are forwarded to the session."""
        client = HTTPClient(max_retries=1)
        custom_headers = {"Authorization": "Bearer token123"}

        mock_session = MagicMock()
        mock_session.closed = False
        mock_session.get = MagicMock(
            return_value=_make_mock_response(status=200, json_data={"auth": True})
        )
        client._session = mock_session
        client._rate_limiter = MagicMock()
        client._rate_limiter.acquire = AsyncMock()

        await client.get("https://api.example.com/secure", headers=custom_headers)

        mock_session.get.assert_called_once_with(
            "https://api.example.com/secure",
            params=None,
            headers=custom_headers,
        )


class TestPost:
    """Test post() method."""

    async def test_successful_post_with_json(self) -> None:
        """Test a successful POST request with JSON body."""
        client = HTTPClient(max_retries=1)
        expected = {"id": 42, "created": True}

        mock_session = MagicMock()
        mock_session.closed = False
        mock_session.post = MagicMock(
            return_value=_make_mock_response(status=200, json_data=expected)
        )
        client._session = mock_session
        client._rate_limiter = MagicMock()
        client._rate_limiter.acquire = AsyncMock()

        result = await client.post(
            "https://api.example.com/items",
            json={"name": "test"},
        )

        assert result == expected
        mock_session.post.assert_called_once_with(
            "https://api.example.com/items",
            data=None,
            json={"name": "test"},
            headers=None,
        )

    async def test_successful_post_with_form_data(self) -> None:
        """Test a successful POST request with form data."""
        client = HTTPClient(max_retries=1)
        expected = {"submitted": True}

        mock_session = MagicMock()
        mock_session.closed = False
        mock_session.post = MagicMock(
            return_value=_make_mock_response(status=200, json_data=expected)
        )
        client._session = mock_session
        client._rate_limiter = MagicMock()
        client._rate_limiter.acquire = AsyncMock()

        result = await client.post(
            "https://api.example.com/submit",
            data={"field": "value"},
        )

        assert result == expected

    async def test_post_http_error_raises_api_error(self) -> None:
        """Test that HTTP errors on POST raise APIError."""
        client = HTTPClient(max_retries=1)

        error = aiohttp.ClientResponseError(
            request_info=MagicMock(),
            history=(),
            status=403,
            message="Forbidden",
        )

        mock_session = MagicMock()
        mock_session.closed = False
        mock_session.post = MagicMock(
            return_value=_make_mock_response(status=403, raise_for_status=error)
        )
        client._session = mock_session
        client._rate_limiter = MagicMock()
        client._rate_limiter.acquire = AsyncMock()

        with pytest.raises(APIError) as exc_info:
            await client.post("https://api.example.com/forbidden", json={})

        assert exc_info.value.status_code == 403

    async def test_post_network_error_raises_network_error(self) -> None:
        """Test that network errors on POST raise NetworkError."""
        client = HTTPClient(max_retries=1)

        mock_ctx = MagicMock()
        mock_ctx.__aenter__ = AsyncMock(
            side_effect=aiohttp.ClientConnectionError("Connection refused")
        )
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.closed = False
        mock_session.post = MagicMock(return_value=mock_ctx)
        client._session = mock_session
        client._rate_limiter = MagicMock()
        client._rate_limiter.acquire = AsyncMock()

        with pytest.raises(NetworkError):
            await client.post("https://api.example.com/unreachable", json={})

    async def test_post_timeout_raises_network_error(self) -> None:
        """Test that a timeout on POST raises NetworkError."""
        client = HTTPClient(max_retries=1)

        mock_ctx = MagicMock()
        mock_ctx.__aenter__ = AsyncMock(side_effect=TimeoutError())
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.closed = False
        mock_session.post = MagicMock(return_value=mock_ctx)
        client._session = mock_session
        client._rate_limiter = MagicMock()
        client._rate_limiter.acquire = AsyncMock()

        with pytest.raises(NetworkError) as exc_info:
            await client.post("https://api.example.com/slow", json={})

        assert "Timeout" in str(exc_info.value)

    async def test_post_rate_limiter_called(self) -> None:
        """Test that rate limiter is invoked on POST."""
        client = HTTPClient(max_retries=1)
        mock_session = MagicMock()
        mock_session.closed = False
        mock_session.post = MagicMock(return_value=_make_mock_response(status=200, json_data={}))
        client._session = mock_session
        client._rate_limiter = MagicMock()
        client._rate_limiter.acquire = AsyncMock()

        await client.post("https://api.example.com/data", json={}, rate_limit=True)

        client._rate_limiter.acquire.assert_awaited_once()

    async def test_post_rate_limiter_skipped(self) -> None:
        """Test that rate limiter is skipped on POST when disabled."""
        client = HTTPClient(max_retries=1)
        mock_session = MagicMock()
        mock_session.closed = False
        mock_session.post = MagicMock(return_value=_make_mock_response(status=200, json_data={}))
        client._session = mock_session
        client._rate_limiter = MagicMock()
        client._rate_limiter.acquire = AsyncMock()

        await client.post("https://api.example.com/data", json={}, rate_limit=False)

        client._rate_limiter.acquire.assert_not_awaited()


class TestFetchText:
    """Test fetch_text() method."""

    async def test_successful_text_response(self) -> None:
        """Test a successful text fetch."""
        client = HTTPClient(max_retries=1)
        expected_text = "<html><body>Hello World</body></html>"

        mock_session = MagicMock()
        mock_session.closed = False
        mock_session.get = MagicMock(
            return_value=_make_mock_response(status=200, text_data=expected_text)
        )
        client._session = mock_session
        client._rate_limiter = MagicMock()
        client._rate_limiter.acquire = AsyncMock()

        result = await client.fetch_text("https://example.com/page")

        assert result == expected_text

    async def test_fetch_text_http_error(self) -> None:
        """Test that HTTP errors raise APIError for text fetch."""
        client = HTTPClient(max_retries=1)

        error = aiohttp.ClientResponseError(
            request_info=MagicMock(),
            history=(),
            status=500,
            message="Internal Server Error",
        )

        mock_session = MagicMock()
        mock_session.closed = False
        mock_session.get = MagicMock(
            return_value=_make_mock_response(status=500, raise_for_status=error)
        )
        client._session = mock_session
        client._rate_limiter = MagicMock()
        client._rate_limiter.acquire = AsyncMock()

        with pytest.raises(APIError) as exc_info:
            await client.fetch_text("https://example.com/error")

        assert exc_info.value.status_code == 500

    async def test_fetch_text_network_error(self) -> None:
        """Test that network errors raise NetworkError for text fetch."""
        client = HTTPClient(max_retries=1)

        mock_ctx = MagicMock()
        mock_ctx.__aenter__ = AsyncMock(
            side_effect=aiohttp.ClientConnectionError("DNS resolution failed")
        )
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.closed = False
        mock_session.get = MagicMock(return_value=mock_ctx)
        client._session = mock_session
        client._rate_limiter = MagicMock()
        client._rate_limiter.acquire = AsyncMock()

        with pytest.raises(NetworkError):
            await client.fetch_text("https://example.com/unreachable")

    async def test_fetch_text_timeout(self) -> None:
        """Test that timeout raises NetworkError for text fetch."""
        client = HTTPClient(max_retries=1)

        mock_ctx = MagicMock()
        mock_ctx.__aenter__ = AsyncMock(side_effect=TimeoutError())
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.closed = False
        mock_session.get = MagicMock(return_value=mock_ctx)
        client._session = mock_session
        client._rate_limiter = MagicMock()
        client._rate_limiter.acquire = AsyncMock()

        with pytest.raises(NetworkError) as exc_info:
            await client.fetch_text("https://example.com/slow")

        assert "Timeout" in str(exc_info.value)

    async def test_fetch_text_with_custom_headers(self) -> None:
        """Test fetch_text passes custom headers."""
        client = HTTPClient(max_retries=1)
        headers = {"Accept": "text/plain"}

        mock_session = MagicMock()
        mock_session.closed = False
        mock_session.get = MagicMock(
            return_value=_make_mock_response(status=200, text_data="plain text")
        )
        client._session = mock_session
        client._rate_limiter = MagicMock()
        client._rate_limiter.acquire = AsyncMock()

        result = await client.fetch_text("https://example.com/text", headers=headers)

        assert result == "plain text"
        mock_session.get.assert_called_once_with(
            "https://example.com/text",
            headers=headers,
        )

    async def test_fetch_text_rate_limiter(self) -> None:
        """Test that fetch_text respects rate_limit flag."""
        client = HTTPClient(max_retries=1)
        mock_session = MagicMock()
        mock_session.closed = False
        mock_session.get = MagicMock(return_value=_make_mock_response(status=200, text_data="ok"))
        client._session = mock_session
        client._rate_limiter = MagicMock()
        client._rate_limiter.acquire = AsyncMock()

        await client.fetch_text("https://example.com/text", rate_limit=False)
        client._rate_limiter.acquire.assert_not_awaited()


class TestAsyncContextManager:
    """Test async context manager protocol (__aenter__/__aexit__)."""

    async def test_context_manager_creates_and_closes_session(self) -> None:
        """Test that the context manager creates a session on entry and closes it on exit."""
        with patch("security_scanner.utils.http_client.ClientSession") as mock_cls:
            mock_session = MagicMock()
            mock_session.closed = False
            mock_session.close = AsyncMock()
            mock_cls.return_value = mock_session

            client = HTTPClient()

            with patch("asyncio.sleep", new_callable=AsyncMock):
                async with client as ctx:
                    assert ctx is client
                    assert client._session is mock_session
                    mock_cls.assert_called_once()

            mock_session.close.assert_awaited_once()

    async def test_context_manager_returns_client_instance(self) -> None:
        """Test that __aenter__ returns the HTTPClient instance itself."""
        with patch("security_scanner.utils.http_client.ClientSession") as mock_cls:
            mock_session = MagicMock()
            mock_session.closed = False
            mock_session.close = AsyncMock()
            mock_cls.return_value = mock_session

            client = HTTPClient()

            with patch("asyncio.sleep", new_callable=AsyncMock):
                async with client as ctx:
                    assert isinstance(ctx, HTTPClient)
                    assert ctx is client
