"""Unit tests for rate_limiter module."""

import asyncio
from unittest.mock import patch

import pytest

from security_scanner.utils.rate_limiter import MultiRateLimiter, RateLimiter


class TestRateLimiterInit:
    """Test RateLimiter initialization."""

    def test_default_params(self) -> None:
        """Test initialization with default parameters."""
        limiter = RateLimiter(rate=10.0)
        assert limiter.rate == 10.0
        assert limiter.burst == 1
        assert limiter.tokens == 1.0

    def test_custom_burst(self) -> None:
        """Test initialization with custom burst capacity."""
        limiter = RateLimiter(rate=5.0, burst=10)
        assert limiter.rate == 5.0
        assert limiter.burst == 10
        assert limiter.tokens == 10.0

    def test_custom_initial_tokens(self) -> None:
        """Test initialization with explicit initial tokens."""
        limiter = RateLimiter(rate=5.0, burst=10, initial_tokens=3)
        assert limiter.tokens == 3.0

    def test_initial_tokens_zero(self) -> None:
        """Test initialization with zero initial tokens."""
        limiter = RateLimiter(rate=5.0, burst=10, initial_tokens=0)
        assert limiter.tokens == 0.0

    def test_initial_tokens_defaults_to_burst(self) -> None:
        """Test that initial_tokens defaults to burst when None."""
        limiter = RateLimiter(rate=1.0, burst=5)
        assert limiter.tokens == 5.0

    def test_lock_is_created(self) -> None:
        """Test that an asyncio Lock is created on init."""
        limiter = RateLimiter(rate=1.0)
        assert isinstance(limiter._lock, asyncio.Lock)

    def test_last_update_is_set(self) -> None:
        """Test that last_update timestamp is set on init."""
        limiter = RateLimiter(rate=1.0)
        assert limiter.last_update > 0


class TestRateLimiterAcquire:
    """Test RateLimiter.acquire() method."""

    @pytest.mark.asyncio
    async def test_acquire_when_tokens_available(self) -> None:
        """Test acquiring a token when tokens are available."""
        limiter = RateLimiter(rate=10.0, burst=5, initial_tokens=5)
        await limiter.acquire()
        # After acquiring 1 token, should have fewer tokens
        assert limiter.tokens < 5.0

    @pytest.mark.asyncio
    async def test_acquire_multiple_tokens(self) -> None:
        """Test acquiring multiple tokens at once."""
        limiter = RateLimiter(rate=10.0, burst=5, initial_tokens=5)
        await limiter.acquire(tokens=3)
        # Should have approximately 2 tokens left (minus tiny elapsed refill)
        assert limiter.tokens < 3.0

    @pytest.mark.asyncio
    async def test_acquire_waits_when_exhausted(self) -> None:
        """Test that acquire waits when tokens are exhausted."""
        limiter = RateLimiter(rate=100.0, burst=1, initial_tokens=0)
        sleep_calls: list[float] = []

        original_sleep = asyncio.sleep

        async def mock_sleep(delay: float) -> None:
            sleep_calls.append(delay)
            # Actually advance time a tiny bit so tokens accumulate
            await original_sleep(0.01)

        with patch("asyncio.sleep", side_effect=mock_sleep):
            await limiter.acquire()
            # Should have called asyncio.sleep at least once since no tokens available
            assert len(sleep_calls) >= 1

    @pytest.mark.asyncio
    async def test_acquire_default_one_token(self) -> None:
        """Test that acquire defaults to requesting 1 token."""
        limiter = RateLimiter(rate=10.0, burst=5, initial_tokens=5)
        await limiter.acquire()
        # Should have consumed exactly 1 token (plus tiny time-based refill)
        assert limiter.tokens >= 3.5  # roughly 4 tokens remain

    @pytest.mark.asyncio
    async def test_acquire_all_tokens_sequentially(self) -> None:
        """Test acquiring all tokens one by one."""
        limiter = RateLimiter(rate=1000.0, burst=3, initial_tokens=3)
        await limiter.acquire()
        await limiter.acquire()
        await limiter.acquire()
        # All tokens consumed; remaining should be very close to 0
        assert limiter.tokens < 1.0


class TestRateLimiterTryAcquire:
    """Test RateLimiter.try_acquire() method."""

    @pytest.mark.asyncio
    async def test_try_acquire_success(self) -> None:
        """Test successful try_acquire when tokens are available."""
        limiter = RateLimiter(rate=10.0, burst=5, initial_tokens=5)
        result = await limiter.try_acquire()
        assert result is True

    @pytest.mark.asyncio
    async def test_try_acquire_failure(self) -> None:
        """Test try_acquire returns False when no tokens available."""
        limiter = RateLimiter(rate=0.001, burst=1, initial_tokens=0)
        result = await limiter.try_acquire()
        assert result is False

    @pytest.mark.asyncio
    async def test_try_acquire_multiple_tokens_success(self) -> None:
        """Test try_acquire with multiple tokens when available."""
        limiter = RateLimiter(rate=10.0, burst=5, initial_tokens=5)
        result = await limiter.try_acquire(tokens=3)
        assert result is True

    @pytest.mark.asyncio
    async def test_try_acquire_multiple_tokens_failure(self) -> None:
        """Test try_acquire with more tokens than available."""
        limiter = RateLimiter(rate=0.001, burst=2, initial_tokens=2)
        result = await limiter.try_acquire(tokens=5)
        assert result is False

    @pytest.mark.asyncio
    async def test_try_acquire_does_not_wait(self) -> None:
        """Test that try_acquire returns immediately without waiting."""
        limiter = RateLimiter(rate=0.001, burst=1, initial_tokens=0)
        with patch("asyncio.sleep") as mock_sleep:
            await limiter.try_acquire()
            mock_sleep.assert_not_called()

    @pytest.mark.asyncio
    async def test_try_acquire_consumes_token(self) -> None:
        """Test that successful try_acquire actually consumes a token."""
        limiter = RateLimiter(rate=0.001, burst=1, initial_tokens=1)
        first = await limiter.try_acquire()
        second = await limiter.try_acquire()
        assert first is True
        assert second is False


class TestRateLimiterReset:
    """Test RateLimiter.reset() method."""

    @pytest.mark.asyncio
    async def test_reset_restores_tokens(self) -> None:
        """Test that reset restores tokens to burst capacity."""
        limiter = RateLimiter(rate=0.001, burst=5, initial_tokens=5)
        await limiter.try_acquire(tokens=5)
        assert limiter.tokens < 1.0
        limiter.reset()
        assert limiter.tokens == 5

    def test_reset_updates_last_update(self) -> None:
        """Test that reset updates the last_update timestamp."""
        limiter = RateLimiter(rate=1.0, burst=5)
        old_update = limiter.last_update
        # Small sleep to ensure monotonic time advances
        import time

        time.sleep(0.01)
        limiter.reset()
        assert limiter.last_update >= old_update


class TestRateLimiterAvailableTokens:
    """Test RateLimiter.available_tokens property."""

    def test_available_tokens_at_init(self) -> None:
        """Test available_tokens reflects initial tokens."""
        limiter = RateLimiter(rate=10.0, burst=5, initial_tokens=5)
        # Should be approximately 5 (plus tiny time-based accumulation)
        assert limiter.available_tokens >= 4.9
        assert limiter.available_tokens <= 5.0

    def test_available_tokens_capped_at_burst(self) -> None:
        """Test that available_tokens does not exceed burst capacity."""
        limiter = RateLimiter(rate=10000.0, burst=5, initial_tokens=5)
        # Even with high rate and some elapsed time, tokens capped at burst
        import time

        time.sleep(0.01)
        assert limiter.available_tokens <= 5.0

    @pytest.mark.asyncio
    async def test_available_tokens_after_consumption(self) -> None:
        """Test available_tokens decreases after acquiring tokens."""
        limiter = RateLimiter(rate=0.001, burst=5, initial_tokens=5)
        await limiter.acquire(tokens=3)
        assert limiter.available_tokens < 3.0

    def test_available_tokens_accumulates_over_time(self) -> None:
        """Test that tokens accumulate over time based on rate."""
        limiter = RateLimiter(rate=1000.0, burst=10, initial_tokens=0)
        import time

        time.sleep(0.01)  # 10ms at 1000 tokens/sec = ~10 tokens
        available = limiter.available_tokens
        assert available > 0.0
        assert available <= 10.0  # capped at burst


class TestMultiRateLimiterInit:
    """Test MultiRateLimiter initialization."""

    def test_init_empty(self) -> None:
        """Test initialization creates empty limiter collection."""
        multi = MultiRateLimiter()
        assert multi._limiters == {}


class TestMultiRateLimiterAddLimiter:
    """Test MultiRateLimiter.add_limiter() method."""

    def test_add_limiter(self) -> None:
        """Test adding a named limiter."""
        multi = MultiRateLimiter()
        multi.add_limiter("api", rate=10.0, burst=5)
        assert "api" in multi._limiters
        assert isinstance(multi._limiters["api"], RateLimiter)

    def test_add_multiple_limiters(self) -> None:
        """Test adding multiple named limiters."""
        multi = MultiRateLimiter()
        multi.add_limiter("api", rate=10.0, burst=5)
        multi.add_limiter("dns", rate=50.0, burst=10)
        assert len(multi._limiters) == 2
        assert "api" in multi._limiters
        assert "dns" in multi._limiters

    def test_add_limiter_with_default_burst(self) -> None:
        """Test adding a limiter with default burst of 1."""
        multi = MultiRateLimiter()
        multi.add_limiter("api", rate=10.0)
        assert multi._limiters["api"].burst == 1

    def test_add_limiter_overwrites_existing(self) -> None:
        """Test that adding a limiter with same name overwrites existing."""
        multi = MultiRateLimiter()
        multi.add_limiter("api", rate=10.0, burst=5)
        multi.add_limiter("api", rate=20.0, burst=10)
        assert multi._limiters["api"].rate == 20.0
        assert multi._limiters["api"].burst == 10


class TestMultiRateLimiterAcquire:
    """Test MultiRateLimiter.acquire() method."""

    @pytest.mark.asyncio
    async def test_acquire_from_named_limiter(self) -> None:
        """Test acquiring tokens from a named limiter."""
        multi = MultiRateLimiter()
        multi.add_limiter("api", rate=10.0, burst=5)
        await multi.acquire("api")
        # Should have consumed a token
        limiter = multi._limiters["api"]
        assert limiter.tokens < 5.0

    @pytest.mark.asyncio
    async def test_acquire_missing_limiter_raises_key_error(self) -> None:
        """Test that acquiring from a missing limiter raises KeyError."""
        multi = MultiRateLimiter()
        with pytest.raises(KeyError, match="Rate limiter 'nonexistent' not found"):
            await multi.acquire("nonexistent")

    @pytest.mark.asyncio
    async def test_acquire_custom_tokens(self) -> None:
        """Test acquiring custom number of tokens from named limiter."""
        multi = MultiRateLimiter()
        multi.add_limiter("api", rate=10.0, burst=5)
        await multi.acquire("api", tokens=3)
        limiter = multi._limiters["api"]
        assert limiter.tokens < 3.0


class TestMultiRateLimiterTryAcquire:
    """Test MultiRateLimiter.try_acquire() method."""

    @pytest.mark.asyncio
    async def test_try_acquire_success(self) -> None:
        """Test successful try_acquire from named limiter."""
        multi = MultiRateLimiter()
        multi.add_limiter("api", rate=10.0, burst=5)
        result = await multi.try_acquire("api")
        assert result is True

    @pytest.mark.asyncio
    async def test_try_acquire_failure(self) -> None:
        """Test try_acquire failure when no tokens available."""
        multi = MultiRateLimiter()
        multi.add_limiter(
            "api",
            rate=0.001,
            burst=1,
        )
        # Consume the only token
        await multi.acquire("api")
        result = await multi.try_acquire("api")
        assert result is False

    @pytest.mark.asyncio
    async def test_try_acquire_missing_limiter_raises_key_error(self) -> None:
        """Test that try_acquire on missing limiter raises KeyError."""
        multi = MultiRateLimiter()
        with pytest.raises(KeyError, match="Rate limiter 'missing' not found"):
            await multi.try_acquire("missing")


class TestMultiRateLimiterGetLimiter:
    """Test MultiRateLimiter.get_limiter() method."""

    def test_get_limiter_success(self) -> None:
        """Test getting an existing limiter by name."""
        multi = MultiRateLimiter()
        multi.add_limiter("api", rate=10.0, burst=5)
        limiter = multi.get_limiter("api")
        assert isinstance(limiter, RateLimiter)
        assert limiter.rate == 10.0
        assert limiter.burst == 5

    def test_get_limiter_missing_raises_key_error(self) -> None:
        """Test that getting a missing limiter raises KeyError."""
        multi = MultiRateLimiter()
        with pytest.raises(KeyError, match="Rate limiter 'missing' not found"):
            multi.get_limiter("missing")

    def test_get_limiter_returns_same_instance(self) -> None:
        """Test that get_limiter returns the same RateLimiter instance."""
        multi = MultiRateLimiter()
        multi.add_limiter("api", rate=10.0, burst=5)
        limiter1 = multi.get_limiter("api")
        limiter2 = multi.get_limiter("api")
        assert limiter1 is limiter2
