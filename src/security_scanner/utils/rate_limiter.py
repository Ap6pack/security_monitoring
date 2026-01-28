"""Token bucket rate limiter for API calls."""

import asyncio
import time
from typing import Optional


class RateLimiter:
    """
    Token bucket rate limiter for controlling request rates.

    Uses a token bucket algorithm to limit the rate of operations while
    allowing for bursts within the defined capacity.
    """

    def __init__(
        self,
        rate: float,
        burst: int = 1,
        initial_tokens: Optional[int] = None,
    ) -> None:
        """
        Initialize the rate limiter.

        Args:
            rate: Number of tokens to add per second
            burst: Maximum number of tokens in the bucket (burst capacity)
            initial_tokens: Initial number of tokens (defaults to burst capacity)
        """
        self.rate = rate
        self.burst = burst
        self.tokens: float = float(initial_tokens if initial_tokens is not None else burst)
        self.last_update = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, tokens: int = 1) -> None:
        """
        Acquire tokens from the bucket, waiting if necessary.

        Args:
            tokens: Number of tokens to acquire
        """
        async with self._lock:
            while True:
                now = time.monotonic()
                elapsed = now - self.last_update

                # Add tokens based on elapsed time
                self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
                self.last_update = now

                if self.tokens >= tokens:
                    self.tokens -= tokens
                    return

                # Calculate wait time for required tokens
                tokens_needed = tokens - self.tokens
                wait_time = tokens_needed / self.rate

                # Release lock while waiting
                await asyncio.sleep(wait_time)

    async def try_acquire(self, tokens: int = 1) -> bool:
        """
        Try to acquire tokens without waiting.

        Args:
            tokens: Number of tokens to acquire

        Returns:
            True if tokens were acquired, False otherwise
        """
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_update

            # Add tokens based on elapsed time
            self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
            self.last_update = now

            if self.tokens >= tokens:
                self.tokens -= tokens
                return True

            return False

    def reset(self) -> None:
        """Reset the rate limiter to initial state."""
        self.tokens = self.burst
        self.last_update = time.monotonic()

    @property
    def available_tokens(self) -> float:
        """Get the current number of available tokens."""
        now = time.monotonic()
        elapsed = now - self.last_update
        return min(self.burst, self.tokens + elapsed * self.rate)


class MultiRateLimiter:
    """
    Manage multiple rate limiters for different resources.

    Useful for handling different rate limits for different APIs or endpoints.
    """

    def __init__(self) -> None:
        """Initialize the multi-rate limiter."""
        self._limiters: dict[str, RateLimiter] = {}

    def add_limiter(self, name: str, rate: float, burst: int = 1) -> None:
        """
        Add a rate limiter for a specific resource.

        Args:
            name: Identifier for the resource
            rate: Tokens per second
            burst: Burst capacity
        """
        self._limiters[name] = RateLimiter(rate=rate, burst=burst)

    async def acquire(self, name: str, tokens: int = 1) -> None:
        """
        Acquire tokens from a specific rate limiter.

        Args:
            name: Identifier for the resource
            tokens: Number of tokens to acquire

        Raises:
            KeyError: If the named rate limiter doesn't exist
        """
        if name not in self._limiters:
            raise KeyError(f"Rate limiter '{name}' not found")
        await self._limiters[name].acquire(tokens)

    async def try_acquire(self, name: str, tokens: int = 1) -> bool:
        """
        Try to acquire tokens without waiting.

        Args:
            name: Identifier for the resource
            tokens: Number of tokens to acquire

        Returns:
            True if tokens were acquired, False otherwise

        Raises:
            KeyError: If the named rate limiter doesn't exist
        """
        if name not in self._limiters:
            raise KeyError(f"Rate limiter '{name}' not found")
        return await self._limiters[name].try_acquire(tokens)

    def get_limiter(self, name: str) -> RateLimiter:
        """
        Get a specific rate limiter.

        Args:
            name: Identifier for the resource

        Returns:
            The rate limiter instance

        Raises:
            KeyError: If the named rate limiter doesn't exist
        """
        if name not in self._limiters:
            raise KeyError(f"Rate limiter '{name}' not found")
        return self._limiters[name]
