"""TTL-aware cache for DNS and other results."""

import time
from typing import Any, Generic, TypeVar

T = TypeVar("T")


class CacheEntry(Generic[T]):
    """Cache entry with TTL and timestamp."""

    def __init__(self, value: T, ttl: int) -> None:
        """
        Initialize cache entry.

        Args:
            value: Value to cache
            ttl: Time to live in seconds
        """
        self.value = value
        self.ttl = ttl
        self.timestamp = time.time()

    def is_expired(self) -> bool:
        """Check if the cache entry is expired."""
        if self.ttl == 0:
            return False  # TTL of 0 means never expire
        return time.time() - self.timestamp > self.ttl


class DNSCache:
    """
    TTL-aware cache for DNS resolution results.

    Uses the TTL from DNS records to determine cache expiration.
    Implements a simple LRU eviction policy when cache is full.
    """

    def __init__(self, max_size: int = 10000, default_ttl: int = 3600) -> None:
        """
        Initialize the DNS cache.

        Args:
            max_size: Maximum number of entries in cache
            default_ttl: Default TTL for entries without explicit TTL
        """
        self.max_size = max_size
        self.default_ttl = default_ttl
        self._cache: dict[str, CacheEntry[Any]] = {}
        self._access_order: list[str] = []  # Track access order for LRU

    def _make_key(self, domain: str, record_type: str) -> str:
        """Create cache key from domain and record type."""
        return f"{domain.lower()}:{record_type.upper()}"

    def get(self, domain: str, record_type: str) -> Any | None:
        """
        Get a cached value.

        Args:
            domain: Domain name
            record_type: DNS record type (A, AAAA, CNAME, etc.)

        Returns:
            Cached value if found and not expired, None otherwise
        """
        key = self._make_key(domain, record_type)
        entry = self._cache.get(key)

        if entry is None:
            return None

        if entry.is_expired():
            # Remove expired entry
            del self._cache[key]
            if key in self._access_order:
                self._access_order.remove(key)
            return None

        # Update access order for LRU
        if key in self._access_order:
            self._access_order.remove(key)
        self._access_order.append(key)

        return entry.value

    def set(
        self,
        domain: str,
        record_type: str,
        value: Any,
        ttl: int | None = None,
    ) -> None:
        """
        Set a cache value.

        Args:
            domain: Domain name
            record_type: DNS record type
            value: Value to cache
            ttl: Time to live in seconds (uses default if not specified)
        """
        key = self._make_key(domain, record_type)

        # Evict oldest entry if cache is full
        if len(self._cache) >= self.max_size and key not in self._cache:
            self._evict_oldest()

        ttl = ttl if ttl is not None else self.default_ttl
        self._cache[key] = CacheEntry(value, ttl)

        # Update access order
        if key in self._access_order:
            self._access_order.remove(key)
        self._access_order.append(key)

    def _evict_oldest(self) -> None:
        """Evict the oldest (least recently used) entry."""
        if self._access_order:
            oldest_key = self._access_order.pop(0)
            if oldest_key in self._cache:
                del self._cache[oldest_key]

    def clear(self) -> None:
        """Clear all cache entries."""
        self._cache.clear()
        self._access_order.clear()

    def clear_expired(self) -> int:
        """
        Remove all expired entries.

        Returns:
            Number of entries removed
        """
        expired_keys = [key for key, entry in self._cache.items() if entry.is_expired()]

        for key in expired_keys:
            del self._cache[key]
            if key in self._access_order:
                self._access_order.remove(key)

        return len(expired_keys)

    def size(self) -> int:
        """Get the current cache size."""
        return len(self._cache)

    def contains(self, domain: str, record_type: str) -> bool:
        """
        Check if a key exists in cache and is not expired.

        Args:
            domain: Domain name
            record_type: DNS record type

        Returns:
            True if key exists and is not expired
        """
        return self.get(domain, record_type) is not None

    def stats(self) -> dict[str, Any]:
        """
        Get cache statistics.

        Returns:
            Dictionary with cache statistics
        """
        expired_count = sum(1 for entry in self._cache.values() if entry.is_expired())
        return {
            "size": len(self._cache),
            "max_size": self.max_size,
            "expired": expired_count,
            "utilization": len(self._cache) / self.max_size if self.max_size > 0 else 0,
        }
