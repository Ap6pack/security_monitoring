"""Unit tests for cache module."""


import pytest

from security_scanner.storage.cache import CacheEntry, DNSCache


class TestCacheEntryInit:
    """Test CacheEntry initialization."""

    def test_init_stores_value(self) -> None:
        """Test that value is stored correctly."""
        entry = CacheEntry(value="1.2.3.4", ttl=300)
        assert entry.value == "1.2.3.4"

    def test_init_stores_ttl(self) -> None:
        """Test that TTL is stored correctly."""
        entry = CacheEntry(value="1.2.3.4", ttl=300)
        assert entry.ttl == 300

    def test_init_sets_timestamp(self) -> None:
        """Test that timestamp is set on creation."""
        entry = CacheEntry(value="test", ttl=60)
        assert entry.timestamp > 0

    def test_init_with_zero_ttl(self) -> None:
        """Test initialization with TTL of zero (never expire)."""
        entry = CacheEntry(value="permanent", ttl=0)
        assert entry.ttl == 0


class TestCacheEntryIsExpired:
    """Test CacheEntry.is_expired() method."""

    def test_not_expired_within_ttl(self) -> None:
        """Test entry is not expired within TTL period."""
        entry = CacheEntry(value="test", ttl=3600)
        assert entry.is_expired() is False

    def test_expired_after_ttl(self) -> None:
        """Test entry is expired after TTL period."""
        entry = CacheEntry(value="test", ttl=60)
        # Simulate time passing beyond TTL
        entry.timestamp = entry.timestamp - 120  # 120 seconds ago
        assert entry.is_expired() is True

    def test_zero_ttl_never_expires(self) -> None:
        """Test that TTL of 0 means the entry never expires."""
        entry = CacheEntry(value="permanent", ttl=0)
        # Even with old timestamp, should not expire
        entry.timestamp = entry.timestamp - 999999
        assert entry.is_expired() is False

    def test_expired_exactly_at_ttl_boundary(self) -> None:
        """Test entry expiration at the TTL boundary."""
        entry = CacheEntry(value="test", ttl=60)
        # Set timestamp to exactly 61 seconds ago (just past TTL)
        import time

        entry.timestamp = time.time() - 61
        assert entry.is_expired() is True

    def test_not_expired_just_before_ttl(self) -> None:
        """Test entry is not expired just before TTL."""
        entry = CacheEntry(value="test", ttl=60)
        import time

        entry.timestamp = time.time() - 59
        assert entry.is_expired() is False


class TestDNSCacheInit:
    """Test DNSCache initialization."""

    def test_default_params(self) -> None:
        """Test initialization with default parameters."""
        cache = DNSCache()
        assert cache.max_size == 10000
        assert cache.default_ttl == 3600

    def test_custom_params(self) -> None:
        """Test initialization with custom parameters."""
        cache = DNSCache(max_size=500, default_ttl=120)
        assert cache.max_size == 500
        assert cache.default_ttl == 120

    def test_empty_on_init(self) -> None:
        """Test that cache starts empty."""
        cache = DNSCache()
        assert cache.size() == 0


class TestDNSCacheMakeKey:
    """Test DNSCache._make_key() method."""

    def test_make_key_format(self) -> None:
        """Test key format is domain:record_type."""
        cache = DNSCache()
        key = cache._make_key("example.com", "A")
        assert key == "example.com:A"

    def test_make_key_lowercases_domain(self) -> None:
        """Test that domain is lowercased in key."""
        cache = DNSCache()
        key = cache._make_key("EXAMPLE.COM", "A")
        assert key == "example.com:A"

    def test_make_key_uppercases_record_type(self) -> None:
        """Test that record type is uppercased in key."""
        cache = DNSCache()
        key = cache._make_key("example.com", "aaaa")
        assert key == "example.com:AAAA"


class TestDNSCacheGet:
    """Test DNSCache.get() method."""

    def test_get_cache_miss(self) -> None:
        """Test get returns None on cache miss."""
        cache = DNSCache()
        result = cache.get("example.com", "A")
        assert result is None

    def test_get_cache_hit(self) -> None:
        """Test get returns value on cache hit."""
        cache = DNSCache()
        cache.set("example.com", "A", ["1.2.3.4"])
        result = cache.get("example.com", "A")
        assert result == ["1.2.3.4"]

    def test_get_expired_entry_returns_none(self) -> None:
        """Test get returns None and removes expired entry."""
        cache = DNSCache(default_ttl=60)
        cache.set("example.com", "A", ["1.2.3.4"])
        # Manually expire the entry
        key = cache._make_key("example.com", "A")
        cache._cache[key].timestamp -= 120  # 120 seconds ago
        result = cache.get("example.com", "A")
        assert result is None
        # Entry should be removed from cache
        assert key not in cache._cache

    def test_get_expired_entry_removed_from_access_order(self) -> None:
        """Test that expired entry is removed from access order."""
        cache = DNSCache(default_ttl=60)
        cache.set("example.com", "A", ["1.2.3.4"])
        key = cache._make_key("example.com", "A")
        cache._cache[key].timestamp -= 120
        cache.get("example.com", "A")
        assert key not in cache._access_order

    def test_get_updates_access_order(self) -> None:
        """Test that get updates access order for LRU."""
        cache = DNSCache()
        cache.set("a.com", "A", ["1.1.1.1"])
        cache.set("b.com", "A", ["2.2.2.2"])
        # Access a.com to move it to the end
        cache.get("a.com", "A")
        assert cache._access_order[-1] == "a.com:A"

    def test_get_case_insensitive_domain(self) -> None:
        """Test that get works case-insensitively for domain."""
        cache = DNSCache()
        cache.set("EXAMPLE.COM", "A", ["1.2.3.4"])
        result = cache.get("example.com", "A")
        assert result == ["1.2.3.4"]

    def test_get_different_record_types(self) -> None:
        """Test getting different record types for the same domain."""
        cache = DNSCache()
        cache.set("example.com", "A", ["1.2.3.4"])
        cache.set("example.com", "AAAA", ["::1"])
        assert cache.get("example.com", "A") == ["1.2.3.4"]
        assert cache.get("example.com", "AAAA") == ["::1"]


class TestDNSCacheSet:
    """Test DNSCache.set() method."""

    def test_set_basic(self) -> None:
        """Test basic set operation."""
        cache = DNSCache()
        cache.set("example.com", "A", ["1.2.3.4"])
        assert cache.size() == 1
        assert cache.get("example.com", "A") == ["1.2.3.4"]

    def test_set_with_custom_ttl(self) -> None:
        """Test set with explicit TTL override."""
        cache = DNSCache(default_ttl=3600)
        cache.set("example.com", "A", ["1.2.3.4"], ttl=120)
        key = cache._make_key("example.com", "A")
        assert cache._cache[key].ttl == 120

    def test_set_uses_default_ttl(self) -> None:
        """Test set uses default TTL when none specified."""
        cache = DNSCache(default_ttl=3600)
        cache.set("example.com", "A", ["1.2.3.4"])
        key = cache._make_key("example.com", "A")
        assert cache._cache[key].ttl == 3600

    def test_set_updates_existing_entry(self) -> None:
        """Test that setting the same key updates the value."""
        cache = DNSCache()
        cache.set("example.com", "A", ["1.2.3.4"])
        cache.set("example.com", "A", ["5.6.7.8"])
        assert cache.get("example.com", "A") == ["5.6.7.8"]
        assert cache.size() == 1

    def test_set_lru_eviction_when_full(self) -> None:
        """Test LRU eviction when cache is full."""
        cache = DNSCache(max_size=2)
        cache.set("a.com", "A", ["1.1.1.1"])
        cache.set("b.com", "A", ["2.2.2.2"])
        # Cache is now full; adding new entry should evict oldest
        cache.set("c.com", "A", ["3.3.3.3"])
        assert cache.size() == 2
        assert cache.get("a.com", "A") is None  # evicted
        assert cache.get("b.com", "A") == ["2.2.2.2"]
        assert cache.get("c.com", "A") == ["3.3.3.3"]

    def test_set_lru_eviction_respects_access_order(self) -> None:
        """Test that LRU eviction respects access order."""
        cache = DNSCache(max_size=2)
        cache.set("a.com", "A", ["1.1.1.1"])
        cache.set("b.com", "A", ["2.2.2.2"])
        # Access a.com to make it most recently used
        cache.get("a.com", "A")
        # Adding new entry should evict b.com (least recently used)
        cache.set("c.com", "A", ["3.3.3.3"])
        assert cache.get("a.com", "A") == ["1.1.1.1"]
        assert cache.get("b.com", "A") is None  # evicted
        assert cache.get("c.com", "A") == ["3.3.3.3"]

    def test_set_no_eviction_on_update(self) -> None:
        """Test that updating existing key does not trigger eviction."""
        cache = DNSCache(max_size=2)
        cache.set("a.com", "A", ["1.1.1.1"])
        cache.set("b.com", "A", ["2.2.2.2"])
        # Update existing entry should NOT evict
        cache.set("a.com", "A", ["9.9.9.9"])
        assert cache.size() == 2
        assert cache.get("a.com", "A") == ["9.9.9.9"]
        assert cache.get("b.com", "A") == ["2.2.2.2"]

    def test_set_updates_access_order(self) -> None:
        """Test that set moves key to end of access order."""
        cache = DNSCache()
        cache.set("a.com", "A", ["1.1.1.1"])
        cache.set("b.com", "A", ["2.2.2.2"])
        cache.set("a.com", "A", ["9.9.9.9"])
        assert cache._access_order[-1] == "a.com:A"


class TestDNSCacheEvictOldest:
    """Test DNSCache._evict_oldest() method."""

    def test_evict_oldest_removes_first_entry(self) -> None:
        """Test that _evict_oldest removes the first entry in access order."""
        cache = DNSCache()
        cache.set("a.com", "A", ["1.1.1.1"])
        cache.set("b.com", "A", ["2.2.2.2"])
        cache._evict_oldest()
        assert cache.get("a.com", "A") is None
        assert cache.get("b.com", "A") == ["2.2.2.2"]

    def test_evict_oldest_on_empty_cache(self) -> None:
        """Test _evict_oldest on empty cache does nothing."""
        cache = DNSCache()
        cache._evict_oldest()  # Should not raise
        assert cache.size() == 0

    def test_evict_oldest_removes_from_access_order(self) -> None:
        """Test that eviction removes key from access order."""
        cache = DNSCache()
        cache.set("a.com", "A", ["1.1.1.1"])
        cache._evict_oldest()
        assert "a.com:A" not in cache._access_order


class TestDNSCacheClear:
    """Test DNSCache.clear() method."""

    def test_clear_empties_cache(self) -> None:
        """Test that clear removes all entries."""
        cache = DNSCache()
        cache.set("a.com", "A", ["1.1.1.1"])
        cache.set("b.com", "A", ["2.2.2.2"])
        cache.clear()
        assert cache.size() == 0

    def test_clear_empties_access_order(self) -> None:
        """Test that clear also clears the access order list."""
        cache = DNSCache()
        cache.set("a.com", "A", ["1.1.1.1"])
        cache.clear()
        assert len(cache._access_order) == 0

    def test_clear_on_empty_cache(self) -> None:
        """Test that clear on empty cache does nothing."""
        cache = DNSCache()
        cache.clear()
        assert cache.size() == 0


class TestDNSCacheClearExpired:
    """Test DNSCache.clear_expired() method."""

    def test_clear_expired_removes_expired_entries(self) -> None:
        """Test that clear_expired removes expired entries."""
        cache = DNSCache(default_ttl=60)
        cache.set("a.com", "A", ["1.1.1.1"])
        cache.set("b.com", "A", ["2.2.2.2"])
        # Expire one entry
        key = cache._make_key("a.com", "A")
        cache._cache[key].timestamp -= 120
        removed = cache.clear_expired()
        assert removed == 1
        assert cache.get("a.com", "A") is None
        assert cache.get("b.com", "A") == ["2.2.2.2"]

    def test_clear_expired_returns_zero_when_none_expired(self) -> None:
        """Test that clear_expired returns 0 when nothing is expired."""
        cache = DNSCache(default_ttl=3600)
        cache.set("a.com", "A", ["1.1.1.1"])
        removed = cache.clear_expired()
        assert removed == 0

    def test_clear_expired_removes_from_access_order(self) -> None:
        """Test that clear_expired removes keys from access order."""
        cache = DNSCache(default_ttl=60)
        cache.set("a.com", "A", ["1.1.1.1"])
        key = cache._make_key("a.com", "A")
        cache._cache[key].timestamp -= 120
        cache.clear_expired()
        assert key not in cache._access_order

    def test_clear_expired_all_entries(self) -> None:
        """Test clearing when all entries are expired."""
        cache = DNSCache(default_ttl=60)
        cache.set("a.com", "A", ["1.1.1.1"])
        cache.set("b.com", "A", ["2.2.2.2"])
        # Expire all entries
        for entry in cache._cache.values():
            entry.timestamp -= 120
        removed = cache.clear_expired()
        assert removed == 2
        assert cache.size() == 0

    def test_clear_expired_on_empty_cache(self) -> None:
        """Test clear_expired on empty cache returns 0."""
        cache = DNSCache()
        removed = cache.clear_expired()
        assert removed == 0


class TestDNSCacheStats:
    """Test DNSCache.stats() method."""

    def test_stats_empty_cache(self) -> None:
        """Test stats on empty cache."""
        cache = DNSCache(max_size=100)
        stats = cache.stats()
        assert stats["size"] == 0
        assert stats["max_size"] == 100
        assert stats["expired"] == 0
        assert stats["utilization"] == 0.0

    def test_stats_with_entries(self) -> None:
        """Test stats with populated cache."""
        cache = DNSCache(max_size=10)
        cache.set("a.com", "A", ["1.1.1.1"])
        cache.set("b.com", "A", ["2.2.2.2"])
        stats = cache.stats()
        assert stats["size"] == 2
        assert stats["max_size"] == 10
        assert stats["utilization"] == pytest.approx(0.2)

    def test_stats_with_expired_entries(self) -> None:
        """Test stats counts expired entries."""
        cache = DNSCache(max_size=10, default_ttl=60)
        cache.set("a.com", "A", ["1.1.1.1"])
        cache.set("b.com", "A", ["2.2.2.2"])
        # Expire one entry
        key = cache._make_key("a.com", "A")
        cache._cache[key].timestamp -= 120
        stats = cache.stats()
        assert stats["expired"] == 1
        assert stats["size"] == 2  # expired entries still counted in size

    def test_stats_utilization_calculation(self) -> None:
        """Test utilization is calculated correctly."""
        cache = DNSCache(max_size=4)
        cache.set("a.com", "A", ["1.1.1.1"])
        cache.set("b.com", "A", ["2.2.2.2"])
        stats = cache.stats()
        assert stats["utilization"] == pytest.approx(0.5)

    def test_stats_full_cache(self) -> None:
        """Test stats when cache is full."""
        cache = DNSCache(max_size=2)
        cache.set("a.com", "A", ["1.1.1.1"])
        cache.set("b.com", "A", ["2.2.2.2"])
        stats = cache.stats()
        assert stats["utilization"] == pytest.approx(1.0)


class TestDNSCacheContains:
    """Test DNSCache.contains() method."""

    def test_contains_existing_entry(self) -> None:
        """Test contains returns True for existing non-expired entry."""
        cache = DNSCache()
        cache.set("example.com", "A", ["1.2.3.4"])
        assert cache.contains("example.com", "A") is True

    def test_contains_missing_entry(self) -> None:
        """Test contains returns False for missing entry."""
        cache = DNSCache()
        assert cache.contains("example.com", "A") is False

    def test_contains_expired_entry(self) -> None:
        """Test contains returns False for expired entry."""
        cache = DNSCache(default_ttl=60)
        cache.set("example.com", "A", ["1.2.3.4"])
        key = cache._make_key("example.com", "A")
        cache._cache[key].timestamp -= 120
        assert cache.contains("example.com", "A") is False


class TestDNSCacheSize:
    """Test DNSCache.size() method."""

    def test_size_empty(self) -> None:
        """Test size of empty cache."""
        cache = DNSCache()
        assert cache.size() == 0

    def test_size_after_additions(self) -> None:
        """Test size after adding entries."""
        cache = DNSCache()
        cache.set("a.com", "A", ["1.1.1.1"])
        cache.set("b.com", "A", ["2.2.2.2"])
        assert cache.size() == 2
