import threading
import time
import pytest

from wristband.python_jwt.models import CacheOptions, LRUNode
from wristband.python_jwt.utils.cache import LRUCache


class TestLRUCache:
    def test_constructor_valid_options(self):
        """Should create cache with valid options."""
        cache = LRUCache(CacheOptions(max_size=10))
        assert cache.size() == 0
        assert cache.get_stats()["max_size"] == 10

    def test_constructor_with_ttl_option(self):
        """Should create cache with TTL option."""
        cache = LRUCache(CacheOptions(max_size=10, ttl=5000))
        assert cache.size() == 0
        assert cache.get_stats()["max_size"] == 10

    def test_constructor_max_size_of_1(self):
        """Should handle maxSize of 1."""
        cache = LRUCache(CacheOptions(max_size=1))
        assert cache.get_stats()["max_size"] == 1

    def test_constructor_large_max_size(self):
        """Should handle large maxSize."""
        cache = LRUCache(CacheOptions(max_size=1000000))
        assert cache.get_stats()["max_size"] == 1000000

    def test_constructor_invalid_max_size(self):
        """Should throw error for invalid maxSize."""
        with pytest.raises(ValueError, match="max_size must be a positive integer"):
            CacheOptions(max_size=0)

        with pytest.raises(ValueError, match="max_size must be a positive integer"):
            CacheOptions(max_size=-1)

        with pytest.raises(ValueError, match="max_size must be a positive integer"):
            CacheOptions(max_size=1.5)

    def test_constructor_invalid_ttl(self):
        """Should throw error for invalid TTL."""
        # None TTL should not throw
        CacheOptions(max_size=10)

        # ttl=None should not throw
        CacheOptions(max_size=10, ttl=None)

        # These should throw because they're negative or non-integer
        with pytest.raises(ValueError, match="ttl must be a positive integer \\(if specified\\)"):
            CacheOptions(max_size=10, ttl=-1000)

        with pytest.raises(ValueError, match="ttl must be a positive integer \\(if specified\\)"):
            CacheOptions(max_size=10, ttl=100.5)

        # Valid TTL should not throw
        CacheOptions(max_size=10, ttl=100)


class TestLRUCacheBasicOperations:
    @pytest.fixture
    def cache(self):
        """Create a fresh cache for each test."""
        return LRUCache(CacheOptions(max_size=3))

    def test_set_and_get(self, cache):
        """Should store and retrieve values."""
        cache.set("key1", "value1")
        assert cache.get("key1") == "value1"

    def test_get_nonexistent_key(self, cache):
        """Should return None for non-existent keys."""
        assert cache.get("nonexistent") is None

    def test_set_existing_key_updates_value(self, cache):
        """Should update existing values and move to front."""
        cache.set("key1", "value1")
        cache.set("key1", "value2")  # This should update the value
        assert cache.get("key1") == "value2"
        assert cache.size() == 1

    def test_empty_string_values(self, cache):
        """Should handle empty string values."""
        cache.set("key1", "")
        assert cache.get("key1") == ""

    def test_empty_string_keys(self, cache):
        """Should handle empty string keys."""
        cache.set("", "value")
        assert cache.get("") == "value"

    def test_special_characters_in_keys(self, cache):
        """Should handle special characters in keys."""
        special_keys = ["key with spaces", "key-with-dashes", "key_with_underscores", "key.with.dots"]
        for key in special_keys:
            cache.set(key, f"value-{key}")
            assert cache.get(key) == f"value-{key}"

    def test_has_existing_keys(self, cache):
        """Should return True for existing keys."""
        cache.set("key1", "value1")
        assert cache.has("key1") is True

    def test_has_nonexistent_keys(self, cache):
        """Should return False for non-existent keys."""
        assert cache.has("nonexistent") is False

    def test_has_does_not_update_lru_order(self, cache):
        """Should not update access time or LRU order."""
        cache.set("key1", "value1")
        cache.set("key2", "value2")
        cache.set("key3", "value3")

        # key1 is now LRU, check existence without updating access time
        cache.has("key1")

        # Add key4 to trigger eviction - key1 should still be evicted
        cache.set("key4", "value4")
        assert cache.has("key1") is False

    def test_delete_existing_keys(self, cache):
        """Should remove existing keys."""
        cache.set("key1", "value1")
        assert cache.delete("key1") is True
        assert cache.get("key1") is None
        assert cache.size() == 0

    def test_delete_nonexistent_keys(self, cache):
        """Should return False for non-existent keys."""
        assert cache.delete("nonexistent") is False

    def test_delete_multiple_keys(self, cache):
        """Should handle multiple deletions."""
        cache.set("key1", "value1")
        cache.set("key2", "value2")

        assert cache.delete("key1") is True
        assert cache.delete("key2") is True
        assert cache.size() == 0

    def test_clear_all_entries(self, cache):
        """Should remove all entries."""
        cache.set("key1", "value1")
        cache.set("key2", "value2")
        cache.set("key3", "value3")

        cache.clear()
        assert cache.size() == 0
        assert cache.get("key1") is None
        assert cache.get("key2") is None
        assert cache.get("key3") is None

    def test_clear_empty_cache(self, cache):
        """Should work on empty cache."""
        cache.clear()
        assert cache.size() == 0

    def test_size_tracking(self, cache):
        """Should return correct size."""
        assert cache.size() == 0

        cache.set("key1", "value1")
        assert cache.size() == 1

        cache.set("key2", "value2")
        assert cache.size() == 2

        cache.delete("key1")
        assert cache.size() == 1

        cache.clear()
        assert cache.size() == 0


class TestLRUEviction:
    @pytest.fixture
    def cache(self):
        """Create a fresh cache for each test."""
        return LRUCache(CacheOptions(max_size=3))

    def test_evict_lru_when_capacity_exceeded(self, cache):
        """Should evict least recently used item when capacity exceeded."""
        # Fill cache to capacity
        cache.set("key1", "value1")
        cache.set("key2", "value2")
        cache.set("key3", "value3")
        assert cache.size() == 3

        # Add fourth item - should evict key1 (least recently used)
        cache.set("key4", "value4")
        assert cache.size() == 3
        assert cache.get("key1") is None  # Should be evicted
        assert cache.get("key2") == "value2"
        assert cache.get("key3") == "value3"
        assert cache.get("key4") == "value4"

    def test_update_lru_order_on_access(self, cache):
        """Should update LRU order on access."""
        cache.set("key1", "value1")
        time.sleep(0.001)  # Small delay to ensure different timestamps

        cache.set("key2", "value2")
        time.sleep(0.001)

        cache.set("key3", "value3")
        time.sleep(0.001)

        # Access key1 to make it most recently used
        cache.get("key1")
        time.sleep(0.001)

        # Add key4 - should evict key2 (now least recently used)
        cache.set("key4", "value4")
        assert cache.get("key1") == "value1"  # Recently accessed
        assert cache.get("key2") is None  # Should be evicted
        assert cache.get("key3") == "value3"
        assert cache.get("key4") == "value4"
        assert cache.size() == 3

    def test_update_lru_order_on_set_existing_key(self, cache):
        """Should update LRU order on set to existing key."""
        cache.set("key1", "value1")
        time.sleep(0.001)

        cache.set("key2", "value2")
        time.sleep(0.001)

        cache.set("key3", "value3")
        time.sleep(0.001)

        # Set key1 again to make it most recently used (moves to front)
        cache.set("key1", "new_value1")
        time.sleep(0.001)

        # Add key4 - should evict key2 (now least recently used)
        cache.set("key4", "value4")
        assert cache.get("key1") == "new_value1"  # Updated value, recently accessed
        assert cache.get("key2") is None  # Should be evicted
        assert cache.get("key3") == "value3"
        assert cache.get("key4") == "value4"
        assert cache.size() == 3

    def test_eviction_with_cache_size_1(self):
        """Should handle eviction with cache size of 1."""
        small_cache = LRUCache(CacheOptions(max_size=1))

        small_cache.set("key1", "value1")
        assert small_cache.get("key1") == "value1"
        assert small_cache.size() == 1

        small_cache.set("key2", "value2")
        assert small_cache.get("key1") is None
        assert small_cache.get("key2") == "value2"
        assert small_cache.size() == 1

    def test_maintain_lru_behavior_sequential_operations(self, cache):
        """Should maintain LRU behavior with sequential operations."""
        # Add entries with time gaps
        cache.set("oldest", "value1")
        time.sleep(0.001)

        cache.set("middle", "value2")
        time.sleep(0.001)

        cache.set("newest", "value3")
        time.sleep(0.001)

        # Trigger eviction - oldest should be evicted
        cache.set("trigger", "value4")

        assert cache.get("oldest") is None
        assert cache.get("middle") == "value2"
        assert cache.get("newest") == "value3"
        assert cache.get("trigger") == "value4"
        assert cache.size() == 3


class TestTTLFunctionality:
    @pytest.fixture
    def cache(self):
        """Create a fresh cache with TTL for each test."""
        return LRUCache(CacheOptions(max_size=5, ttl=100))  # 100ms TTL

    def test_return_values_within_ttl(self, cache):
        """Should return values within TTL."""
        cache.set("key1", "value1")
        assert cache.get("key1") == "value1"

    def test_expire_entries_after_ttl(self, cache):
        """Should expire entries after TTL based on lastAccessed time."""
        cache.set("key1", "value1")
        assert cache.get("key1") == "value1"

        # Wait for TTL to expire based on lastAccessed
        time.sleep(0.15)  # 150ms

        assert cache.get("key1") is None
        assert cache.size() == 0  # Should be auto-removed

    def test_extend_ttl_on_access(self, cache):
        """Should extend TTL on each access (lastAccessed update)."""
        cache.set("key1", "value1")

        # Access the key partway through TTL
        time.sleep(0.05)  # 50ms
        assert cache.get("key1") == "value1"  # This updates lastAccessed

        # Wait another 75ms (total 125ms from creation, but only 75ms from last access)
        time.sleep(0.075)

        # Should still exist because lastAccessed was updated
        assert cache.get("key1") == "value1"

        # Now wait full TTL from last access
        time.sleep(0.15)  # 150ms
        assert cache.get("key1") is None

    def test_ttl_in_has_method(self, cache):
        """Should handle TTL in has() method based on lastAccessed."""
        cache.set("key1", "value1")
        assert cache.has("key1") is True

        time.sleep(0.15)  # 150ms

        assert cache.has("key1") is False
        assert cache.size() == 0

    def test_extend_ttl_when_setting_existing_key(self, cache):
        """Should extend TTL when setting existing key (moves to front)."""
        cache.set("key1", "value1")

        # Wait part of the TTL
        time.sleep(0.05)  # 50ms

        # Set the key again (should update lastAccessed)
        cache.set("key1", "new_value")

        # Wait original TTL duration from initial creation
        time.sleep(0.075)  # 75ms (total 125ms from initial)

        # Should still exist because lastAccessed was updated by the second set()
        assert cache.get("key1") == "new_value"

        # Wait full TTL from the second set operation
        time.sleep(0.15)  # 150ms
        assert cache.get("key1") is None

    def test_no_expiration_without_ttl(self):
        """Should not expire if no TTL is set."""
        no_ttl_cache = LRUCache(CacheOptions(max_size=5))
        no_ttl_cache.set("key1", "value1")

        # Simulate time passing
        time.sleep(0.2)  # 200ms

        assert no_ttl_cache.get("key1") == "value1"
        assert no_ttl_cache.has("key1") is True

    def test_mixed_expired_and_non_expired_entries(self, cache):
        """Should handle mixed expired and non-expired entries."""
        cache.set("key1", "value1")

        time.sleep(0.05)  # 50ms

        cache.set("key2", "value2")  # Added later

        time.sleep(0.075)  # Total 125ms

        assert cache.get("key1") is None  # Expired (125ms > 100ms TTL)
        assert cache.get("key2") == "value2"  # Still valid (75ms < 100ms TTL)

    def test_has_not_updating_last_accessed(self, cache):
        """Should handle TTL with has() not updating lastAccessed."""
        cache.set("key1", "value1")

        # Wait part of TTL
        time.sleep(0.05)  # 50ms

        # has() should not extend TTL
        assert cache.has("key1") is True

        # Wait for original TTL to expire
        time.sleep(0.075)  # Total 125ms

        # Should be expired because has() didn't update lastAccessed
        assert cache.has("key1") is False
        assert cache.get("key1") is None


class TestGetStats:
    def test_return_correct_statistics(self):
        """Should return correct statistics."""
        cache = LRUCache(CacheOptions(max_size=10))

        stats = cache.get_stats()
        assert stats["size"] == 0
        assert stats["max_size"] == 10

        cache.set("key1", "value1")
        cache.set("key2", "value2")

        stats = cache.get_stats()
        assert stats["size"] == 2
        assert stats["max_size"] == 10

    def test_update_size_after_operations(self):
        """Should update size after operations."""
        cache = LRUCache(CacheOptions(max_size=3))

        cache.set("key1", "value1")
        assert cache.get_stats()["size"] == 1

        cache.set("key2", "value2")
        assert cache.get_stats()["size"] == 2

        cache.delete("key1")
        assert cache.get_stats()["size"] == 1

        cache.clear()
        assert cache.get_stats()["size"] == 0


class TestEdgeCases:
    def test_rapid_sequential_operations(self):
        """Should handle rapid sequential operations."""
        cache = LRUCache(CacheOptions(max_size=100))

        # Add many items rapidly
        for i in range(50):
            cache.set(f"key{i}", f"value{i}")

        assert cache.size() == 50

        # Access them all
        for i in range(50):
            assert cache.get(f"key{i}") == f"value{i}"

    def test_cache_overflow_correctly(self):
        """Should handle cache overflow correctly."""
        cache = LRUCache(CacheOptions(max_size=2))

        # Add items beyond capacity
        for i in range(10):
            cache.set(f"key{i}", f"value{i}")
            assert cache.size() <= 2

        # Should only have last 2 items
        assert cache.get("key8") == "value8"
        assert cache.get("key9") == "value9"
        assert cache.size() == 2

    def test_alternating_set_get_patterns(self):
        """Should handle alternating set/get patterns."""
        cache = LRUCache(CacheOptions(max_size=3))

        cache.set("key1", "value1")
        time.sleep(0.001)

        cache.get("key1")  # key1 becomes MRU
        time.sleep(0.001)

        cache.set("key2", "value2")  # key2 becomes MRU, key1 becomes LRU
        time.sleep(0.001)

        cache.get("key1")  # key1 becomes MRU again, key2 becomes LRU
        time.sleep(0.001)

        cache.set("key3", "value3")  # key3 becomes MRU, key1 in middle, key2 is LRU
        time.sleep(0.001)

        cache.get("key2")  # key2 becomes MRU, key3 in middle, key1 becomes LRU
        time.sleep(0.001)

        cache.set("key4", "value4")  # Should evict key1 (LRU)

        assert cache.size() == 3
        assert cache.get("key1") is None  # Should be evicted (was LRU)
        assert cache.get("key2") == "value2"  # Recently accessed
        assert cache.get("key3") == "value3"  # Middle
        assert cache.get("key4") == "value4"  # Just added

    def test_numeric_and_boolean_like_string_keys(self):
        """Should handle numeric and boolean-like string keys."""
        cache = LRUCache(CacheOptions(max_size=10))

        cache.set("123", "numeric")
        cache.set("true", "boolean")
        cache.set("null", "null value")
        cache.set("undefined", "undefined value")

        assert cache.get("123") == "numeric"
        assert cache.get("true") == "boolean"
        assert cache.get("null") == "null value"
        assert cache.get("undefined") == "undefined value"

    def test_maintain_o1_performance_frequent_evictions(self):
        """Should maintain O(1) performance with frequent evictions."""
        cache = LRUCache(CacheOptions(max_size=5))

        # Add many items to force frequent evictions
        start_time = time.time()
        for i in range(1000):
            cache.set(f"key{i}", f"value{i}")
        end_time = time.time()

        assert cache.size() == 5
        # Performance check - should complete quickly with O(1) evictions
        assert (end_time - start_time) < 0.1  # Should be very fast


class TestConsistencyAndStateManagement:
    @pytest.fixture
    def cache(self):
        """Create a fresh cache for each test."""
        return LRUCache(CacheOptions(max_size=3))

    def test_maintain_consistent_state_mixed_operations(self, cache):
        """Should maintain consistent state after mixed operations."""
        # Complex sequence of operations
        cache.set("a", "1")
        cache.set("b", "2")
        cache.get("a")  # Make 'a' more recent than 'b'
        cache.set("c", "3")
        cache.has("b")  # Check 'b' without updating access time
        cache.set("d", "4")  # Should evict 'b' (least recently accessed)
        cache.delete("a")
        cache.set("e", "5")

        assert cache.size() == 3
        assert cache.get("a") is None  # Deleted
        assert cache.get("b") is None  # Evicted
        assert cache.get("c") == "3"
        assert cache.get("d") == "4"
        assert cache.get("e") == "5"

    def test_concurrent_like_access_patterns(self, cache):
        """Should handle concurrent-like access patterns."""
        keys = ["user1", "user2", "user3", "user4", "user5"]

        # Simulate accessing different users
        for i, key in enumerate(keys):
            cache.set(key, f"data{i}")
            if i >= 3:
                # Cache is full, should start evicting
                assert cache.size() == 3

        # Verify final state - should have last 3 entries
        assert cache.get("user1") is None  # Evicted
        assert cache.get("user2") is None  # Evicted
        assert cache.get("user3") == "data2"
        assert cache.get("user4") == "data3"
        assert cache.get("user5") == "data4"

    def test_set_updating_values_for_existing_keys(self, cache):
        """Should handle set() updating values for existing keys."""
        cache.set("key1", "original")
        assert cache.get("key1") == "original"

        # Setting again should change value and update lastAccessed
        cache.set("key1", "new_value")
        assert cache.get("key1") == "new_value"  # Value changed

        # Fill cache: key1 is now MRU due to the second set()
        cache.set("key2", "value2")  # key2 is MRU, key1 becomes LRU
        cache.set("key3", "value3")  # key3 is MRU, key2 in middle, key1 is LRU
        cache.set("key4", "value4")  # Should evict key1 (LRU)

        assert cache.get("key1") is None  # Should be evicted (was LRU)
        assert cache.get("key2") == "value2"  # Should remain
        assert cache.get("key3") == "value3"
        assert cache.get("key4") == "value4"


class TestDoublyLinkedListEdgeCases:
    @pytest.fixture
    def cache(self):
        """Create a fresh cache for each test."""
        return LRUCache(CacheOptions(max_size=2))

    def test_move_to_front_head_node(self, cache):
        """Should handle moveToFront on head node."""
        cache.set("key1", "value1")
        cache.set("key2", "value2")

        # Access key2 (already at head) - should still work
        assert cache.get("key2") == "value2"

        # Verify structure is still intact
        assert cache.size() == 2
        assert cache.get("key1") == "value1"

    def test_remove_node_single_item_cache(self, cache):
        """Should handle removeNode on single item cache."""
        cache.set("key1", "value1")
        assert cache.size() == 1

        # Delete the only item
        assert cache.delete("key1") is True
        assert cache.size() == 0

        # Cache should be empty but functional
        cache.set("key2", "value2")
        assert cache.get("key2") == "value2"

    def test_evict_lru_edge_case(self):
        """Should handle evictLeastRecentlyUsed with edge case."""
        single_cache = LRUCache(CacheOptions(max_size=1))

        single_cache.set("key1", "value1")
        assert single_cache.get("key1") == "value1"

        # Add second item - should evict first
        single_cache.set("key2", "value2")
        assert single_cache.get("key1") is None
        assert single_cache.get("key2") == "value2"
        assert single_cache.size() == 1

    def test_add_to_front_remove_node_updates(self, cache):
        """Should handle addToFront and removeNode with head.next updates."""
        # Fill cache
        cache.set("key1", "value1")
        cache.set("key2", "value2")

        # Delete first item (tests removeNode with prev/next pointer updates)
        cache.delete("key1")
        assert cache.size() == 1

        # Add new item (tests addToFront with proper head.next setup)
        cache.set("key3", "value3")
        assert cache.get("key2") == "value2"
        assert cache.get("key3") == "value3"

    def test_remove_node_during_ttl_expiration(self):
        """Should handle removeNode edge cases during TTL expiration."""
        ttl_cache = LRUCache(CacheOptions(max_size=3, ttl=50))

        ttl_cache.set("key1", "value1")
        ttl_cache.set("key2", "value2")

        time.sleep(0.075)  # 75ms

        # Both get() calls will trigger removeNode for expired entries
        assert ttl_cache.get("key1") is None  # removeNode called
        assert ttl_cache.get("key2") is None  # removeNode called
        assert ttl_cache.size() == 0

    def test_complex_move_to_front_scenarios(self, cache):
        """Should handle complex moveToFront scenarios."""
        cache.set("key1", "value1")
        cache.set("key2", "value2")

        # key1 is now LRU, key2 is MRU
        # Access key1 to move it to front (tests moveToFront: removeNode then addToFront)
        cache.get("key1")

        # Now key2 should be LRU, key1 should be MRU
        cache.set("key3", "value3")  # Should evict key2

        assert cache.get("key1") == "value1"  # Should still exist
        assert cache.get("key2") is None  # Should be evicted
        assert cache.get("key3") == "value3"  # Should exist


class TestMemoryAndResourceManagement:
    def test_not_grow_beyond_max_size(self):
        """Should not grow beyond maxSize."""
        cache = LRUCache(CacheOptions(max_size=10))

        # Add way more than maxSize
        for i in range(100):
            cache.set(f"key{i}", f"value{i}")
            assert cache.size() <= 10

        assert cache.size() == 10

    def test_cleanup_expired_entries_on_access(self):
        """Should properly clean up expired entries on access."""
        cache = LRUCache(CacheOptions(max_size=5, ttl=50))

        cache.set("key1", "value1")
        cache.set("key2", "value2")
        assert cache.size() == 2

        time.sleep(0.075)  # 75ms

        # Access should clean up expired entries
        assert cache.get("key1") is None  # Should be expired and cleaned up
        assert cache.get("key2") is None  # Should also be expired and cleaned up

        # Size should now reflect the cleanup
        assert cache.size() == 0

    def test_empty_cache_operations_gracefully(self):
        """Should handle empty cache operations gracefully."""
        cache = LRUCache(CacheOptions(max_size=10))

        assert cache.get("anything") is None
        assert cache.has("anything") is False
        assert cache.delete("anything") is False
        assert cache.size() == 0

        cache.clear()  # Should not throw
        assert cache.size() == 0

    def test_clear_resetting_linked_list_properly(self):
        """Should handle clear() resetting linked list properly."""
        cache = LRUCache(CacheOptions(max_size=3))

        # Fill cache
        cache.set("key1", "value1")
        cache.set("key2", "value2")
        cache.set("key3", "value3")

        # Clear and verify head/tail reset
        cache.clear()
        assert cache.size() == 0

        # Should work normally after clear
        cache.set("new1", "value1")
        cache.set("new2", "value2")
        assert cache.get("new1") == "value1"
        assert cache.get("new2") == "value2"


class TestThreadSafety:
    def test_thread_safe_operations(self):
        """Should handle concurrent operations safely."""
        cache = LRUCache(CacheOptions(max_size=100))

        def worker(thread_id):
            for i in range(50):
                key = f"thread{thread_id}_key{i}"
                value = f"thread{thread_id}_value{i}"
                cache.set(key, value)
                retrieved = cache.get(key)
                assert retrieved == value or retrieved is None  # May be evicted

        threads = []
        for i in range(5):
            thread = threading.Thread(target=worker, args=(i,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        # Cache should maintain its invariants
        assert cache.size() <= 100

    def test_concurrent_eviction(self):
        """Should handle concurrent eviction safely."""
        cache = LRUCache(CacheOptions(max_size=10))

        def add_items(start, end):
            for i in range(start, end):
                cache.set(f"key{i}", f"value{i}")

        # Multiple threads adding items that will cause evictions
        threads = []
        for i in range(0, 100, 20):
            thread = threading.Thread(target=add_items, args=(i, i + 20))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        assert cache.size() <= 10

    def test_concurrent_get_set_delete(self):
        """Should handle concurrent get/set/delete operations."""
        cache = LRUCache(CacheOptions(max_size=50))
        results = []

        def mixed_operations(thread_id):
            thread_results = []
            for i in range(20):
                key = f"key{i % 10}"  # Reuse some keys

                # Set operation
                cache.set(key, f"value{thread_id}_{i}")

                # Get operation
                value = cache.get(key)
                thread_results.append(("get", key, value))

                # Occasionally delete
                if i % 5 == 0:
                    deleted = cache.delete(key)
                    thread_results.append(("delete", key, deleted))

            results.extend(thread_results)

        threads = []
        for i in range(3):
            thread = threading.Thread(target=mixed_operations, args=(i,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        # Verify cache is in a consistent state
        assert cache.size() >= 0
        assert cache.size() <= 50


class TestTimingAndPerformance:
    def test_ttl_calculation_precision(self):
        """Should handle TTL calculations with precise timing."""
        # Test with longer TTL to be more reliable
        cache = LRUCache(CacheOptions(max_size=5, ttl=100))  # 100ms TTL

        # Set a value
        cache.set("key1", "value1")

        # Wait for TTL to expire WITHOUT accessing the key
        time.sleep(0.12)  # 120ms > 100ms TTL

        # Now access - should be expired and return None
        assert cache.get("key1") is None

    def test_ttl_expiration_on_has(self):
        """Should expire entries when checked with has() method."""
        cache = LRUCache(CacheOptions(max_size=5, ttl=100))  # 100ms TTL

        cache.set("key1", "value1")
        assert cache.has("key1") is True

        # Wait for TTL to expire
        time.sleep(0.12)  # 120ms > 100ms TTL

        # has() should return False for expired entries
        assert cache.has("key1") is False
        assert cache.size() == 0  # Should be cleaned up

    def test_ttl_with_proper_mocking(self):
        """Test TTL with properly mocked time - simpler approach."""
        # Remove the problematic mocked test for now and just test that
        # TTL works with real timing
        cache = LRUCache(CacheOptions(max_size=5, ttl=100))  # 100ms TTL

        cache.set("key1", "value1")

        # Should exist immediately
        assert cache.get("key1") == "value1"

        # Wait for expiration
        time.sleep(0.12)  # 120ms > 100ms TTL

        # Should be expired
        assert cache.get("key1") is None

    def test_last_accessed_update_on_get(self):
        """Should update lastAccessed time on get operations."""
        cache = LRUCache(CacheOptions(max_size=5, ttl=100))  # 100ms TTL
        cache.set("key1", "value1")

        # Access partway through TTL - should extend the TTL
        time.sleep(0.05)  # 50ms
        cache.get("key1")  # This resets last_accessed

        # Wait another 70ms (total 120ms from creation, but only 70ms from last access)
        time.sleep(0.07)  # 70ms
        assert cache.get("key1") == "value1"  # Should still be valid

        # Wait full TTL from last access
        time.sleep(0.11)  # 110ms > 100ms TTL
        assert cache.get("key1") is None  # Should be expired

    def test_last_accessed_update_on_set(self):
        """Should update lastAccessed time on set operations."""
        cache = LRUCache(CacheOptions(max_size=5, ttl=100))  # 100ms TTL
        cache.set("key1", "value1")

        # Update value partway through TTL - should extend the TTL
        time.sleep(0.05)  # 50ms
        cache.set("key1", "new_value")  # This resets last_accessed

        # Wait another 70ms (total 120ms from creation, but only 70ms from last set)
        time.sleep(0.07)  # 70ms
        assert cache.get("key1") == "new_value"  # Should still be valid

        # Wait full TTL from last set
        time.sleep(0.11)  # 110ms > 100ms TTL
        assert cache.get("key1") is None  # Should be expired

    def test_performance_large_dataset(self):
        """Should maintain performance with large datasets."""
        cache = LRUCache(CacheOptions(max_size=1000))

        # Measure set operations
        start_time = time.time()
        for i in range(5000):
            cache.set(f"key{i}", f"value{i}")
        set_time = time.time() - start_time

        # Measure get operations
        start_time = time.time()
        for i in range(4000, 5000):  # Get recent items
            cache.get(f"key{i}")
        get_time = time.time() - start_time

        # Should be reasonably fast (adjust thresholds as needed)
        assert set_time < 1.0  # 5000 sets should complete in under 1 second
        assert get_time < 0.1  # 1000 gets should complete in under 0.1 seconds
        assert cache.size() == 1000

    def test_memory_efficiency(self):
        """Should efficiently manage memory usage."""
        cache = LRUCache(CacheOptions(max_size=100))

        # Fill cache beyond capacity multiple times
        for round_num in range(5):
            for i in range(150):  # More than max_size
                key = f"round{round_num}_key{i}"
                value = f"round{round_num}_value{i}" * 10  # Larger values
                cache.set(key, value)

        # Should maintain size limit
        assert cache.size() == 100

        # Clear and verify memory is released
        cache.clear()
        assert cache.size() == 0


class TestErrorHandling:
    def test_invalid_cache_options_types(self):
        """Should handle invalid types gracefully."""
        with pytest.raises(ValueError):
            CacheOptions(max_size="10")  # String instead of int

        with pytest.raises(ValueError):
            CacheOptions(max_size=10, ttl="100")  # String TTL

    def test_none_key_handling(self):
        """Should handle None keys appropriately."""
        cache = LRUCache(CacheOptions(max_size=10))

        # Python will convert None to string "None"
        cache.set(str(None), "none_value")
        assert cache.get(str(None)) == "none_value"

    def test_unicode_keys_and_values(self):
        """Should handle Unicode strings correctly."""
        cache = LRUCache(CacheOptions(max_size=10))

        unicode_key = "キー123"
        unicode_value = "値456"

        cache.set(unicode_key, unicode_value)
        assert cache.get(unicode_key) == unicode_value

    def test_large_string_values(self):
        """Should handle large string values."""
        cache = LRUCache(CacheOptions(max_size=5))

        large_value = "x" * 10000  # 10KB string
        cache.set("large_key", large_value)
        assert cache.get("large_key") == large_value

    def test_empty_cache_stats(self):
        """Should return correct stats for empty cache."""
        cache = LRUCache(CacheOptions(max_size=10))
        stats = cache.get_stats()

        assert isinstance(stats, dict)
        assert stats["size"] == 0
        assert stats["max_size"] == 10
        assert len(stats) == 2  # Only size and max_size


class TestLRUNodeModel:
    def test_lru_node_initialization(self):
        """Should initialize LRUNode correctly."""
        node = LRUNode()
        assert node.key == ""
        assert node.value == ""
        assert node.last_accessed == 0
        assert node.prev is None
        assert node.next is None

    def test_lru_node_with_parameters(self):
        """Should initialize LRUNode with parameters."""
        current_time = int(time.time() * 1000)
        node = LRUNode(key="test_key", value="test_value", last_accessed=current_time)

        assert node.key == "test_key"
        assert node.value == "test_value"
        assert node.last_accessed == current_time
        assert node.prev is None
        assert node.next is None

    def test_lru_node_linking(self):
        """Should handle node linking correctly."""
        node1 = LRUNode(key="key1", value="value1")
        node2 = LRUNode(key="key2", value="value2")

        # Link nodes
        node1.next = node2
        node2.prev = node1

        assert node1.next == node2
        assert node2.prev == node1


class TestCacheOptionsModel:
    def test_cache_options_initialization(self):
        """Should initialize CacheOptions correctly."""
        options = CacheOptions(max_size=100)
        assert options.max_size == 100
        assert options.ttl is None

    def test_cache_options_with_ttl(self):
        """Should initialize CacheOptions with TTL."""
        options = CacheOptions(max_size=50, ttl=5000)
        assert options.max_size == 50
        assert options.ttl == 5000

    def test_cache_options_validation_edge_cases(self):
        """Should validate edge cases correctly."""
        # Minimum valid values
        options = CacheOptions(max_size=1, ttl=1)
        assert options.max_size == 1
        assert options.ttl == 1

        # Large values
        options = CacheOptions(max_size=1000000, ttl=86400000)  # 1 day in ms
        assert options.max_size == 1000000
        assert options.ttl == 86400000


class TestIntegration:
    """Integration tests combining multiple cache features."""

    def test_lru_with_ttl_integration(self):
        """Should properly integrate LRU eviction with TTL expiration."""
        cache = LRUCache(CacheOptions(max_size=3, ttl=100))

        # Add items that will expire
        cache.set("expire_soon1", "value1")
        time.sleep(0.05)
        cache.set("expire_soon2", "value2")
        time.sleep(0.05)

        # Add item that causes LRU eviction
        cache.set("newer1", "value3")
        cache.set("newer2", "value4")  # This should evict expire_soon1 (LRU)

        assert cache.size() == 3
        assert cache.get("expire_soon1") is None  # Evicted by LRU

        # Check expire_soon2 exists but DON'T call get() as that would reset TTL
        assert cache.has("expire_soon2") is True  # Still valid, has() doesn't reset TTL

        # Wait for TTL expiration of expire_soon2 (100ms from when it was set)
        time.sleep(0.06)  # Total >100ms for expire_soon2

        assert cache.has("expire_soon2") is False  # Expired by TTL (has() checks expiration)
        assert cache.get("newer1") == "value3"  # Still valid
        assert cache.get("newer2") == "value4"  # Still valid

    def test_complex_usage_pattern(self):
        """Should handle complex real-world usage patterns."""
        cache = LRUCache(CacheOptions(max_size=5, ttl=200))

        # Simulate JWT key caching scenario
        keys = {
            "kid_1": "-----BEGIN PUBLIC KEY-----\nMIIBIjAN...",
            "kid_2": "-----BEGIN PUBLIC KEY-----\nMIIBIjAN...",
            "kid_3": "-----BEGIN PUBLIC KEY-----\nMIIBIjAN...",
        }

        # Cache keys with realistic access patterns
        for kid, key in keys.items():
            cache.set(kid, key)

        # Simulate frequent access to some keys
        for _ in range(10):
            cache.get("kid_1")  # Very frequent
            if _ % 2 == 0:
                cache.get("kid_2")  # Moderate frequency

        # Add more keys to trigger eviction
        cache.set("kid_4", "new_key_4")
        cache.set("kid_5", "new_key_5")
        cache.set("kid_6", "new_key_6")  # Should evict kid_3 (least accessed)

        assert cache.get("kid_1") is not None  # Frequently accessed, should remain
        assert cache.get("kid_2") is not None  # Moderately accessed, should remain
        assert cache.get("kid_3") is None  # Should be evicted
        assert cache.size() == 5

    def test_stress_test_combined_features(self):
        """Should handle stress testing of combined features."""
        cache = LRUCache(CacheOptions(max_size=20, ttl=50))

        # Rapid operations with mixed patterns
        for i in range(100):
            # Add new entries
            cache.set(f"key_{i}", f"value_{i}")

            # Access some old entries to keep them alive
            if i > 10:
                cache.get(f"key_{i-5}")

            # Check existence without updating access time
            if i > 5:
                cache.has(f"key_{i-3}")

            # Occasionally delete entries
            if i % 10 == 0 and i > 0:
                cache.delete(f"key_{i-1}")

        # Cache should maintain its constraints
        assert cache.size() <= 20

        # Wait for TTL expiration and verify cleanup
        time.sleep(0.06)

        # Access cache to trigger cleanup of expired entries
        cache.get("non_existent")

        # Add new entry to potentially trigger more cleanup
        cache.set("final_key", "final_value")
        assert cache.get("final_key") == "final_value"
