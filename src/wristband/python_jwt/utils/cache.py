import threading
import time
from typing import Dict, Optional

from ..models import CacheOptions, LRUNode


class LRUCache:
    """
    Least Recently Used (LRU) cache with optional TTL support.

    This implementation uses a doubly-linked list combined with a hash map to achieve
    O(1) performance for all operations.

    Key features:
    - O(1) operations: Get, Set, Has, and eviction are all O(1)
    - LRU eviction: Based on actual access order with constant-time eviction
    - TTL support: Optional automatic expiration of entries
    - Memory safety: Bounded size with predictable memory usage
    - Framework agnostic: Works in any Python environment
    - Thread-safe operations: All operations are synchronous and atomic

    Example:
        ```python
        # JWKS key caching example
        jwks_cache = LRUCache(CacheOptions(max_size=20, ttl=3600000))  # 1 hour
        jwks_cache.set('kid123', public_key_pem)
        cached_key = jwks_cache.get('kid123')
        ```
    """

    def __init__(self, options: CacheOptions):
        """
        Create a new LRU cache instance with the specified configuration.

        Args:
            options: Configuration object specifying cache behavior

        Example:
            ```python
            # Simple cache for 100 keys
            cache = LRUCache(CacheOptions(max_size=100))

            # Cache with 60-minute expiration
            expiring_cache = LRUCache(CacheOptions(max_size=50, ttl=60 * 60 * 1000))
            ```
        """
        self._cache: Dict[str, LRUNode] = {}  # Hash map for O(1) key lookups pointing to doubly-linked list nodes.
        self._max_size = options.max_size  # Max entries allowed in the cache. Triggers LRU eviction when exceeded.
        self._ttl = (
            options.ttl
        )  # Optional time-to-live in milliseconds. If defined, entries expire after this duration.

        # Initialize dummy head and tail nodes to simplify edge cases
        self._head = LRUNode()  # Head of the doubly-linked list (most recently used)
        self._tail = LRUNode()  # Tail of the doubly-linked list (least recently used)
        self._head.next = self._tail
        self._tail.prev = self._head

        self._lock = threading.RLock()

    def get(self, key: str) -> Optional[str]:
        """
        Retrieve a value from the cache and move it to the front (most recently used).

        This method implements LRU behavior with O(1) performance by moving the accessed
        node to the head of the doubly-linked list. If the entry has expired based on TTL,
        it will be automatically removed and None will be returned.

        Args:
            key: The cache key to retrieve

        Returns:
            The cached value if found and not expired; None otherwise

        Example:
            ```python
            cache.set('kid123', 'public_key123')

            # Later...
            key123 = cache.get('kid123')   # 'public_key123' moves to front
            missing = cache.get('kid999')  # None

            # After TTL expiration (if configured)
            expired = cache.get('kid123')  # None (auto-removed)
            ```
        """
        with self._lock:
            # First check for existing key
            node = self._cache.get(key)
            if not node:
                return None

            # Check TTL expiration
            current_time_ms = int(time.time() * 1000)
            if self._ttl and current_time_ms - node.last_accessed > self._ttl:
                self._remove_node(node)
                del self._cache[key]
                return None

            # Move to front (most recently used) and update access time
            node.last_accessed = current_time_ms
            self._move_to_front(node)

            return node.value

    def set(self, key: str, value: str) -> None:
        """
        Store a value in the cache with O(1) LRU eviction when size limit is exceeded.

        If the key already exists, updates the value and moves it to the front.
        If adding a new entry would exceed max_size, evicts the least recently
        used entry (tail) in O(1) time before adding the new one.

        Args:
            key: The cache key to store
            value: The string value to cache

        Example:
            ```python
            # Store new entries
            cache.set('kid123', 'public_key123')
            cache.set('kid456', 'public_key456')

            # Update existing entry (moves to front, resets TTL if configured)
            cache.set('kid123', 'updated_public_key123')

            # When cache is full, LRU entry is automatically evicted in O(1) time
            cache.set('kid789', 'public_key789')  # Evicts tail node instantly
            ```
        """
        with self._lock:
            current_time_ms = int(time.time() * 1000)
            existing_node = self._cache.get(key)

            # Update existing node and make it most recently used
            if existing_node:
                existing_node.value = value
                existing_node.last_accessed = current_time_ms
                self._move_to_front(existing_node)
                return

            # Otherwise create a new node
            new_node = LRUNode(key=key, value=value, last_accessed=current_time_ms)
            self._cache[key] = new_node
            self._add_to_front(new_node)

            # Eviction occurs if over capacity
            if len(self._cache) > self._max_size:
                self._evict_least_recently_used()

    def has(self, key: str) -> bool:
        """
        Check if a key exists in the cache without updating access order.

        This is useful for existence checks that shouldn't affect LRU ordering.
        Automatically removes and returns False for expired entries.

        Args:
            key: The cache key to check

        Returns:
            True if the key exists and is not expired; False otherwise

        Example:
            ```python
            cache.set('key123', 'public_key123')

            if cache.has('key123'):
                print('Data exists in cache')
                # LRU order is NOT affected by this check

            # Check for expired entries
            if not cache.has('old_key'):
                print('Data missing or expired')
            ```
        """
        with self._lock:
            node = self._cache.get(key)
            if not node:
                return False

            # Check if expired
            current_time_ms = int(time.time() * 1000)
            if self._ttl and current_time_ms - node.last_accessed > self._ttl:
                self._remove_node(node)
                del self._cache[key]
                return False

            return True

    def delete(self, key: str) -> bool:
        """
        Remove a specific key from the cache in O(1) time.

        Args:
            key: The cache key to remove

        Returns:
            True if the key existed and was removed; False if it didn't exist

        Example:
            ```python
            cache.set('key123', 'public_key123')

            # Later, when entry expires
            was_removed = cache.delete('key123')   # True
            already_gone = cache.delete('key123')  # False
            ```
        """
        with self._lock:
            node = self._cache.get(key)
            if not node:
                return False

            self._remove_node(node)
            del self._cache[key]
            return True

    def clear(self) -> None:
        """
        Remove all entries from the cache.

        Resets the cache to an empty state and reinitializes the doubly-linked list.

        Example:
            ```python
            # Reset during testing
            cache.clear()
            print(cache.size())  # 0
            ```
        """
        with self._lock:
            self._cache.clear()
            self._head.next = self._tail
            self._tail.prev = self._head

    def size(self) -> int:
        """
        Return the current number of entries in the cache.

        Returns:
            The number of entries currently stored

        Example:
            ```python
            cache = LRUCache(CacheOptions(max_size=100))
            print(cache.size())  # 0

            cache.set('a', '1')
            cache.set('b', '2')
            print(cache.size())  # 2
            ```
        """
        with self._lock:
            return len(self._cache)

    def get_stats(self) -> Dict[str, int]:
        """
        Return cache statistics for monitoring and debugging.

        Returns:
            Dictionary containing current cache statistics

        Example:
            ```python
            stats = cache.get_stats()
            print(f"Cache utilization: {stats['size']}/{stats['max_size']}")
            print(f"Fill ratio: {(stats['size'] / stats['max_size'] * 100):.1f}%")
            ```
        """
        with self._lock:
            return {"size": len(self._cache), "max_size": self._max_size}

    def _move_to_front(self, node: LRUNode) -> None:
        """
        Move a node to the front of the doubly-linked list (most recently used).
        This is an O(1) operation that maintains LRU ordering.

        Args:
            node: The node to move to front
        """
        self._remove_node(node)
        self._add_to_front(node)

    def _add_to_front(self, node: LRUNode) -> None:
        """
        Add a node to the front of the doubly-linked list (after head).
        This is an O(1) operation.

        Args:
            node: The node to add to front
        """
        node.prev = self._head
        node.next = self._head.next

        if self._head.next:
            self._head.next.prev = node
        self._head.next = node

    def _remove_node(self, node: LRUNode) -> None:
        """
        Remove a node from the doubly-linked list. This is an O(1) operation.

        Args:
            node: The node to remove
        """
        if node.prev:
            node.prev.next = node.next
        if node.next:
            node.next.prev = node.prev
        node.prev = None
        node.next = None

    def _evict_least_recently_used(self) -> None:
        """
        Remove the least recently used entry (tail) from the cache.
        This is an O(1) operation that maintains cache size limits.
        """
        lru = self._tail.prev
        if lru and lru != self._head:
            self._remove_node(lru)
            del self._cache[lru.key]
