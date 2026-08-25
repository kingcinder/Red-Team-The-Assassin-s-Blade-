"""
RedTeam Harness — Smart Result Cache (v4.0 Phase 2)
LRU cache keyed by tool+args hash with TTL expiration.
Identical scans (e.g., nmap of the same target/ports) never re-run
within TTL, saving time on long engagements with repeated probes.
"""
import hashlib
import json
import time
import threading
from collections import OrderedDict
from typing import Dict, Any, Optional, Tuple


DEFAULT_CACHE_SIZE = 256
DEFAULT_TTL_SECONDS = 600  # 10 minutes
CACHE_HIT_SAVING_MIN_SECONDS = 2.0  # Only log savings > 2s


class ResultCache:
    """Thread-safe LRU cache for tool execution results."""

    def __init__(self, max_size: int = DEFAULT_CACHE_SIZE,
                 ttl_seconds: int = DEFAULT_TTL_SECONDS):
        self.max_size = max_size
        self.ttl = ttl_seconds
        self._cache: OrderedDict[str, Tuple[float, Dict[str, Any]]] = OrderedDict()
        self._lock = threading.Lock()
        self._hits = 0
        self._misses = 0
        self._total_saved_seconds = 0.0

    def _key(self, tool: str, args: dict) -> str:
        """Deterministic key: tool + sorted JSON of args → SHA256."""
        canonical = json.dumps(args, sort_keys=True, default=str)
        raw = f"{tool}:{canonical}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def get(self, tool: str, args: dict) -> Optional[Dict[str, Any]]:
        """Return cached result if present and not expired."""
        key = self._key(tool, args)
        with self._lock:
            if key in self._cache:
                ts, result = self._cache[key]
                if time.time() - ts < self.ttl:
                    # Move to end (LRU)
                    self._cache.move_to_end(key)
                    self._hits += 1
                    self._total_saved_seconds += result.get("duration", 0)
                    return result
                else:
                    # Expired
                    del self._cache[key]
            self._misses += 1
        return None

    def put(self, tool: str, args: dict, result: Dict[str, Any]):
        """Store result in cache. Evicts LRU if over max_size."""
        key = self._key(tool, args)
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
            self._cache[key] = (time.time(), result)
            while len(self._cache) > self.max_size:
                self._cache.popitem(last=False)

    def invalidate(self, tool: Optional[str] = None):
        """Invalidate cache entries, optionally filtered by tool name."""
        with self._lock:
            if tool is None:
                self._cache.clear()
            else:
                extinct = [k for k in self._cache if tool in k]
                for k in extinct:
                    del self._cache[k]

    def get_stats(self) -> Dict[str, Any]:
        """Return cache statistics."""
        with self._lock:
            total = self._hits + self._misses
            hit_rate = (self._hits / total * 100) if total > 0 else 0.0
            return {
                "size": len(self._cache),
                "max_size": self.max_size,
                "ttl_seconds": self.ttl,
                "hits": self._hits,
                "misses": self._misses,
                "hit_rate_pct": round(hit_rate, 1),
                "total_saved_seconds": round(self._total_saved_seconds, 1),
                "avg_saved_per_hit": round(
                    self._total_saved_seconds / self._hits, 2) if self._hits else 0,
            }

    def clear(self):
        """Clear all cached entries."""
        with self._lock:
            self._cache.clear()