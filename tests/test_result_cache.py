"""
Tests for core/result_cache.py — the ResultCache seam (candidate #6).

LRU tool-result cache with TTL. Pins: key determinism (args order
independence), hit/miss accounting, TTL expiry, LRU eviction, scoped
invalidation, and stats.
"""
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.result_cache import ResultCache


def _check(name, fn):
    try:
        fn()
        print(f"  {name}: OK")
    except AssertionError as e:
        print(f"  {name}: FAIL — {e}")
        raise


def test_roundtrip_and_key_determinism():
    c = ResultCache()
    args = {"target": "10.0.0.5", "ports": "80,443"}
    c.put("nmap_scan", args, {"stdout": "open", "exit_code": 0, "duration": 3.0})
    # Same args in different dict order → same key → cache hit
    got = c.get("nmap_scan", {"ports": "80,443", "target": "10.0.0.5"})
    assert got is not None and got["stdout"] == "open"
    # Different args → miss
    assert c.get("nmap_scan", {"target": "10.0.0.6"}) is None
    # Different tool → miss
    assert c.get("nikto_scan", args) is None


def test_hit_miss_stats():
    c = ResultCache()
    c.put("t1", {"a": 1}, {"duration": 2.0})
    c.get("t1", {"a": 1})
    c.get("t1", {"a": 1})
    c.get("t1", {"a": 999})  # miss
    s = c.get_stats()
    assert s["hits"] == 2 and s["misses"] == 1
    assert s["hit_rate_pct"] == round(2 / 3 * 100, 1)
    assert s["total_saved_seconds"] == 4.0
    assert s["avg_saved_per_hit"] == 2.0


def test_ttl_expiry():
    c = ResultCache(ttl_seconds=1)
    c.put("t1", {"a": 1}, {"stdout": "x"})
    assert c.get("t1", {"a": 1}) is not None
    time.sleep(1.1)
    assert c.get("t1", {"a": 1}) is None, "expired entry must miss"


def test_lru_eviction():
    c = ResultCache(max_size=2)
    c.put("t1", {"a": 1}, {"stdout": "1"})
    c.put("t2", {"a": 1}, {"stdout": "2"})
    c.get("t1", {"a": 1})  # t1 most-recently-used
    c.put("t3", {"a": 1}, {"stdout": "3"})  # evicts t2 (LRU)
    assert c.get("t1", {"a": 1}) is not None
    assert c.get("t2", {"a": 1}) is None, "LRU entry must be evicted"
    assert c.get("t3", {"a": 1}) is not None
    assert c.get_stats()["size"] == 2


def test_invalidate():
    c = ResultCache()
    c.put("nmap_scan", {"a": 1}, {"stdout": "1"})
    c.put("nikto_scan", {"a": 1}, {"stdout": "2"})
    c.invalidate("nmap_scan")
    assert c.get("nmap_scan", {"a": 1}) is None
    assert c.get("nikto_scan", {"a": 1}) is not None
    c.invalidate()
    assert c.get_stats()["size"] == 0


def test_lru_keeps_tool_index_consistent():
    # Evicting LRU entries must not corrupt the tool-key index
    c = ResultCache(max_size=1)
    c.put("t1", {"a": 1}, {"stdout": "1"})
    c.put("t2", {"a": 1}, {"stdout": "2"})  # evicts t1
    assert c.get("t1", {"a": 1}) is None
    assert c.get("t2", {"a": 1}) is not None
    c.invalidate("t1")  # stale index entry must not raise
    assert c.get_stats()["size"] == 1


def test_clear():
    c = ResultCache()
    c.put("t1", {"a": 1}, {"stdout": "1"})
    c.clear()
    assert c.get_stats()["size"] == 0
    assert c.get("t1", {"a": 1}) is None


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in tests:
        _check(fn.__name__, fn)
    print(f"\nAll {len(tests)} result-cache tests PASSED.")
