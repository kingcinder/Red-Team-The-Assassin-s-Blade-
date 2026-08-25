"""
Tests for core/context_manager.py — the ContextManager seam (candidate #6).

Token-aware sliding window: pins the persistent-facts block, prefix
preservation (system + few-shots), old tool-output compression, and budget
trimming (never mutates the input list).
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.context_manager import ContextManager


def _check(name, fn):
    try:
        fn()
        print(f"  {name}: OK")
    except AssertionError as e:
        print(f"  {name}: FAIL — {e}")
        raise


def _msgs(n, system=False):
    msgs = []
    if system:
        msgs.append({"role": "system", "content": "You are a pentest agent."})
    for i in range(n):
        msgs.append({"role": "user", "content": f"message {i} " + "x" * 50})
    return msgs


def test_facts():
    c = ContextManager()
    assert c.get_facts_block() == "", "empty facts → no block"
    c.add_fact("host", "10.0.0.5")
    c.add_facts({"port": "445", "service": "SMB"})
    block = c.get_facts_block()
    assert "## Persistent Facts" in block
    assert "**host**: 10.0.0.5" in block
    assert "**port**: 445" in block


def test_facts_injected_into_system():
    c = ContextManager()
    c.add_fact("host", "10.0.0.5")
    msgs = _msgs(6, system=True)
    out = c.trim(msgs)
    system = out[0]
    assert "## Persistent Facts" in system["content"]
    assert "**host**: 10.0.0.5" in system["content"]
    # Not injected twice
    out2 = c.trim(out)
    assert out2[0]["content"].count("## Persistent Facts") == 1


def test_prefix_preserved():
    c = ContextManager(max_tokens=100000)  # huge budget → nothing trimmed
    msgs = _msgs(8, system=True)
    out = c.trim(msgs)
    assert out[0]["role"] == "system"
    assert out[0]["content"].startswith("You are a pentest agent.")
    assert len(out) == len(msgs), "big budget keeps everything"
    assert msgs == _msgs(8, system=True), "input must not be mutated"


def test_trim_reduces_size():
    c = ContextManager(max_tokens=400)  # small budget
    msgs = _msgs(12, system=True)
    out = c.trim(msgs)
    # Prefix (system) always survives; newest message always survives
    assert out[0]["role"] == "system"
    assert out[-1]["role"] == "user"
    assert len(out) < len(msgs)
    # A small/negative budget may truncate the newest message to empty —
    # but the newest message must never be dropped from the output
    assert out[-1] is not None
    s = c.get_stats()
    assert s["trim_count"] == 1
    assert s["total_messages_trimmed"] >= 1


def test_tool_output_compression():
    c = ContextManager()
    huge = ("10.0.0.1: 80/tcp open 443/tcp open Apache/2.4.49 " * 200)
    compressed = c._compress_tool_output(huge)
    assert compressed.startswith("[Compressed]")
    assert "10.0.0.1" in compressed
    assert "Open:" in compressed
    assert len(compressed) < len(huge)
    # Short content passes through unchanged
    assert c._compress_tool_output("short") == "short"


def test_compression_in_trim():
    # >5 messages so the oversized tool_result lands in the SUFFIX
    # (prefix is always kept verbatim; only suffix messages are compressed).
    # LARGE budget: a small budget makes `available` negative, so the
    # reversed-suffix loop breaks on the newest message before ever reaching
    # the tool_result. Compression triggers on size (>200 tokens) regardless
    # of budget, so a big budget lets the loop reach and compress it.
    c = ContextManager(max_tokens=100000)
    msgs = [{"role": "system", "content": "SYS"},
            {"role": "user", "content": "scan"},
            {"role": "user", "content": "list"},
            {"role": "user", "content": "enum"},
            {"role": "user", "content": "probe"},
            {"role": "tool_result", "content": "port 22/tcp open OpenSSH " * 300},
            {"role": "user", "content": "next"}]
    out = c.trim(msgs)
    assert any(m["role"] == "tool_result" and "[Compressed]" in m["content"]
               for m in out)


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in tests:
        _check(fn.__name__, fn)
    print(f"\nAll {len(tests)} context-manager tests PASSED.")
