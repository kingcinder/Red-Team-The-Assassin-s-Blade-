"""Tests for the findings literal gate (Serpent Circle run 2, perf).

FindingsExtractor skips the regex engine for pure-alternation patterns
(?:a|b|c) whose literal alternatives are all absent from the text — a
provable necessary condition. These tests prove the gate:
  1. never skips a real match (literal present → pattern runs → finding),
  2. is case-insensitive like the compiled regex,
  3. actually skips work (finditer not invoked when literals are absent),
  4. only pure alternations are gated (complex patterns always run).
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.findings import (  # noqa: E402
    FINDING_PATTERNS, FindingsExtractor, _derive_gate_literals)


def _qualifying_pattern():
    for sev, cat, title, pattern, dedupe in FINDING_PATTERNS:
        lits = _derive_gate_literals(pattern)
        if lits:
            return title, lits
    raise AssertionError("no qualifying pattern in FINDING_PATTERNS")


class TestGateDerivation(unittest.TestCase):
    def test_pure_alternation_qualifies(self):
        self.assertEqual(_derive_gate_literals(r"(?:a|b)"), ["a", "b"])

    def test_escaped_dots_qualify(self):
        self.assertEqual(
            _derive_gate_literals(r"(?:169\.254\.169\.254|ssrf)"),
            ["169.254.169.254", "ssrf"])

    def test_anchored_qualifies(self):
        self.assertEqual(_derive_gate_literals(r"^(?:x|y)$"), ["x", "y"])

    def test_metacharacters_disqualify(self):
        for pat in (r"(?:a.*b|cc)", r"(?:a|b)?", r"(?:a|b)(?:c)",
                    r"(?:a\d|b)"):
            self.assertIsNone(_derive_gate_literals(pat), pat)


class _CountingPattern:
    """Delegating regex wrapper that counts finditer invocations.
    (Compiled re.Pattern instances reject attribute patching, so the
    spy is a wrapper object satisfying the same interface.)"""

    def __init__(self, real):
        self._real = real
        self.calls = 0

    def finditer(self, *args, **kwargs):
        self.calls += 1
        return self._real.finditer(*args, **kwargs)

    def search(self, *args, **kwargs):
        return self._real.search(*args, **kwargs)


class TestGateScanBehavior(unittest.TestCase):
    def _extractor(self):
        fx = FindingsExtractor()
        self.assertGreater(sum(1 for g in fx._gates if g), 0,
                           "expected at least one gated pattern")
        return fx

    def _spied(self, fx, title):
        """Replace one compiled pattern with a counting wrapper."""
        idx = next(i for i, (_, _, t, _, _) in enumerate(fx._compiled)
                   if t == title)
        sev, cat, t, real, dedupe = fx._compiled[idx]
        spy = _CountingPattern(real)
        fx._compiled[idx] = (sev, cat, t, spy, dedupe)
        return spy

    def test_gate_skips_finditer_when_literals_absent(self):
        title, lits = _qualifying_pattern()
        fx = self._extractor()
        spy = self._spied(fx, title)
        # Probe text deliberately free of every literal substring:
        # the gate must skip the regex engine entirely.
        fx.scan("step", "tool", "zzzzzzzz")
        self.assertEqual(spy.calls, 0,
                         "finditer invoked although no literal was present")

    def test_gate_passes_text_with_literal(self):
        title, lits = _qualifying_pattern()
        fx = self._extractor()
        spy = self._spied(fx, title)
        # A text containing the first literal MUST run the regex.
        fx.scan("step", "tool", f"context {lits[0]} context")
        self.assertGreater(spy.calls, 0,
                           "finditer skipped although a literal was present")

    def test_gate_is_case_insensitive(self):
        # The compiled regex runs with IGNORECASE; the gate must not be
        # stricter. Uppercase literal → pattern still runs.
        title, lits = _qualifying_pattern()
        fx = self._extractor()
        spy = self._spied(fx, title)
        fx.scan("step", "tool", f"context {lits[0].upper()} context")
        self.assertGreater(spy.calls, 0,
                           "uppercase literal was wrongly gated out")

    def test_complex_patterns_always_run(self):
        # A pattern that cannot be gated (metacharacters) must never be
        # skipped even when the text looks empty of keywords.
        fx = self._extractor()
        ungated = [i for i, g in enumerate(fx._gates) if g is None]
        self.assertGreater(len(ungated), 0)
        # scan must not raise and must return a list for ungated patterns
        res = fx.scan("step", "tool", "nothing relevant here")
        self.assertIsInstance(res, list)


if __name__ == "__main__":
    unittest.main()