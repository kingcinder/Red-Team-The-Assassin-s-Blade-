"""Manifest resilience policy tests (v7.1 Task 7).

The user's core requirement: no single tool failure kills an operation.
These tests pin that EVERY long-running wireless capture/deauth step has
a degrade path (fallback, retries, or warn routing), and that the
flagship handshake chain reroutes to a sibling intent (PMKID) when its
capture gate never matches.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from core.mech.intents import load_manifest_dir  # noqa: E402

# Tools that hang around (captures, deauth waits, brute force) — a hang
# here must never kill the plan silently.
LONG_TOOLS = {
    "airodump_capture", "hcxdumptool_capture", "reaver_run",
    "aireplay_deauth", "mdk3_amok_attack", "responder_run",
}


class TestManifestResilience(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        manifest_dir = os.path.join(
            os.path.dirname(__file__), "..", "..", "attacks")
        cls.manifests = load_manifest_dir(os.path.abspath(manifest_dir))

    def test_every_wireless_long_step_has_degrade_path(self):
        checked = 0
        for m in self.manifests.values():
            if m.category != "wireless":
                continue
            for s in m.plan:
                if s.tool not in LONG_TOOLS:
                    continue
                checked += 1
                self.assertTrue(
                    s.fallbacks or s.retries > 0 or s.on_fail == "warn"
                    or s.on_timeout == "warn",
                    f"{m.id}.{s.step} ({s.tool}) has no degrade path")
        self.assertGreaterEqual(checked, 5,
                                "expected the long-tool steps to be covered")

    def test_wpa_handshake_reroutes_to_pmkid(self):
        m = self.manifests["wifi_wpa_handshake"]
        reroutes = [fb["use_intent"] for s in m.plan
                    for fb in s.fallbacks if "use_intent" in fb]
        self.assertIn("wifi_pmkid", reroutes)

    def test_reroute_targets_exist_and_are_wireless(self):
        for m in self.manifests.values():
            for s in m.plan:
                for fb in s.fallbacks:
                    target = fb.get("use_intent")
                    if target:
                        self.assertIn(target, self.manifests,
                                      f"{m.id}.{s.step} reroutes to unknown "
                                      f"intent '{target}'")
                        self.assertEqual(
                            self.manifests[target].category, m.category,
                            f"{m.id} reroutes across categories")

    def test_inline_fallback_tools_exist_in_registry(self):
        from core.tool_registry import ToolRegistry
        registry = ToolRegistry({})
        for m in self.manifests.values():
            for s in m.plan:
                for fb in s.fallbacks:
                    tool = fb.get("tool")
                    if tool:
                        self.assertIsNotNone(
                            registry.get_tool(tool),
                            f"{m.id}.{s.step} fallback tool '{tool}' "
                            f"is not in the registry")


if __name__ == "__main__":
    unittest.main()
