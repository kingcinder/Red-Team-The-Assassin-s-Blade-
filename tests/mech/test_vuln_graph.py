"""VULN-GRAPH tests (v7.0 P3.2/P3.5): deterministic scoring, cycle
detection, explanation strings, cross-domain seeding into compiled plans,
and load-time validation of the shipped attacks/ directory."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from core.mech.vuln_graph import (  # noqa: E402
    VulnGraph, load_vuln_graph, Vertex, Capitalization)
from core.mech import DEFAULT_GRAPH_PATH, DEFAULT_MANIFEST_DIR  # noqa: E402
from core.mech.intents import load_manifest_dir  # noqa: E402


def findings(*titles):
    return [{"title": t, "detail": t} for t in titles]


class TestShippedGraph(unittest.TestCase):
    """The real attacks/vuln_graph.yaml + all 12 manifests load clean."""

    def test_shipped_graph_loads(self):
        vertices = load_vuln_graph(DEFAULT_GRAPH_PATH)
        ids = {v.id for v in vertices}
        self.assertIn("ap.discovered", ids)
        self.assertIn("wifi.psk_recovered", ids)
        self.assertIn("client.credential_harvest", ids)
        self.assertIn("creds.validated", ids)
        self.assertIn("web.dynamic_params", ids)
        self.assertIn("host.sudo_misconfig", ids)

    def test_shipped_manifests_all_load(self):
        manifests = load_manifest_dir(DEFAULT_MANIFEST_DIR)
        self.assertEqual(len(manifests), 12)
        for m in manifests.values():
            self.assertFalse(m.llm_required)
            self.assertTrue(m.plan)


class TestScoring(unittest.TestCase):
    def setUp(self):
        self.graph = VulnGraph(load_vuln_graph(DEFAULT_GRAPH_PATH))

    def test_ap_discovery_moves_ordered(self):
        moves = self.graph.next_moves(findings("BSSID AA:BB:CC:DD:EE:FF"))
        self.assertTrue(moves)
        scores = [m.score for m in moves]
        self.assertEqual(scores, sorted(scores, reverse=True))
        # The explanation names the matched vertex.
        self.assertIn("ap.discovered", moves[0].why)

    def test_handshake_finding_suggests_crack_first(self):
        moves = self.graph.next_moves(
            findings("WPA handshake captured"))
        self.assertTrue(moves)
        self.assertEqual(moves[0].vertex_id, "ap.handshake_captured")
        self.assertEqual(moves[0].intent, "wifi_wpa_handshake")
        self.assertAlmostEqual(moves[0].score, 0.95 * 0.90)

    def test_psk_recovery_seeds_cross_domain(self):
        """P3.4: wifi.psk → rogue AP → credential harvest → SMB relay."""
        moves = self.graph.next_moves(findings("KEY FOUND! [ password123 ]"))
        intents = [m.intent for m in moves]
        self.assertIn("wifi_rogue_ap", intents)
        # And the credential-harvest vertex fires off NTLM material:
        moves2 = self.graph.next_moves(findings("NTLMv2 Hash captured"))
        intents2 = [m.intent for m in moves2]
        self.assertIn("smb_credential_relay", intents2)
        self.assertIn("ad_kerberoast", intents2)

    def test_failed_probe_zeroes_score_but_keeps_move(self):
        moves = self.graph.next_moves(
            findings("WPA handshake captured"),
            probe_checker=lambda name: False)  # everything fails
        self.assertTrue(moves)
        top = next(m for m in moves if m.probe_ok is False)
        self.assertEqual(top.score, 0.0)
        self.assertIn("blocked", top.why)

    def test_probe_ok_scores_full(self):
        moves = self.graph.next_moves(
            findings("WPA handshake captured"),
            probe_checker=lambda name: True)
        top = moves[0]
        self.assertTrue(top.probe_ok)
        self.assertGreater(top.score, 0.5)

    def test_deterministic_ordering(self):
        f = findings("WPA handshake", "KEY FOUND", "BSSID")
        runs = [tuple((m.vertex_id, m.intent) for m in self.graph.next_moves(f))
                for _ in range(3)]
        self.assertEqual(runs[0], runs[1])
        self.assertEqual(runs[1], runs[2])

    def test_no_match_no_moves(self):
        self.assertEqual(self.graph.next_moves(findings("nothing matches")), [])


class TestCycleDetection(unittest.TestCase):
    def _write(self, tmp, vertices):
        import yaml
        path = os.path.join(tmp, "g.yaml")
        with open(path, "w") as f:
            yaml.safe_dump({"vertices": vertices}, f)
        return path

    def test_direct_cycle_rejected(self):
        with unittest.TestCase().subTest():
            pass
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, [
                {"id": "a", "matched_by": {"pattern": "x"},
                 "requires": ["cap.b"], "provides": ["cap.a"],
                 "grants": [], "capitalization": [{"intent": "i"}]},
                {"id": "b", "matched_by": {"pattern": "y"},
                 "requires": ["cap.a"], "provides": ["cap.b"],
                 "grants": [], "capitalization": [{"intent": "i"}]},
            ])
            with self.assertRaises(ValueError) as cm:
                load_vuln_graph(path)
            self.assertIn("cycle", str(cm.exception))

    def test_duplicate_capability_allowed_parallel_paths(self):
        # Parallel attack paths may both produce a capability (handshake +
        # PMKID both yield wifi.handshake_file); this must NOT be rejected.
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, [
                {"id": "a", "matched_by": {"pattern": "x"},
                 "provides": ["cap.same"], "grants": [],
                 "capitalization": [{"intent": "i"}]},
                {"id": "b", "matched_by": {"pattern": "y"},
                 "provides": ["cap.same"], "grants": [],
                 "capitalization": [{"intent": "i"}]},
            ])
            vertices = load_vuln_graph(path)  # must not raise
            self.assertEqual(len(vertices), 2)

    def test_self_dependency_not_a_cycle(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, [
                {"id": "a", "matched_by": {"pattern": "x"},
                 "requires": ["cap.a"], "provides": ["cap.a"],
                 "grants": [], "capitalization": [{"intent": "i"}]},
            ])
            vertices = load_vuln_graph(path)  # must not raise
            self.assertEqual(len(vertices), 1)

    def test_bad_regex_rejected(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, [
                {"id": "a", "matched_by": {"pattern": "([bad"},
                 "provides": ["c"], "grants": [],
                 "capitalization": [{"intent": "i"}]},
            ])
            with self.assertRaises(ValueError) as cm:
                load_vuln_graph(path)
            self.assertIn("bad regex", str(cm.exception))

    def test_confidence_out_of_range_rejected(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, [
                {"id": "a", "matched_by": {"pattern": "x"},
                 "provides": ["c"], "grants": [],
                 "capitalization": [{"intent": "i", "confidence": 5.0}]},
            ])
            with self.assertRaises(ValueError) as cm:
                load_vuln_graph(path)
            self.assertIn("confidence", str(cm.exception))


class TestCrossDomainSeeding(unittest.TestCase):
    """P3.5: a finding-seeded compile carries prior facts into the plan."""

    def test_seeded_facts_reach_resolvers(self):
        from core.mech import MechUnit
        from core.mech.resolver import ResolveContext
        unit = MechUnit(config={}, manifest_dir=DEFAULT_MANIFEST_DIR)
        # Compile the SMB relay with credentials 'discovered' upstream —
        # the resolver context must carry them (cross-domain hand-off).
        ctx = unit._resolve_context(
            target={"host": "10.0.0.5", "username": "svc-backup",
                    "password": "P@ss"},
            facts={"creds_source": "responder_poison"})
        self.assertEqual(ctx.target["host"], "10.0.0.5")
        self.assertEqual(ctx.facts["creds_source"], "responder_poison")
        plan = unit.compile(
            "smb_credential_relay",
            target={"host": "10.0.0.5", "username": "svc-backup",
                    "password": "P@ss"})
        self.assertTrue(plan.runnable)
        validate_args = plan.steps[0].args
        self.assertEqual(validate_args["username"], "svc-backup")


if __name__ == "__main__":
    unittest.main()
