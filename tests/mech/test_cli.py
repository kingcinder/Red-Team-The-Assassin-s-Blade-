"""CLI arg-parsing tests: malformed `--mech run/compile` args must produce a
usage error, never an IndexError traceback (the CLI is a terminal-facing
surface — a bad invocation must degrade, not crash)."""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from core.mech import cli  # noqa: E402


class TestSplitRunArgs(unittest.TestCase):
    def test_parses_target_and_facts(self):
        intent_id, target, facts = cli._split_run_args(
            ["wifi_pmkid", "--target", "bssid=AA:BB", "--facts", "essid=TestNet"])
        self.assertEqual(intent_id, "wifi_pmkid")
        self.assertEqual(target, {"bssid": "AA:BB"})
        self.assertEqual(facts, {"essid": "TestNet"})

    def test_bare_value_after_target_flag_stored_under_target_key(self):
        intent_id, target, facts = cli._split_run_args(
            ["wifi_pmkid", "--target", "AA:BB"])
        self.assertEqual(target, {"target": "AA:BB"})

    def test_dangling_target_raises_value_error_not_index_error(self):
        with self.assertRaises(ValueError):
            cli._split_run_args(["wifi_pmkid", "--target"])

    def test_dangling_facts_raises_value_error_not_index_error(self):
        with self.assertRaises(ValueError):
            cli._split_run_args(["wifi_pmkid", "--facts"])


class TestRunOrCompileGuard(unittest.TestCase):
    def test_dangling_target_returns_usage_error_exit_code(self):
        # The guard returns exit 2 on a dangling --target before it ever
        # needs a real unit (no registry/runner construction required).
        code = cli._run_or_compile(None, ["wifi_pmkid", "--target"],
                                   execute=True)
        self.assertEqual(code, 2)

    def test_valid_args_delegate_to_cmd_run(self):
        with mock.patch("core.mech.cli._cmd_run", return_value=0) as cmd:
            code = cli._run_or_compile(None, ["wifi_pmkid", "--target",
                                              "bssid=AA:BB"], execute=False)
        self.assertEqual(code, 0)
        cmd.assert_called_once()
        args = cmd.call_args
        self.assertEqual(args.args[1], "wifi_pmkid")     # intent_id
        self.assertEqual(args.args[2], {"bssid": "AA:BB"})  # target
        self.assertEqual(args.kwargs["execute"], False)


if __name__ == "__main__":
    unittest.main()