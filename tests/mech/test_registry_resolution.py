"""Tests for registry-aware tool resolution (v7.1.x).

The consolidated tool registry (/home/cody/redteam-tools/bin) symlinks
every installed tool. PATH is still preferred, but probes and the resolver
must fall back to the registry so the doctor succeeds even when the
harness runs with a minimal PATH (systemd timers, cron, IDE launches).
"""
import os
import shutil
import stat
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from core.mech.probes import registry_which, registry_bin_dir, probe_tools_present  # noqa: E402


class TestRegistryWhich(unittest.TestCase):
    def test_registry_dir_shape(self):
        # Host-independent: the default registry path is codypc-local
        # (/home/cody/redteam-tools/bin) and does not exist on CI runners.
        # Point the documented test seam at a temp dir with the shape.
        with tempfile.TemporaryDirectory() as tmp:
            shaped = os.path.join(tmp, "redteam-tools", "bin")
            os.makedirs(shaped)
            with mock.patch("core.mech.probes.REGISTRY_BIN_DIR", shaped):
                d = registry_bin_dir()
                self.assertTrue(d.endswith("redteam-tools/bin"))
                self.assertTrue(os.path.isdir(d))

    def test_finds_system_tool_via_path_first(self):
        # sh is on PATH everywhere; PATH hit must win over the registry.
        self.assertEqual(registry_which("sh"), shutil.which("sh"))

    def test_finds_tool_only_present_in_registry(self):
        # nmap is installed at /usr/bin/nmap and symlinked in the registry.
        # Simulate a minimal PATH (no /usr/bin) — the registry must answer.
        reg = registry_bin_dir()
        target = os.path.join(reg, "nmap")
        if not os.path.isfile(target):
            self.skipTest("registry has no nmap symlink on this host")
        empty_path = mock.patch.dict(os.environ, {"PATH": "/nonexistent"})
        with empty_path:
            self.assertEqual(registry_which("nmap"), target)

    def test_missing_tool_returns_none(self):
        empty_path = mock.patch.dict(os.environ, {"PATH": "/nonexistent"})
        with empty_path:
            self.assertIsNone(registry_which("definitely-not-a-binary-xyz"))

    def test_absent_registry_dir_is_not_fatal(self):
        with mock.patch("core.mech.probes.REGISTRY_BIN_DIR",
                        "/nonexistent/redteam-tools/bin"):
            self.assertIsNone(registry_which("definitely-not-a-binary-xyz"))


class TestProbeToolsPresentRegistryAware(unittest.TestCase):
    def test_probe_finds_registry_only_tool(self):
        reg = registry_bin_dir()
        if not os.path.isfile(os.path.join(reg, "nmap")):
            self.skipTest("registry has no nmap symlink on this host")
        empty_path = mock.patch.dict(os.environ, {"PATH": "/nonexistent"})
        with empty_path:
            res = probe_tools_present(["nmap"])
        self.assertTrue(res.ok, res.reason)
        self.assertIn("registry", res.detail.get("via", [""])[0])

    def test_probe_still_reports_real_missing(self):
        empty_path = mock.patch.dict(os.environ, {"PATH": "/nonexistent"})
        with empty_path:
            res = probe_tools_present(["definitely-not-a-binary-xyz"])
        self.assertFalse(res.ok)
        self.assertEqual(res.missing, ["definitely-not-a-binary-xyz"])


class TestResolverRegistryAware(unittest.TestCase):
    def test_resolver_shutil_which_falls_back_to_registry(self):
        from core.mech.resolver import shutil_which
        reg = registry_bin_dir()
        if not os.path.isfile(os.path.join(reg, "nmap")):
            self.skipTest("registry has no nmap symlink on this host")
        empty_path = mock.patch.dict(os.environ, {"PATH": "/nonexistent"})
        with empty_path, mock.patch("shutil.which", lambda *a, **k: None):
            self.assertEqual(shutil_which("nmap"),
                             os.path.join(reg, "nmap"))


if __name__ == "__main__":
    unittest.main()
