"""Tests for the v6.3.3 command-builder hardening.

Addresses live failures where the LLM's wireless/sniffing tool args were
rejected:

1. Interface args with trailing sentence punctuation (`wlan0mon.`, `wlan1 `)
   reached airmon-ng / ip-link / capture tools and failed with
   nonexistent-interface errors (e.g. `monitor_mode_disable ✗ Failed (1)`).
   `_clean_interface()` now strips trailing punctuation/whitespace.
2. aircrack/wifite pointed at a missing wordlist
   (`/usr/share/wordlists/dictionary.txt`) and stalled; `_resolve_wordlist()`
   now falls back to an existing wordlist (repo `wordlists/rockyou.txt`, etc.).
3. v6.3.6 integration: with a base iface gone and its monitor variant live in
   /sys/class/net, a real airodump+wifite+aircrack build through _build_command
   must compose monitor-adaptation + wordlist-fallback + capture-path anchoring.
"""
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from types import SimpleNamespace  # noqa: E402

from core.command_builder import (  # noqa: E402
    _clean_interface, _resolve_wordlist, _build_command)


def _tool(name, binary="fakebinary"):
    return SimpleNamespace(name=name, path=None, binary=binary, subcommand=None, timeout=300)


class TestCleanInterface(unittest.TestCase):
    def test_trailing_period_stripped(self):
        # The live failure: monitor_mode_disable with "wlan0mon."
        self.assertEqual(_clean_interface("wlan0mon."), "wlan0mon")

    def test_trailing_punctuation_and_whitespace(self):
        self.assertEqual(_clean_interface("  wlan0mon. "), "wlan0mon")
        self.assertEqual(_clean_interface("wlan1,"), "wlan1")
        self.assertEqual(_clean_interface("wlan2mon!\n"), "wlan2mon")

    def test_valid_interface_untouched(self):
        self.assertEqual(_clean_interface("wlan0mon"), "wlan0mon")
        self.assertEqual(_clean_interface("eth0"), "eth0")
        self.assertEqual(_clean_interface("mon-wlan1"), "mon-wlan1")

    def test_blank_returns_empty(self):
        self.assertEqual(_clean_interface(""), "")
        self.assertEqual(_clean_interface(None), "")
        self.assertEqual(_clean_interface("   "), "")

    def test_internal_period_preserved(self):
        # A trailing-period strip must not remove an internal separator
        # (`1.2eth`-style names / versioned ifaces keep internal dots).
        self.assertEqual(_clean_interface("wlan0.100."), "wlan0.100")


class TestResolveWordlist(unittest.TestCase):
    def test_existing_path_passes_through_as_absolute(self):
        # repo wordlists/rockyou.txt definitely exists (per repo layout).
        for cand in ("./wordlists/rockyou.txt", "wordlists/rockyou.txt"):
            if os.path.exists(cand):
                # Returned path must exist AND be absolute (the runner cwd is
                # the sandbox dir, so relative reprs would miss the file).
                resolved = _resolve_wordlist(cand)
                self.assertTrue(os.path.exists(resolved))
                self.assertTrue(os.path.isabs(resolved))
                return
        self.skipTest("no known wordlist on disk to test pass-through")

    def test_missing_wordlist_falls_back_to_existing_absolute(self):
        resolved = _resolve_wordlist("/usr/share/wordlists/dictionary.txt")
        if os.path.exists("./wordlists/rockyou.txt"):
            self.assertTrue(os.path.exists(resolved))
            self.assertTrue(os.path.isabs(resolved))
        else:
            # As long as it resolves to SOMETHING that exists, the fallback works.
            self.assertTrue(os.path.exists(resolved))

    def test_blank_returns_blank(self):
        self.assertEqual(_resolve_wordlist(""), "")
        self.assertEqual(_resolve_wordlist(None), "")


class TestMonitorModeBuilders(unittest.TestCase):
    """Regression: monitor_mode_* must not pass a trailing-dot interface."""

    def test_monitor_mode_enable_cleans_interface(self):
        cmd = _build_command("/tmp/out", _tool("monitor_mode_enable"),
                             {"interface": "wlan0mon."})
        self.assertEqual(cmd, ["sudo", "airmon-ng", "start", "wlan0mon"])

    def test_monitor_mode_disable_cleans_interface(self):
        # The exact live failure from the logs.
        cmd = _build_command("/tmp/out", _tool("monitor_mode_disable"),
                             {"interface": "wlan0mon."})
        self.assertEqual(cmd, ["sudo", "airmon-ng", "stop", "wlan0mon"])


class TestCaptureToolBuilders(unittest.TestCase):
    """Regression: capture/sniffing/monitor tools clean the interface arg."""

    def test_iface_up_cleans(self):
        cmd = _build_command("/tmp", _tool("iface_up"), {"interface": "wlan0mon."})
        self.assertEqual(cmd, ["sudo", "ip", "link", "set", "wlan0mon", "up"])

    def test_airodump_cleans_trailing_iface(self):
        cmd = _build_command("/tmp", _tool("airodump_capture"),
                             {"interface": "wlan0mon.", "channel": "6"})
        self.assertIn("wlan0mon", cmd)
        self.assertNotIn("wlan0mon.", cmd)

    def test_wifite_cleans_interface_and_resolves_wordlist(self):
        cmd = _build_command("/tmp", _tool("wifite_auto"),
                             {"interface": "wlan0mon.",
                              "wordlist": "/usr/share/wordlists/dictionary.txt"})
        # interface cleaned (binary is the stub 'fakebinary' from _tool)
        self.assertEqual(cmd[:4], ["sudo", "fakebinary", "-i", "wlan0mon"])
        # wordlist substituted to an existing ABSOLUTE file (repo rockyou)
        if os.path.exists("./wordlists/rockyou.txt"):
            self.assertIn("--dict", cmd)
            self.assertTrue(os.path.exists(cmd[cmd.index("--dict") + 1]))
            self.assertTrue(os.path.isabs(cmd[cmd.index("--dict") + 1]))

    def test_aircrack_uses_resolved_wordlist(self):
        cmd = _build_command("/tmp", _tool("aircrack_crack"),
                             {"cap_file": "h.pcap",
                              "wordlist": "/usr/share/wordlists/dictionary.txt"})
        if os.path.exists("./wordlists/rockyou.txt"):
            # The resolved wordlist must be present and actually exist.
            wl_index = cmd.index("-w") + 1
            self.assertTrue(os.path.exists(cmd[wl_index]))


class MonitorNetNamespace:
    """Context managing a simulated /sys/class/net where the base adapter was
    renamed to a monitor variant (airmon-ng does `wlan0` -> `wlan0mon`).

    The extra real-monitor variant `wlan1mon` (present in the directory but
    not the requested base) exercises the loose listdir fallback branch too.
    All non-`/sys/class/net` paths fall through to the real filesystem so the
    repo wordlists still resolve.
    """

    def __init__(self, live=("wlan0mon", "wlan1mon")):
        self._live = set(live)

    def __enter__(self):
        # Bind the REAL functions BEFORE patching: the patch target is the
        # shared `os` module attribute, so after patching `os.path.isdir` inside
        # the fallthrough would re-enter the side_effect and recurse forever.
        self._real_isdir = os.path.isdir
        self._real_listdir = os.listdir
        self._isdir_p = patch("core.command_builder.os.path.isdir",
                              side_effect=self._isdir)
        self._listdir_p = patch("core.command_builder.os.listdir",
                                side_effect=self._listdir)
        self._isdir_p.start()
        self._listdir_p.start()
        return self

    def _isdir(self, path):
        prefix = "/sys/class/net/"
        if str(path).startswith(prefix):
            name = str(path)[len(prefix):].rstrip("/")
            return name in self._live
        return self._real_isdir(path)  # real FS for wordlists etc.

    def _listdir(self, path):
        if str(path) == "/sys/class/net":
            return list(self._live)
        return self._real_listdir(path)

    def __exit__(self, *exc):
        self._listdir_p.stop()
        self._isdir_p.stop()


class TestChainedWirelessIntegration(unittest.TestCase):
    """v6.3.6: base-iface-gone/monitor-present layout; a real airodump+wifite+
    aircrack build must compose monitor-adapt + wordlist-fallback + capture
    anchoring correctly in the emitted commands."""

    def test_monitor_adapt_when_base_iface_gone(self):
        # Base wlan0 is GONE (renamed) — only wlan0mon / wlan1mon are live.
        with MonitorNetNamespace(live=("wlan0mon", "wlan1mon")):
            # airodump is a monitor-required tool: wlan0 must adapt to wlan0mon.
            cmd = _build_command(
                "/tmp/out", _tool("airodump_capture"),
                {"interface": "wlan0", "channel": "6",
                 "capture_file": "handshake"})
        self.assertIn("wlan0mon", cmd)
        self.assertNotIn("wlan0", cmd)  # no bare base iface in the argv
        # capture -w prefix anchored absolute under output_dir
        self.assertIn("-w", cmd)
        self.assertEqual(cmd[cmd.index("-w") + 1],
                         os.path.normpath("/tmp/out/handshake"))

    def test_wifite_adapts_monitor_and_falls_back_on_wordlist(self):
        with MonitorNetNamespace(live=("wlan0mon", "wlan1mon")):
            cmd = _build_command(
                "/tmp/out", _tool("wifite_auto"),
                {"interface": "wlan0",
                 "wordlist": "/usr/share/wordlists/dictionary.txt"})
            # monitor-adapt: wlan0 -> wlan0mon via -i
            self.assertEqual(cmd[:4], ["sudo", "fakebinary", "-i", "wlan0mon"])
            # wordlist fallback: a REAL absolute file must have been substituted
            if os.path.exists("./wordlists/rockyou.txt"):
                self.assertIn("--dict", cmd)
                wl = cmd[cmd.index("--dict") + 1]
                self.assertTrue(os.path.exists(wl))
                self.assertTrue(os.path.isabs(wl))

    def test_aircrack_anchors_capture_and_resolves_wordlist(self):
        with MonitorNetNamespace(live=("wlan0mon", "wlan1mon")):
            cmd = _build_command(
                "/tmp/out", _tool("aircrack_crack"),
                {"cap_file": "handshake-01.cap",
                 "wordlist": "/usr/share/wordlists/dictionary.txt"})
            # capture path anchored absolute under the SAME output_dir airdump
            # wrote `-w /tmp/out/handshake` to (-> handshake-01.cap).
            self.assertEqual(cmd[1],
                             os.path.normpath("/tmp/out/handshake-01.cap"))
            if os.path.exists("./wordlists/rockyou.txt"):
                self.assertIn("-w", cmd)
                self.assertTrue(os.path.isabs(cmd[cmd.index("-w") + 1]))

    def test_real_monitor_variant_found_via_listdir_fallback(self):
        # Base `wl` is only a PREFIX of the live adapters (no exact `wlmon` /
        # `wl-mon` / `wl_mon` variants exist), so the exact-variant checks miss
        # and only the loose listdir fallback (any live iface starting with the
        # base and ending "mon") can resolve to a real monitor adapter.
        with MonitorNetNamespace(live=("wlan0mon", "wlan1mon")):
            cmd = _build_command(
                "/tmp/out", _tool("airodump_capture"),
                {"interface": "wl", "channel": "1"})
        # The loose fallback deterministically returns the FIRST live adapter in
        # sorted listdir order — tighten the assertion to that exact value.
        self.assertEqual(cmd[-1], "wlan0mon")


if __name__ == "__main__":
    unittest.main()