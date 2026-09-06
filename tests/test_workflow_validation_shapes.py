import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.workflow_engine import WorkflowStateMachine


def test_validate_template_rejects_non_object_args(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text("name: bad\nsteps:\n  - name: x\n    tool: echo\n    args: nope\n")
    result = WorkflowStateMachine.validate_template(str(path))
    assert result["valid"] is False
    assert any("args" in error and "object" in error for error in result["errors"])


def test_validate_template_rejects_non_list_extracts(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text("name: bad\nsteps:\n  - name: x\n    tool: echo\n    args: {}\n    extracts: nope\n")
    result = WorkflowStateMachine.validate_template(str(path))
    assert result["valid"] is False
    assert any("extracts" in error and "list" in error for error in result["errors"])


def test_resolve_template_display_name_and_stem():
    # v6.x: the cockpit sends the template's display `name:` field, not the
    # filename — resolve_template must map it to the real file (this is the
    # regression that made cockpit launches fail with "template not found").
    td = os.path.join(os.path.dirname(__file__), "..", "workflows", "templates")
    p = WorkflowStateMachine.resolve_template(td, "Evil Twin & WPA2 Handshake Capture Chain")
    assert p is not None and os.path.basename(p) == "evil_twin_chain.yaml", p
    assert os.path.basename(WorkflowStateMachine.resolve_template(td, "evil_twin_chain")) \
        == "evil_twin_chain.yaml"
    assert os.path.basename(WorkflowStateMachine.resolve_template(td, "evil_twin_chain.yaml")) \
        == "evil_twin_chain.yaml"
    assert os.path.basename(
        WorkflowStateMachine.resolve_template(td, "Wireless WPA/WPA2 Attack Chain")) \
        == "wireless_wpa_chain.yaml"


def test_resolve_template_rejects_traversal():
    td = os.path.join(os.path.dirname(__file__), "..", "workflows", "templates")
    for evil in ("/etc/passwd", "../../etc/passwd", "../other.yaml", ""):
        assert WorkflowStateMachine.resolve_template(td, evil) is None, evil
    assert WorkflowStateMachine.resolve_template(td, "no_such_template_xyz") is None


def test_match_registered_tool_installed_only():
    # v6.3 live-run bug: the LLM suggested raw binary 'airodump-ng' on retry;
    # the runner blocked it as unknown_tool and, on a gate:true step, aborted
    # the whole workflow. _match_registered_tool must resolve it to a
    # registered INSTALLED tool and reject garbage names — and it must never
    # hand back a registered-but-uninstalled tool (which would fail the same
    # way on retry).
    from unittest.mock import MagicMock
    from core.workflow_engine import WorkflowStateMachine

    runner = MagicMock()
    registry = MagicMock()
    registry.get_all_tools.return_value = {
        "airodump_capture": {}, "nmap_scan": {}, "hashcat_crack": {},
        "hcxdumptool_capture": {}, "hcxpcapngtool_convert": {},
    }
    reg_inst = {"airodump_capture": True, "nmap_scan": True,
                "hashcat_crack": True, "hcxdumptool_capture": True,
                "hcxpcapngtool_convert": True}

    def fake_get(n):
        td = MagicMock()
        td.installed = reg_inst.get(n, False)
        return td

    registry.get_tool.side_effect = fake_get
    runner.registry = registry
    wf = WorkflowStateMachine.__new__(WorkflowStateMachine)
    wf.runner = runner

    # flagship raw-binary -> registered tool
    assert wf._match_registered_tool("airodump-ng") == "airodump_capture"
    assert wf._match_registered_tool("nmap") == "nmap_scan"
    # garbage / noise tokens rejected
    for bad in ("a", "ng", "x7"):
        assert wf._match_registered_tool(bad) is None, bad
    # registered-but-uninstalled never suggested (exact match included)
    reg_inst["airodump_capture"] = False
    assert wf._match_registered_tool("airodump_capture") is None
    assert wf._match_registered_tool("airodump-ng") is None
    reg_inst["airodump_capture"] = True
    assert wf._match_registered_tool("airodump-ng") == "airodump_capture"


def test_adapt_monitor_interface_airmon_rename():
    # v6.3 live-run bug: airmon-ng renamed wlxdcef09d3ad89 -> wlan1mon when
    # entering monitor mode, so downstream steps passing the ORIGINAL
    # {{interface}} failed with ioctl(SIOCGIFINDEX) failed: No such device.
    # The engine must substitute the live monitor iface for wireless tools,
    # never redirect system interface tools, and leave existing ifaces alone.
    from unittest.mock import MagicMock, patch
    from core.workflow_engine import WorkflowStateMachine

    wf = WorkflowStateMachine.__new__(WorkflowStateMachine)
    wf.runner = MagicMock()

    # wlan0 VANISHED (airmon renamed it); wlan0mon + mon0 are monitor (803)
    exists = {"wlan0": False, "wlan0mon": True, "mon0": True, "wlan1": True}
    ld_return = ["wlan0", "wlan0mon", "mon0", "wlan1"]

    def isdir(p):
        return exists.get(p.split("/")[-1], False)

    def opener(name, *a, **k):
        # /sys/class/net/<iface>/type -> the IFACE is the [-2] component
        iface = name.split("/")[-2]
        typ = "803" if iface in ("wlan0mon", "mon0") else "1"

        class F:
            def __enter__(self_):
                return self_

            def read(self_):
                return typ

            def __exit__(self_, *x):
                return False

        return F()

    with patch("os.path.isdir", side_effect=isdir), \
         patch("os.listdir", return_value=ld_return), \
         patch("builtins.open", side_effect=opener):
        # wireless tool + vanished iface -> exact variant wins
        got = wf._adapt_monitor_interface({"interface": "wlan0"},
                                          "airodump_capture")
        assert got["interface"] == "wlan0mon", got
        # system interface tools never redirected
        for t in ("iface_down", "iface_up", "iface_addr", "route_config",
                  "interface_discovery", "macchanger", "ifconfig"):
            r = wf._adapt_monitor_interface({"interface": "wlan0"}, t)
            assert r["interface"] == "wlan0", (t, r)
        # existing iface untouched
        assert wf._adapt_monitor_interface({"interface": "wlan1"},
                                           "airodump_capture")["interface"] == "wlan1"
        # tier-2 fallback: no exact variant -> any monitor iface
        got = wf._adapt_monitor_interface({"interface": "wlan9"},
                                          "airodump_capture")
        assert got["interface"] == "mon0", got


def test_wifite_builder_shape_and_fastfail():
    # v6.3 live-run bug: wifite_auto hit the generic single-param positional
    # path and emitted `wifite wlan0mon`, which wifite rejects with
    # "unrecognized arguments". _build_wifite must emit `-i <iface>` (and
    # optional --dict <wordlist>) and fail fast on a missing interface.
    from core.command_builder import _build_command
    from core.tool_registry import ToolRegistry

    reg = ToolRegistry({})
    t = reg.get_tool("wifite_auto")
    assert t is not None
    cmd = _build_command("/tmp/out", t,
                         {"interface": "wlan0mon", "wordlist": "/w/lab.txt"})
    assert cmd[:2] == ["sudo", t.path or t.binary], cmd
    assert cmd[2:5] == ["-i", "wlan0mon", "--dict"], cmd
    # v6.3.3: a missing wordlist is substituted with an EXISTING absolute path
    # (the runner cwd is the sandbox, so relative/vanished paths would miss),
    # not passed through literally. Guarded: on a checkout without any fallback
    # candidate, the substitution returns the stripped original, so only assert
    # existence when a candidate is actually present (isabs always holds).
    assert os.path.isabs(cmd[5]), cmd
    if os.path.exists("./wordlists/rockyou.txt"):
        assert os.path.exists(cmd[5]), cmd
    # missing interface -> ValueError (fast fail, not 3600s interactive hang)
    try:
        _build_command("/tmp/out", t, {})
        raise AssertionError("expected ValueError for missing interface")
    except ValueError as e:
        assert "interface" in str(e)


def test_evil_twin_pmkid_path_no_self_gate():
    # v6.3 live-run bug: pmkid_capture carried a file_gate on its OWN output
    # (pmkid_cap.pcapng), so the producer could never satisfy its
    # precondition, hcxdumptool never ran, and the whole passive PMKID path
    # (convert -> hashcat 22000) cascaded into skips. The producer must have
    # no file_gate; only the consumers (convert, crack) may gate.
    import yaml

    with open(os.path.join(os.path.dirname(__file__), "..",
                           "workflows", "templates",
                           "evil_twin_chain.yaml")) as fh:
        data = yaml.safe_load(fh)
    steps = {s["name"]: s for s in data["steps"]}
    assert "file_gate" not in steps["pmkid_capture"], \
        "producer must not gate on its own output"
    assert steps["pmkid_convert"].get("file_gate") == ["{{pmkid_capture}}.pcapng"]
    assert steps["pmkid_crack"].get("file_gate") == ["{{pmkid_capture}}.hc22000"]


if __name__ == "__main__":
    # This file is pytest-style (the two validate_template tests use the
    # tmp_path fixture) but the CI loop runs `python3 tests/test_*.py` — so
    # execute the fixture-free regression tests here, otherwise these fixes
    # would pass vacuously under the plain-script runner.
    test_resolve_template_display_name_and_stem()
    test_resolve_template_rejects_traversal()
    test_match_registered_tool_installed_only()
    test_adapt_monitor_interface_airmon_rename()
    test_wifite_builder_shape_and_fastfail()
    test_evil_twin_pmkid_path_no_self_gate()
    print("\n=== RESOLVER + WIRELESS + WIFITE REGRESSION TESTS PASSED ===")
