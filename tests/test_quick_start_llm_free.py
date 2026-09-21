"""LLM-free quick-start buttons — regression guards.

The five quick-action buttons (Network Recon, Web App Test, WiFi Attack,
OSINT, AD Attack) historically called sendQuickPrompt(), funneling the
operator into the LLM chat even though template-driven workflows run
entirely on the local toolchain. They now open the Run Workflow modal with
the template preselected via launchQuickWorkflow() — zero LLM involved.

These tests pin that wiring: the HTML must never route a quick-start button
through sendQuickPrompt again, the launcher + template names must exist on
the JS side, and every referenced workflow template must resolve by exact
display name against the templates dir (what /api/workflows serves).
"""
import glob
import os
import sys

import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

REPO = os.path.join(os.path.dirname(__file__), "..")
HTML_PATH = os.path.join(REPO, "dashboard", "templates", "index.html")
JS_PATH = os.path.join(REPO, "dashboard", "static", "js", "cockpit.js")
TEMPLATES_DIR = os.path.join(REPO, "workflows", "templates")

QUICK_START_WORKFLOWS = [
    "Network Reconnaissance",
    "Web Application Assessment",
    "Wireless WPA/WPA2 Attack Chain",
    "OSINT & External Footprinting",
    "Kerberoasting Chain",
]


def _html():
    with open(HTML_PATH) as f:
        return f.read()


def _js():
    with open(JS_PATH) as f:
        return f.read()


def test_quick_start_buttons_do_not_use_the_llm_chat():
    html = _html()
    quick_start = html.split('class="quick-start"')[1].split("</div>")[0]
    assert "sendQuickPrompt" not in quick_start, (
        "quick-start buttons must not route through the LLM chat")
    assert quick_start.count("launchQuickWorkflow(") == 5, (
        "all five quick-start buttons must call launchQuickWorkflow")


def test_launcher_exists_and_is_llm_free():
    js = _js()
    assert "function launchQuickWorkflow(" in js
    assert "openWorkflowModal" in js
    assert "onWorkflowSelect" in js
    # The launcher drives the workflow modal, never the chat socket.
    assert "send_task" not in js.split("function launchQuickWorkflow(")[1].split("}")[0]


def test_all_quick_start_templates_resolve_by_exact_name():
    names = set()
    for path in glob.glob(os.path.join(TEMPLATES_DIR, "*.yaml")):
        with open(path) as f:
            names.add(yaml.safe_load(f)["name"])
    for wanted in QUICK_START_WORKFLOWS:
        assert wanted in names, (
            f"template {wanted!r} missing from workflows/templates — "
            "launchQuickWorkflow preselects by exact display name")


def test_recon_scan_quick_path_removes_gate_abort_regression():
    # Guards the earlier Omega-campaign fix the quick-starts depend on:
    # nmap_scan must split multi-flag scan_type into real argv tokens, or
    # every template-driven recon run aborts at its first gate step.
    from types import SimpleNamespace

    from core.command_builder import _build_command

    t = SimpleNamespace(name="nmap_scan", binary="nmap", path="nmap",
                        subcommand=None, parameters={})
    argv = _build_command("/tmp/out", t, {
        "target": "127.0.0.1", "ports": "1-1000",
        "scan_type": "-sS -Pn -T4"})
    assert "-Pn" in argv and "-T4" in argv
    assert not any(" " in a for a in argv)


if __name__ == "__main__":
    test_quick_start_buttons_do_not_use_the_llm_chat()
    test_launcher_exists_and_is_llm_free()
    test_all_quick_start_templates_resolve_by_exact_name()
    test_recon_scan_quick_path_removes_gate_abort_regression()
    print("quick-start LLM-free wiring: OK")
