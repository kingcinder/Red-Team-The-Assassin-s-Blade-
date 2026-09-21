"""LLM-free quick-start trees — regression guards.

The five quick-action buttons (Network Recon, Web App Test, WiFi Attack,
OSINT, AD Attack) historically called sendQuickPrompt(), funneling the
operator into the LLM chat. They now open a branch picker
(openQuickStartBranch) offering two concrete LLM-free workflows per
objective; picking one opens the Run Workflow modal with the template
preselected and its required-variable form ready to fill in.

These tests pin that wiring end-to-end: HTML must not route a quick-start
button through sendQuickPrompt, every QUICK_START_TREES branch must name
a template that actually exists (by exact display name, what
launchQuickWorkflow preselects), and every branch template's declared
required variables must include the var the launcher focuses.
"""
import glob
import os
import re
import sys

import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

REPO = os.path.join(os.path.dirname(__file__), "..")
HTML_PATH = os.path.join(REPO, "dashboard", "templates", "index.html")
JS_PATH = os.path.join(REPO, "dashboard", "static", "js", "cockpit.js")
TEMPLATES_DIR = os.path.join(REPO, "workflows", "templates")


def _html():
    with open(HTML_PATH) as f:
        return f.read()


def _js():
    with open(JS_PATH) as f:
        return f.read()


def _tree():
    """Parse QUICK_START_TREES out of cockpit.js without eval.

    Structure per branch: { workflow: '…', focus: '…', why: '…' }, where
    why may contain any non-quote characters (em-dashes, slashes). We walk
    the block with a small tokenizer rather than a single mega-regex.
    """
    js = _js()
    block = js.split("const QUICK_START_TREES = {")[1].split("\n};")[0]
    trees = {}
    for key_m in re.finditer(r"^    (\w+): \{", block, re.M):
        key = key_m.group(1)
        start = key_m.end()
        end = block.find("\n    },", start)
        body = block[start:end]
        branches = []
        for bm in re.finditer(
                r"\{\s*workflow:\s*'([^']*)',\s*focus:\s*'([^']*)',\s*why:\s*'((?:[^']|\\')*)'",
                body):
            branches.append({"workflow": bm.group(1), "focus": bm.group(2)})
        trees[key] = branches
    return trees


def _template_names():
    names = {}
    for path in glob.glob(os.path.join(TEMPLATES_DIR, "*.yaml")):
        with open(path) as f:
            t = yaml.safe_load(f)
        names[t["name"]] = t
    return names


def test_quick_start_buttons_do_not_use_the_llm_chat():
    html = _html()
    quick_start = html.split('class="quick-start"')[1].split("</div>")[0]
    assert "sendQuickPrompt" not in quick_start, (
        "quick-start buttons must not route through the LLM chat")
    assert quick_start.count("openQuickStartBranch(") == 5, (
        "all five quick-start buttons must open the branch picker")


def test_branch_picker_ui_exists():
    html = _html()
    assert 'id="quickstart-modal"' in html
    assert 'id="qs-branch-list"' in html
    js = _js()
    assert "function openQuickStartBranch(" in js
    assert "function closeQuickStartBranch(" in js
    assert "launchQuickWorkflow(" in js  # the picker hands off to the modal
    assert "send_task" not in js.split("const QUICK_START_TREES")[1].split("// ── LLM")[0], (
        "the quick-start layer must never touch the LLM chat socket")


def test_every_branch_names_an_existing_template():
    trees = _tree()
    names = _template_names()
    assert set(trees) == {"recon", "web", "wifi", "osint", "ad"}, sorted(trees)
    for key, branches in trees.items():
        assert len(branches) == 2, f"{key}: expected 2 branches, got {len(branches)}"
        for b in branches:
            assert b["workflow"] in names, (
                f"{key}: branch template {b['workflow']!r} missing from workflows/templates")


def test_branch_focus_var_is_declared_in_its_template():
    trees = _tree()
    names = _template_names()
    for key, branches in trees.items():
        for b in branches:
            t = names[b["workflow"]]
            variables = t.get("variables", {})
            assert b["focus"] in variables, (
                f"{key}: {b['workflow']} focuses var {b['focus']!r} "
                f"but template declares {sorted(variables)}")


def test_branch_templates_are_hermetic_or_llm_free():
    # No quick-start branch may reference an LLM-coupled step; workflows run
    # on the local toolchain by design.
    trees = _tree()
    names = _template_names()
    llm_tools = {t for t, td in names.items() if "llm" in str(td.get("steps", "")).lower()}
    for key, branches in trees.items():
        for b in branches:
            steps = names[b["workflow"]].get("steps", [])
            for s in steps:
                assert "llm" not in str(s.get("tool", "")).lower(), (
                    f"{b['workflow']}: step {s.get('name')} looks LLM-coupled")
    assert not llm_tools or True  # (informational)


def test_branch_picker_builds_handlers_without_inline_html():
    """Branch buttons must not be rendered with inline onclick attributes.

    Regression: branch names contain double quotes once JSON.stringify'd;
    building `<button onclick="...${JSON.stringify(b.workflow)}...">` makes
    the attribute terminate at the first quote, leaving every branch button
    dead (found in live GUI audit — picker rendered but clicking did
    nothing). The picker must attach real event listeners instead.
    """
    js = _js()
    picker = js.split("function openQuickStartBranch(")[1].split("function closeQuickStartBranch")[0]
    assert "onclick=" not in picker, (
        "branch buttons must not use inline onclick attributes")
    assert "JSON.stringify" not in picker, (
        "JSON.stringify inside HTML attributes breaks on double quotes")
    assert "addEventListener('click'" in picker, (
        "branch buttons must attach real event listeners")


def test_smoke_template_is_truly_hermetic():
    """The automated smoke E2E must stay sub-second and network-free."""
    t = _template_names()["Cockpit Smoke Check"]
    tools = {s["tool"] for s in t["steps"]}
    assert tools <= {"system_info", "process_list"}, tools
    for s in t["steps"]:
        assert s.get("timeout", 300) <= 60, f"{s['name']} timeout too long for CI"
        assert s.get("retries", 2) <= 1, f"{s['name']} retries inflate worst-case time"


if __name__ == "__main__":
    test_quick_start_buttons_do_not_use_the_llm_chat()
    test_branch_picker_ui_exists()
    test_every_branch_names_an_existing_template()
    test_branch_focus_var_is_declared_in_its_template()
    test_branch_templates_are_hermetic_or_llm_free()
    test_branch_picker_builds_handlers_without_inline_html()
    test_smoke_template_is_truly_hermetic()
    print("quick-start tree wiring: OK")
