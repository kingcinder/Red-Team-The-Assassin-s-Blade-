#!/usr/bin/env python3
"""
RedTeam Harness — Smoke Import Regression Test
==============================================

Imports EVERY Python module in the project and instantiates the Flask app.
Catches the class of regression where a module is removed from an import
statement but still referenced at runtime (NameError), or a package export
is lost — problems that `py_compile` cannot detect.

Regression this guards against:
  - Commit d889653 overwrote tools/__init__.py with a docstring-only file,
    silently removing the ALL_TOOL_MODULES export. dashboard/server.py then
    failed with ImportError at runtime, but all compile checks passed.
"""
import os
import sys
import glob
import py_compile

PROJECT_ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, PROJECT_ROOT)
os.chdir(PROJECT_ROOT)

passed = 0
failed = []


def check(name, fn):
    global passed
    try:
        fn()
        passed += 1
        print(f"  ✓ {name}")
    except Exception as e:
        failed.append(f"{name}: {type(e).__name__}: {e}")
        print(f"  ✗ {name}: {type(e).__name__}: {e}")


# 1. Compile every .py file (syntax gate)
def compile_all():
    mods = glob.glob("**/*.py", recursive=True)
    mods = [m for m in mods if "__pycache__" not in m and not m.startswith("wheels")]
    for m in mods:
        py_compile.compile(m, doraise=True)
    print(f"     ({len(mods)} files compiled)")


check("compile all .py files", compile_all)

# 2. Import every core module
core_modules = sorted(
    f"core.{os.path.basename(f)[:-3]}"
    for f in glob.glob("core/*.py")
    if not f.endswith("__init__.py")
)
for mod in core_modules:
    check(f"import {mod}", lambda m=mod: __import__(m))

# 3. Import tools package and verify the ALL_TOOL_MODULES export
def tools_export():
    from tools import ALL_TOOL_MODULES, BaseTool
    assert len(ALL_TOOL_MODULES) == 14, f"expected 14 tool modules, got {len(ALL_TOOL_MODULES)}"
    names = [c.__name__ for c in ALL_TOOL_MODULES]
    for expected in ("ReconTools", "VulnTools", "WebTools", "PasswordTools",
                     "WirelessTools", "SniffingTools", "ExploitTools",
                     "ForensicsTools", "ReversingTools", "SocialTools",
                     "PostExTools", "OSINTTools", "StressTools", "HardwareTools"):
        assert expected in names, f"missing {expected} in ALL_TOOL_MODULES"


check("tools.ALL_TOOL_MODULES export (14 modules)", tools_export)

# 4. Import dashboard server and instantiate the Flask app
def dashboard_server():
    import dashboard.server
    app = dashboard.server.create_app({})
    routes = sorted(r.rule for r in app.url_map.iter_rules())
    assert len(routes) >= 55, f"expected 55+ routes, got {len(routes)}"


check("dashboard.server + create_app (Flask)", dashboard_server)

# 5. Import the main entry point
def harness_entry():
    import harness


check("import harness", harness_entry)

# 6. Exercise the dashboard's tool-scanning routes' data path
def tools_api_data():
    import dashboard.server
    app = dashboard.server.create_app({})
    client = app.test_client()
    resp = client.get("/api/tools")
    assert resp.status_code == 200, f"/api/tools returned {resp.status_code}"
    data = resp.get_json()
    assert isinstance(data, dict) and len(data) >= 1, "tools grouped by category expected"
    resp2 = client.get("/api/tools/attack-chains")
    assert resp2.status_code == 200, f"/api/tools/attack-chains returned {resp2.status_code}"
    resp3 = client.get("/api/tools/quick-commands")
    assert resp3.status_code == 200, f"/api/tools/quick-commands returned {resp3.status_code}"


check("GET /api/tools, /api/tools/attack-chains, /api/tools/quick-commands", tools_api_data)

print(f"\n{'='*50}")
if failed:
    print(f"SMOKE IMPORTS: {passed} passed, {len(failed)} FAILED")
    for f in failed:
        print(f"  ✗ {f}")
    sys.exit(1)
print(f"SMOKE IMPORTS: ALL {passed} CHECKS PASSED")
print(f"{'='*50}")
