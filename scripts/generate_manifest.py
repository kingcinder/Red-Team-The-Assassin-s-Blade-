#!/usr/bin/env python3
"""
generate_manifest.py — Build the air-gapped provisioning manifest.

Cross-references:
  - requirements.txt ↔ wheels/ directory (Python dependency coverage)
  - Tool registry ↔ INSTALL_RECIPES ↔ config.yaml (Kali tool coverage)

Output: MANIFEST.json (single source of truth for air-gapped deployments)

Usage:
    python3 scripts/generate_manifest.py
    python3 scripts/generate_manifest.py --verify   # exit 1 if out of date
"""
import sys
import os
import re
import ast
import json
import hashlib

# Ensure we can import from the harness root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

HARNESS_ROOT = os.path.join(os.path.dirname(__file__), "..")
MANIFEST_PATH = os.path.join(HARNESS_ROOT, "MANIFEST.json")


def parse_requirements(req_path):
    """Parse requirements.txt into {pkg_lower: {spec, raw}}."""
    reqs = {}
    with open(req_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r"^([a-zA-Z0-9_-]+)\s*(.*)", line)
            if m:
                reqs[m.group(1).lower()] = {"spec": m.group(2) or "*", "raw": line}
    return reqs


def scan_wheels(wheels_dir):
    """Scan wheels/ directory, return {pkg_lower: {version, filename}}."""
    wheels = {}
    if not os.path.isdir(wheels_dir):
        return wheels
    for fn in os.listdir(wheels_dir):
        if fn.endswith(".whl"):
            parts = fn.split("-")
            if len(parts) >= 2:
                pkg = parts[0].lower()
                ver = parts[1]
                wheels[pkg] = {"version": ver, "filename": fn}
    return wheels


def scan_imports(root_dir):
    """Scan all .py files for third-party imports."""
    stdlib = set()
    try:
        stdlib = set(sys.stdlib_module_names)
    except AttributeError:
        pass
    extra_stdlib = {
        "abc", "argparse", "array", "ast", "base64", "binascii", "bisect",
        "builtins", "bz2", "calendar", "cgi", "cmath", "cmd", "code",
        "codecs", "codeop", "collections", "compileall", "concurrent",
        "configparser", "contextlib", "contextvars", "copy", "copyreg",
        "csv", "ctypes", "dataclasses", "datetime", "decimal", "difflib",
        "dis", "email", "encodings", "enum", "errno", "faulthandler",
        "fcntl", "filecmp", "fileinput", "fnmatch", "fractions", "ftplib",
        "functools", "gc", "getopt", "getpass", "gettext", "glob", "grp",
        "gzip", "hashlib", "heapq", "hmac", "html", "http", "imaplib",
        "imp", "importlib", "inspect", "io", "ipaddress", "itertools",
        "json", "keyword", "linecache", "locale", "logging", "lzma",
        "mailbox", "marshal", "math", "mimetypes", "mmap", "multiprocessing",
        "numbers", "operator", "os", "pathlib", "pdb", "pickle",
        "pickletools", "pipes", "pkgutil", "platform", "plistlib", "posix",
        "posixpath", "pprint", "profile", "pstats", "pty", "pwd",
        "py_compile", "pyclbr", "pydoc", "queue", "quopri", "random", "re",
        "readline", "reprlib", "resource", "rlcompleter", "runpy", "sched",
        "secrets", "select", "selectors", "shelve", "shlex", "shutil",
        "signal", "site", "smtplib", "socket", "socketserver", "sqlite3",
        "ssl", "stat", "statistics", "string", "stringprep", "struct",
        "subprocess", "sys", "sysconfig", "syslog", "tabnanny", "tarfile",
        "tempfile", "termios", "test", "textwrap", "threading", "time",
        "timeit", "tkinter", "token", "tokenize", "trace", "traceback",
        "tracemalloc", "tty", "types", "typing", "unicodedata", "unittest",
        "urllib", "uuid", "venv", "warnings", "wave", "weakref",
        "webbrowser", "wsgiref", "xml", "xmlrpc", "zipapp", "zipfile",
        "zipimport", "zlib",
    }
    stdlib |= extra_stdlib
    internal_prefixes = ("core", "dashboard", "tools", "harness")

    imports = set()
    skip_dirs = {"__pycache__", ".git", "node_modules", "wheels", "sessions", "output", ".github"}
    for root, dirs, files in os.walk(root_dir):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for f in files:
            if not f.endswith(".py"):
                continue
            path = os.path.join(root, f)
            try:
                with open(path) as fh:
                    tree = ast.parse(fh.read())
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            top = alias.name.split(".")[0]
                            if top not in stdlib and not top.startswith(internal_prefixes):
                                imports.add(top)
                    elif isinstance(node, ast.ImportFrom) and node.module:
                        top = node.module.split(".")[0]
                        if top not in stdlib and not top.startswith(internal_prefixes):
                            imports.add(top)
            except Exception:
                pass
    return imports


def get_tools_data():
    """Load tool registry, installer recipes, and config.yaml tools."""
    from core.tool_registry import ToolRegistry
    from tools import ALL_TOOL_MODULES
    from core.tool_installer import INSTALL_RECIPES

    registry = ToolRegistry({})
    for mod_cls in ALL_TOOL_MODULES:
        try:
            mod = mod_cls(registry)
        except Exception:
            pass

    import yaml
    with open(os.path.join(HARNESS_ROOT, "config.yaml")) as f:
        cfg = yaml.safe_load(f)
    config_tools = cfg.get("tools", {})

    return registry, INSTALL_RECIPES, config_tools


def build_manifest():
    """Build the complete manifest dict."""
    req_path = os.path.join(HARNESS_ROOT, "requirements.txt")
    wheels_dir = os.path.join(HARNESS_ROOT, "wheels")

    reqs = parse_requirements(req_path)
    wheels = scan_wheels(wheels_dir)
    imports = scan_imports(HARNESS_ROOT)
    registry, install_recipes, config_tools = get_tools_data()

    # ── Python dependencies ──
    python_deps = []
    seen_pkgs = set()
    for pkg, info in sorted(reqs.items()):
        wheel = wheels.get(pkg)
        entry = {
            "package": pkg,
            "requirement": info["raw"],
            "in_requirements_txt": True,
            "in_wheels_bundle": wheel is not None,
            "wheel_version": wheel["version"] if wheel else None,
            "wheel_filename": wheel["filename"] if wheel else None,
            "imported_in_code": pkg in imports or pkg.replace("_", "-") in imports or pkg.replace("-", "_") in imports,
            "status": "ok" if wheel else "MISSING_FROM_WHEELS",
        }
        python_deps.append(entry)
        seen_pkgs.add(pkg)

    for pkg, info in sorted(wheels.items()):
        if pkg not in seen_pkgs:
            python_deps.append({
                "package": pkg,
                "requirement": None,
                "in_requirements_txt": False,
                "in_wheels_bundle": True,
                "wheel_version": info["version"],
                "wheel_filename": info["filename"],
                "imported_in_code": pkg in imports,
                "status": "transitive_dependency",
            })

    # ── Kali tools ──
    kali_tools = []
    seen_binaries = set()
    for name, tool in sorted(registry._tools.items()):
        binary = tool.binary or tool.name
        if binary in seen_binaries:
            continue
        seen_binaries.add(binary)
        recipe = install_recipes.get(binary, install_recipes.get(tool.name))
        config_entry = config_tools.get(binary, config_tools.get(tool.name))
        kali_tools.append({
            "binary": binary,
            "tool_name": tool.name,
            "category": tool.category,
            "installed_on_host": tool.installed,
            "has_installer_recipe": recipe is not None,
            "install_method": recipe.get("method") if recipe else None,
            "install_package": recipe.get("package") or recipe.get("repo") if recipe else None,
            "in_config_yaml": config_entry is not None,
            "status": "installed" if tool.installed else ("installable" if recipe else "manual_install_required"),
        })

    for binary, path in sorted(config_tools.items()):
        if binary not in seen_binaries:
            seen_binaries.add(binary)
            recipe = install_recipes.get(binary)
            kali_tools.append({
                "binary": binary,
                "tool_name": binary,
                "category": "config_only",
                "installed_on_host": os.path.which(binary) is not None,
                "has_installer_recipe": recipe is not None,
                "install_method": recipe.get("method") if recipe else None,
                "install_package": recipe.get("package") or recipe.get("repo") if recipe else None,
                "in_config_yaml": True,
                "status": "config_only",
            })

    # ── Summaries ──
    installed_count = sum(1 for t in kali_tools if t["installed_on_host"])
    missing_count = sum(1 for t in kali_tools if not t["installed_on_host"])
    installable_count = sum(1 for t in kali_tools if not t["installed_on_host"] and t["has_installer_recipe"])
    wheel_ok = sum(1 for d in python_deps if d["status"] == "ok")
    wheel_missing = sum(1 for d in python_deps if d["status"] == "MISSING_FROM_WHEELS")

    wheel_size = 0
    if os.path.isdir(wheels_dir):
        for fn in os.listdir(wheels_dir):
            if fn.endswith(".whl"):
                wheel_size += os.path.getsize(os.path.join(wheels_dir, fn))

    return {
        "_meta": {
            "description": "RedTeam Harness air-gapped provisioning manifest",
            "version": "1.0.0",
            "generated_by": "scripts/generate_manifest.py",
            "purpose": "Single source of truth for all Python dependencies and Kali tools",
        },
        "python_dependencies": {
            "summary": {
                "requirements_txt_packages": len(reqs),
                "wheels_bundle_packages": len(wheels),
                "third_party_imports": len(imports),
                "wheel_coverage_ok": wheel_ok,
                "wheel_coverage_missing": wheel_missing,
                "all_wheels_present": wheel_missing == 0,
            },
            "packages": python_deps,
        },
        "kali_tools": {
            "summary": {
                "total_tracked": len(kali_tools),
                "installed_on_host": installed_count,
                "missing_from_host": missing_count,
                "auto_installable": installable_count,
                "manual_install_required": missing_count - installable_count,
            },
            "tools": kali_tools,
        },
        "installer_recipes": {
            "summary": {
                "total_recipes": len(install_recipes),
                "apt_recipes": sum(1 for r in install_recipes.values() if r.get("method") == "apt"),
                "pip_recipes": sum(1 for r in install_recipes.values() if r.get("method") == "pip"),
                "go_recipes": sum(1 for r in install_recipes.values() if r.get("method") == "go"),
                "github_release_recipes": sum(1 for r in install_recipes.values() if r.get("method") == "github_release"),
                "script_recipes": sum(1 for r in install_recipes.values() if r.get("method") in ("script", "shell_script")),
                "git_recipes": sum(1 for r in install_recipes.values() if r.get("method") == "git"),
            },
            "recipes": {k: v for k, v in sorted(install_recipes.items())},
        },
        "offline_bundle": {
            "wheels_dir": "wheels/",
            "wheel_count": len(wheels),
            "total_wheel_size_mb": round(wheel_size / 1024 / 1024, 1),
            "install_command": "pip install --no-index --find-links=wheels/ -r requirements.txt",
        },
    }


def main():
    verify_only = "--verify" in sys.argv

    manifest = build_manifest()

    if verify_only:
        if not os.path.exists(MANIFEST_PATH):
            print("ERROR: MANIFEST.json does not exist. Run without --verify first.")
            return 1
        with open(MANIFEST_PATH) as f:
            existing = json.load(f)
        if json.dumps(manifest, sort_keys=True) == json.dumps(existing, sort_keys=True):
            print("MANIFEST.json is up to date.")
            return 0
        else:
            print("ERROR: MANIFEST.json is out of date. Run: python3 scripts/generate_manifest.py")
            return 1
    else:
        with open(MANIFEST_PATH, "w") as f:
            json.dump(manifest, f, indent=2)
        s = manifest["python_dependencies"]["summary"]
        t = manifest["kali_tools"]["summary"]
        print(f"Written {MANIFEST_PATH}")
        print(f"  Python: {s['requirements_txt_packages']} reqs, {s['wheels_bundle_packages']} wheels, {s['wheel_coverage_missing']} missing")
        print(f"  Kali:   {t['total_tracked']} tools, {t['installed_on_host']} installed, {t['auto_installable']} installable, {t['manual_install_required']} manual")
        return 0


if __name__ == "__main__":
    sys.exit(main())
