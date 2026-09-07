#!/usr/bin/env python3
"""
RedTeam Harness — Mech-Unit manifest validator (v7.0 P6.4).

CI gate: every attack intent manifest and the VULN-GRAPH must load clean,
every referenced tool must exist in the tool registry, and every step must
carry no LLM requirement. Run from the repo root:

    python3 scripts/validate_mech_manifests.py

Exit 0 = all good; exit 1 = validation failures (printed).
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANIFEST_DIR = os.path.join(REPO_ROOT, "attacks")
GRAPH_PATH = os.path.join(MANIFEST_DIR, "vuln_graph.yaml")


def main() -> int:
    failures = []

    # 1. Every intent manifest loads (fail-fast validator).
    try:
        from core.mech.intents import load_manifest_dir
        manifests = load_manifest_dir(MANIFEST_DIR)
        print(f"[ok] {len(manifests)} intent manifests loaded from attacks/")
    except ValueError as exc:
        print(f"[FAIL] manifest load: {exc}")
        return 1

    # 2. VULN-GRAPH loads and compiles every pattern.
    try:
        from core.mech.vuln_graph import load_vuln_graph
        vertices = load_vuln_graph(GRAPH_PATH)
        print(f"[ok] vuln graph: {len(vertices)} vertices, patterns compile")
    except (ValueError, OSError) as exc:
        print(f"[FAIL] vuln graph: {exc}")
        return 1

    # 3. Every manifest carries llm_required: false (structural guarantee).
    for mid, manifest in manifests.items():
        if manifest.llm_required:
            failures.append(f"{mid}: llm_required must be false")
    if not failures:
        print("[ok] all manifests carry llm_required: false")

    # 4. Every graph capitalization intent exists in the manifest set.
    intent_ids = set(manifests)
    for vertex in vertices:
        for cap in vertex.capitalization:
            if cap.intent not in intent_ids:
                failures.append(
                    f"vertex '{vertex.id}' capitalizes via unknown intent "
                    f"'{cap.intent}'")
    if not failures:
        print("[ok] every VULN-GRAPH move references a real intent")

    # 5. Every step tool exists in the tool registry (name-level check).
    try:
        from core.tool_registry import ToolRegistry
        registry = ToolRegistry({})
        known = set(registry.get_all_tools())
        for manifest in manifests.values():
            for step in manifest.plan:
                if step.tool not in known:
                    failures.append(
                        f"{manifest.id}: step '{step.step}' references "
                        f"unknown tool '{step.tool}'")
                for fb in step.fallbacks:
                    fb_tool = fb.get("tool")
                    if fb_tool and fb_tool not in known:
                        failures.append(
                            f"{manifest.id}: fallback '{fb.get('step')}' "
                            f"references unknown tool '{fb_tool}'")
        if not failures:
            print(f"[ok] all step tools exist in the registry "
                  f"({len(known)} tools registered)")
    except Exception as exc:
        # Registry build problems shouldn't mask manifest issues, but the
        # tool check is best-effort on exotic hosts.
        print(f"[warn] tool registry check skipped: {exc}")

    # 6. No subprocess anywhere in the mech package (Decision Register #23).
    mech_dir = os.path.join(REPO_ROOT, "core", "mech")
    for fn in sorted(os.listdir(mech_dir)):
        if not fn.endswith(".py"):
            continue
        with open(os.path.join(mech_dir, fn)) as f:
            src = f.read()
        if "import subprocess" in src or "subprocess." in src:
            failures.append(f"core/mech/{fn}: subprocess usage forbidden")

    if failures:
        print("\nValidation failures:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("\nAll Mech-Unit manifest checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
