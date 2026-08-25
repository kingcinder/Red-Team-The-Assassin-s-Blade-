#!/usr/bin/env python3
"""Functional test for the Correlation Attack Graph visualizer (v5.3).

Covers: the FindingCorrelator attack-graph data structure (nodes/edges/
metadata), the /api/correlation/graph endpoint wiring (task_id vs
campaign_id sources, error handling), the shared campaign-findings
collector, and the /api/tasks/all source picker.
"""
import os
import sys
import json
import py_compile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

for m in ["core/correlation.py", "core/orchestrator.py",
          "dashboard/server.py"]:
    try:
        py_compile.compile(m, doraise=True)
        print(f"OK {m}")
    except py_compile.PyCompileError as e:
        print(f"FAIL {m}: {e}")
        sys.exit(1)

from core.correlation import FindingCorrelator
from dashboard.server import _collect_campaign_findings


def sample_findings():
    return [
        {"target": "10.0.0.1", "severity": "critical", "title": "SQL injection on login",
         "dedupe_key": "sqli_login", "source_tool": "sqlmap_scan",
         "evidence": "error-based injection in /login"},
        {"target": "10.0.0.1", "severity": "high", "title": "Open SMB port 445",
         "dedupe_key": "smb_445", "source_tool": "nmap_scan",
         "evidence": "tcp/445 open microsoft-ds"},
        {"target": "10.0.0.2", "severity": "medium", "title": "Apache exposed",
         "dedupe_key": "apache_exposed", "source_tool": "nmap_scan",
         "evidence": "tcp/80 open http"},
        {"target": "10.0.0.3", "severity": "info", "title": "DNS zone transfer allowed",
         "dedupe_key": "dns_zone", "source_tool": "dns_scan",
         "evidence": "AXFR succeeded"},
    ]


# ═══════════════════════════════════════════════════════════════
# 1. Attack graph data structure (nodes/edges/metadata)
# ═══════════════════════════════════════════════════════════════
def test_graph_structure():
    print("\n── graph structure ──")
    corr = FindingCorrelator()
    paths = corr.correlate(sample_findings())
    assert len(paths) >= 1, "expected at least one correlated path"
    # Every path carries the SAME graph object (attached by correlate)
    graph = paths[0].get("graph", {})
    assert "nodes" in graph and "edges" in graph and "metadata" in graph

    nodes = graph["nodes"]
    edges = graph["edges"]
    assert len(nodes) >= 1, "graph must have path nodes"
    assert len(edges) >= 1, "graph must have edges"

    # Node types: at least one 'path' node
    types = {n.get("type") for n in nodes}
    assert "path" in types, f"missing path node type, got {types}"
    # Every node has severity + id + label
    for n in nodes:
        assert n.get("id") and n.get("label"), f"node missing id/label: {n}"
        assert n.get("severity"), f"node missing severity: {n}"

    # Edge shapes: source/target/type
    for e in edges:
        assert e.get("source") and e.get("target"), f"edge missing endpoints: {e}"
        assert e.get("type") in ("belongs_to", "chain"), f"bad edge type: {e}"

    # Metadata
    md = graph["metadata"]
    assert md.get("total_nodes") == len(nodes)
    assert md.get("total_edges") == len(edges)
    assert md.get("total_paths") == len(paths)
    # Severity distribution counts paths by severity
    assert "severity_distribution" in md
    print("  graph structure: OK")


# ═══════════════════════════════════════════════════════════════
# 2. Endpoint wiring: /api/correlation/graph
# ═══════════════════════════════════════════════════════════════
def test_endpoint_wiring():
    print("\n── endpoint wiring ──")
    srv = open(os.path.join(os.path.dirname(__file__), "..",
                            "dashboard", "server.py")).read()
    orch = open(os.path.join(os.path.dirname(__file__), "..",
                             "core", "orchestrator.py")).read()
    # Route exists
    assert '"/api/correlation/graph"' in srv
    assert '"/api/tasks/all"' in srv
    # Requires task_id or campaign_id
    assert "request.args.get(\"task_id\", \"\")" in srv
    assert "request.args.get(\"campaign_id\", \"\")" in srv
    assert "Provide ?task_id= or ?campaign_id=" in srv
    # Task source delegates to orchestrator's task correlation
    assert "orchestrator.get_task_correlation(task_id)" in srv
    # Campaign source uses the shared collector + correlator
    assert "_collect_campaign_findings(campaign, config)" in srv
    assert "orchestrator.correlate_findings(all_findings)" in srv
    # Returns the graph (paths[0].graph — correlator attaches same object)
    assert "paths[0].get(\"graph\", {})" in srv
    assert '"source": task_id or campaign_id' in srv
    # /api/tasks/all must EXCLUDE multi_* combined-run dirs (their task_ids
    # don't match the get_task_correlation regex → would 404 in the picker)
    assert '"/api/tasks/all"' in srv
    assert "ts.startswith(\"multi_\")" in srv, \
        "tasks/all must skip multi_* combined-run directories"
    # Orchestrator exposes task correlation
    assert "def get_task_correlation" in orch
    print("  endpoint wiring: OK")


# ═══════════════════════════════════════════════════════════════
# 3. Shared campaign findings collector
# ═══════════════════════════════════════════════════════════════
def test_campaign_findings_collector():
    print("\n── campaign findings collector ──")
    # Retained per-target findings (campaign comparison view) get collected
    campaign = {
        "per_target": {
            "10.0.0.1": {"findings": [
                {"title": "SQL injection on login", "severity": "critical",
                 "dedupe_key": "sqli_login", "source_tool": "sqlmap_scan"}]},
            "10.0.0.2": {"findings": []},
        },
        "findings_total": 1,
    }
    cfg = {"workflow": {"tasks_dir": "/tmp/rt_ag_nonexistent_tasks"}}
    collected = _collect_campaign_findings(campaign, cfg)
    assert len(collected) == 1
    f = collected[0]
    assert f["target"] == "10.0.0.1", "collector must tag retained findings with target"
    assert f["dedupe_key"] == "sqli_login"
    # No findings → empty
    empty = _collect_campaign_findings({"per_target": {}}, cfg)
    assert empty == []
    # Missing per_target → empty
    assert _collect_campaign_findings({}, cfg) == []
    print("  campaign findings collector: OK")


# ═══════════════════════════════════════════════════════════════
# 4. Empty-graph fallbacks (no findings anywhere)
# ═══════════════════════════════════════════════════════════════
def test_empty_fallbacks():
    print("\n── empty graph fallbacks ──")
    corr = FindingCorrelator()
    paths = corr.correlate([])
    assert paths == []
    # correlate_findings returns empty structure
    from core.orchestrator import Orchestrator
    # (Orchestrator needs a config but correlate_findings is pure — build one
    #  with a minimal config; it won't touch the LLM for empty input)
    orch = Orchestrator.__new__(Orchestrator)
    orch.correlator = corr
    result = orch.correlate_findings([])
    assert result["paths"] == [] and result["paths_count"] == 0
    print("  empty fallbacks: OK")


test_graph_structure()
test_endpoint_wiring()
test_campaign_findings_collector()
test_empty_fallbacks()

print("\n=== ALL ATTACK GRAPH VISUALIZER TESTS PASSED ===")
