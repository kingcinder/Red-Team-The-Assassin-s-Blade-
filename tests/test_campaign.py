#!/usr/bin/env python3
"""Functional test for the C2 Campaign Manager (live campaign dashboard backend).

Covers: campaign creation, per-target live progress, findings heatmap grid,
drift confidence gauges, cumulative risk scoring, aggregate recomputation,
and the real-time SocketIO event wiring that drives the dashboard.
"""
import os
import sys
import py_compile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# 1. Compile check
for m in ["core/campaign.py", "core/task_scheduler.py", "dashboard/server.py"]:
    try:
        py_compile.compile(m, doraise=True)
        print(f"OK {m}")
    except py_compile.PyCompileError as e:
        print(f"FAIL {m}: {e}")
        sys.exit(1)

from core.campaign import CampaignManager


def make_campaign(n_targets=3):
    mgr = CampaignManager(tasks_dir="/tmp/rt_campaign_tests")
    targets = [f"10.0.0.{i}" for i in range(1, n_targets + 1)]
    camp = mgr.create_campaign("Test Campaign", targets, workflow="recon_scan.yaml")
    return mgr, camp, targets


# ═══════════════════════════════════════════════════════════════
# 1. Campaign creation
# ═══════════════════════════════════════════════════════════════
def test_creation():
    print("\n── campaign creation ──")
    mgr, camp, targets = make_campaign()
    assert camp["status"] == "created"
    assert camp["targets"] == targets
    assert set(camp["per_target"].keys()) == set(targets)
    for t in targets:
        p = camp["per_target"][t]
        assert p["status"] == "pending"
        assert p["progress"] == 0
        assert p["findings_by_severity"] == {"critical": 0, "high": 0, "medium": 0,
                                              "low": 0, "info": 0}
    assert camp["findings_total"] == 0
    assert camp["risk_score"] == 0.0
    # list_campaigns summary shape
    summaries = mgr.list_campaigns()
    assert len(summaries) == 1
    s = summaries[0]
    assert s["id"] == camp["id"] and s["target_count"] == 3
    print("  creation: OK")


# ═══════════════════════════════════════════════════════════════
# 2. Per-target live progress
# ═══════════════════════════════════════════════════════════════
def test_progress_bars():
    print("\n── per-target progress bars ──")
    mgr, camp, targets = make_campaign()
    # Simulate a workflow completing 3 of 5 steps on target 1
    mgr.update_target(camp["id"], "10.0.0.1", {
        "status": "running",
        "completed_steps": 3,
        "total_steps": 5,
        "findings": [{"severity": "high", "source_tool": "nmap_scan"},
                     {"severity": "info", "source_tool": "nmap_scan"}],
    })
    t1 = mgr.get_campaign(camp["id"])["per_target"]["10.0.0.1"]
    assert t1["progress"] == 60, f"progress={t1['progress']}"
    assert t1["status"] == "running"
    assert t1["started"] is not None
    assert t1["findings_count"] == 2
    assert t1["findings_by_severity"]["high"] == 1
    assert t1["findings_by_severity"]["info"] == 1
    # Complete it
    mgr.update_target(camp["id"], "10.0.0.1", {
        "status": "complete", "completed_steps": 5, "total_steps": 5,
        "findings": [], "drift_score": 0.1,
    })
    t1 = mgr.get_campaign(camp["id"])["per_target"]["10.0.0.1"]
    assert t1["progress"] == 100
    assert t1["status"] == "complete"
    assert t1["finished"] is not None
    assert t1["drift_confidence"] == "high"  # 0.1 <= 0.15
    print("  progress bars: OK")


# ═══════════════════════════════════════════════════════════════
# 3. Findings heatmap grid (tool × severity)
# ═══════════════════════════════════════════════════════════════
def test_heatmap():
    print("\n── findings heatmap grid ──")
    mgr, camp, targets = make_campaign(2)
    mgr.update_target(camp["id"], "10.0.0.1", {
        "status": "complete", "completed_steps": 2, "total_steps": 2,
        "findings": [
            {"severity": "critical", "source_tool": "nmap_scan"},
            {"severity": "high", "source_tool": "nmap_scan"},
            {"severity": "critical", "source_tool": "sqlmap_scan"},
        ],
    })
    mgr.update_target(camp["id"], "10.0.0.2", {
        "status": "complete", "completed_steps": 2, "total_steps": 2,
        "findings": [
            {"severity": "medium", "source_tool": "nmap_scan"},
        ],
    })
    hm = mgr.get_target_heatmap(camp["id"])
    assert hm["total"] == 4
    assert "nmap_scan" in hm["tools"] and "sqlmap_scan" in hm["tools"]
    grid = hm["grid"]
    assert grid["nmap_scan"]["critical"] == 1
    assert grid["nmap_scan"]["high"] == 1
    assert grid["nmap_scan"]["medium"] == 1
    assert grid["sqlmap_scan"]["critical"] == 1
    # Every tool row has all 5 severity columns
    for tool, row in grid.items():
        assert set(row.keys()) == {"critical", "high", "medium", "low", "info"}
    print("  heatmap grid: OK")


# ═══════════════════════════════════════════════════════════════
# 4. Drift confidence gauges
# ═══════════════════════════════════════════════════════════════
def test_drift_gauges():
    print("\n── drift confidence gauges ──")
    mgr, camp, targets = make_campaign(3)
    # high confidence (low drift)
    mgr.update_target(camp["id"], "10.0.0.1", {
        "status": "complete", "completed_steps": 1, "total_steps": 1,
        "drift_score": 0.05})
    # medium
    mgr.update_target(camp["id"], "10.0.0.2", {
        "status": "complete", "completed_steps": 1, "total_steps": 1,
        "drift_score": 0.3})
    # low/uncertain
    mgr.update_target(camp["id"], "10.0.0.3", {
        "status": "complete", "completed_steps": 1, "total_steps": 1,
        "drift_score": 0.8})
    c = mgr.get_campaign(camp["id"])
    pts = c["per_target"]
    assert pts["10.0.0.1"]["drift_confidence"] == "high"
    assert pts["10.0.0.2"]["drift_confidence"] == "medium"
    assert pts["10.0.0.3"]["drift_confidence"] == "uncertain"
    # Campaign aggregate drift = mean of per-target drift
    assert abs(c["drift_avg"] - round((0.05 + 0.3 + 0.8) / 3, 3)) < 0.001
    assert c["drift_confidence"] == "medium"
    print("  drift gauges: OK")


# ═══════════════════════════════════════════════════════════════
# 5. Cumulative risk scoring
# ═══════════════════════════════════════════════════════════════
def test_risk_scoring():
    print("\n── cumulative risk scoring ──")
    mgr, camp, targets = make_campaign(2)
    # High-severity findings should push risk up
    mgr.update_target(camp["id"], "10.0.0.1", {
        "status": "complete", "completed_steps": 1, "total_steps": 1,
        "findings": [{"severity": "critical", "source_tool": "nmap_scan"},
                     {"severity": "high", "source_tool": "nmap_scan"}],
        "drift_score": 0.05,
    })
    mgr.update_target(camp["id"], "10.0.0.2", {
        "status": "complete", "completed_steps": 1, "total_steps": 1,
        "findings": [], "drift_score": 0.05,
    })
    risk = mgr.get_risk_summary(camp["id"])
    assert risk["total_risk"] > 0, "critical findings must raise risk"
    assert "rating" in risk and "breakdown" in risk
    assert risk["breakdown"]["findings_severity_risk"] > 0
    assert risk["coverage_pct"] == 100, "both targets complete → full coverage"
    assert risk["targets_completed"] == 2
    # Campaign-level risk_score matches the summary
    c = mgr.get_campaign(camp["id"])
    assert c["risk_score"] == risk["total_risk"]
    # No-finding campaign ≈ minimal risk
    mgr2 = CampaignManager()
    camp2 = mgr2.create_campaign("Clean", ["10.0.0.9"], workflow="x")
    mgr2.update_target(camp2["id"], "10.0.0.9", {
        "status": "complete", "completed_steps": 1, "total_steps": 1})
    risk2 = mgr2.get_risk_summary(camp2["id"])
    assert risk2["total_risk"] <= 12, f"clean campaign risk too high: {risk2['total_risk']}"
    print("  risk scoring: OK")


# ═══════════════════════════════════════════════════════════════
# 6. Aggregate recomputation + campaign status
# ═══════════════════════════════════════════════════════════════
def test_aggregates():
    print("\n── aggregate recomputation ──")
    mgr, camp, targets = make_campaign(3)
    mgr.mark_target_started(camp["id"], "10.0.0.1")
    c = mgr.get_campaign(camp["id"])
    assert c["status"] == "running" and c["active_targets"] == 1
    # One complete, one failed
    mgr.update_target(camp["id"], "10.0.0.1", {
        "status": "complete", "completed_steps": 1, "total_steps": 1})
    mgr.update_target(camp["id"], "10.0.0.2", {
        "status": "failed", "completed_steps": 0, "total_steps": 1,
        "error": "gate failed"})
    c = mgr.get_campaign(camp["id"])
    assert c["completed_targets"] == 1
    assert c["failed_targets"] == 1
    # Third target is still pending — pending ≠ active
    assert c["active_targets"] == 0, f"active={c['active_targets']} (t3 pending)"
    # Complete the last → all done, but one target FAILED → campaign status
    # is 'failed' (correct: a campaign with a failed target isn't 'complete')
    mgr.update_target(camp["id"], "10.0.0.3", {
        "status": "complete", "completed_steps": 1, "total_steps": 1})
    c = mgr.get_campaign(camp["id"])
    assert c["status"] == "failed", f"failed-target campaign status={c['status']}"
    assert c["completed_targets"] == 2 and c["failed_targets"] == 1
    # mark_campaign_complete is idempotent-safe
    mgr.mark_campaign_complete(camp["id"])
    # Clean campaign (no failures) → 'complete'
    mgr2 = CampaignManager()
    camp2 = mgr2.create_campaign("Clean", ["10.0.0.9"], workflow="x")
    mgr2.update_target(camp2["id"], "10.0.0.9", {
        "status": "complete", "completed_steps": 1, "total_steps": 1})
    assert mgr2.get_campaign(camp2["id"])["status"] == "complete"
    # Error on unknown campaign/target
    assert "error" in mgr.get_campaign("nope")
    assert "error" in mgr.update_target(camp["id"], "9.9.9.9", {"status": "x"})
    print("  aggregates: OK")


# ═══════════════════════════════════════════════════════════════
# 6b. No double-counting when both the scheduler and the dashboard event
#     handler update the same campaign (the server handler must NOT pass
#     findings — the scheduler's direct update_target is authoritative).
# ═══════════════════════════════════════════════════════════════
def test_no_findings_double_count():
    print("\n── no findings double-count ──")
    mgr, camp, targets = make_campaign(1)
    findings = [{"severity": "critical", "source_tool": "nmap_scan"},
                {"severity": "high", "source_tool": "nmap_scan"}]
    # Path 1: scheduler's run_one() calls update_target WITH findings
    mgr.update_target(camp["id"], "10.0.0.1", {
        "status": "complete", "completed_steps": 2, "total_steps": 2,
        "findings": findings, "drift_score": 0.1})
    # Path 2: dashboard on_workflow_complete_campaign fires and must NOT
    # re-add findings (would double-count) — only status/progress/error.
    mgr.update_target(camp["id"], "10.0.0.1", {
        "status": "complete", "completed_steps": 2, "total_steps": 2,
        "error": None})
    c = mgr.get_campaign(camp["id"])
    assert c["findings_total"] == 2, f"findings double-counted: {c['findings_total']}"
    t = c["per_target"]["10.0.0.1"]
    assert t["findings_count"] == 2
    assert t["findings_by_severity"]["critical"] == 1
    assert t["findings_by_severity"]["high"] == 1
    hm = mgr.get_target_heatmap(camp["id"])
    assert hm["total"] == 2, f"heatmap total inflated: {hm['total']}"
    print("  no double-count: OK")


# ═══════════════════════════════════════════════════════════════
# 7. Real-time SocketIO wiring (scheduler → orchestrator → dashboard)
# ═══════════════════════════════════════════════════════════════
def test_realtime_wiring():
    print("\n── real-time SocketIO wiring ──")
    sched_src = open(os.path.join(os.path.dirname(__file__), "..",
                                  "core", "task_scheduler.py")).read()
    orch_src = open(os.path.join(os.path.dirname(__file__), "..",
                                 "core", "orchestrator.py")).read()
    srv_src = open(os.path.join(os.path.dirname(__file__), "..",
                                "dashboard", "server.py")).read()

    # The scheduler must emit the PREFIXED event names the dashboard subscribes to
    assert 'self._emit("on_workflow_start"' in sched_src, \
        "scheduler must emit on_workflow_start (prefixed)"
    assert 'self._emit("on_workflow_complete"' in sched_src, \
        "scheduler must emit on_workflow_complete (prefixed)"
    assert 'self._emit("multi_target_progress"' in sched_src
    # Scheduler progress payloads must carry campaign_id (JS matches on it)
    assert '"campaign_id": campaign_id' in sched_src
    # Orchestrator must register multi_target_progress in _callbacks
    assert '"multi_target_progress": []' in orch_src
    # Dashboard must forward it to SocketIO (and NOT re-add findings)
    assert "on_multi_target_progress" in srv_src
    assert 'orchestrator.on("multi_target_progress"' in srv_src
    assert "double-count" in srv_src.lower(), "server must document the double-count guard"
    # Dashboard campaign handlers subscribed to the prefixed names
    assert 'orchestrator.on("on_workflow_start", on_workflow_start_campaign)' in srv_src
    assert 'orchestrator.on("on_workflow_complete", on_workflow_complete_campaign)' in srv_src
    print("  real-time wiring: OK")


# ═══════════════════════════════════════════════════════════════
# 8. Campaign comparison (side-by-side view)
# ═══════════════════════════════════════════════════════════════
def test_compare_campaigns():
    print("\n── campaign comparison ──")
    mgr = CampaignManager(tasks_dir="/tmp/rt_campaign_tests")
    # Campaign A: target .1 has port 22 open + weak ssh (persistent), .2 has apache
    camp_a = mgr.create_campaign("Engagement A", ["10.0.0.1", "10.0.0.2"],
                                 workflow="recon_scan.yaml")
    mgr.update_target(camp_a["id"], "10.0.0.1", {
        "status": "complete", "completed_steps": 3, "total_steps": 3,
        "findings": [
            {"title": "Open port 22", "severity": "medium", "source_tool": "nmap_scan",
             "dedupe_key": "port_22_open", "evidence": "tcp/22 open ssh"},
            {"title": "Weak SSH ciphers", "severity": "high", "source_tool": "ssh_audit",
             "dedupe_key": "ssh_weak_ciphers", "evidence": "arcfour enabled"},
        ]})
    mgr.update_target(camp_a["id"], "10.0.0.2", {
        "status": "complete", "completed_steps": 2, "total_steps": 2,
        "findings": [
            {"title": "Apache exposed", "severity": "medium", "source_tool": "nmap_scan",
             "dedupe_key": "apache_exposed"},
        ]})
    # Campaign B: .1 still has the SAME weak ssh (persistent exposure), .3 has SQLi
    camp_b = mgr.create_campaign("Engagement B", ["10.0.0.1", "10.0.0.3"],
                                 workflow="web_pentest.yaml")
    mgr.update_target(camp_b["id"], "10.0.0.1", {
        "status": "complete", "completed_steps": 3, "total_steps": 3,
        "findings": [
            {"title": "Weak SSH ciphers", "severity": "high", "source_tool": "ssh_audit",
             "dedupe_key": "ssh_weak_ciphers"},
        ]})
    mgr.update_target(camp_b["id"], "10.0.0.3", {
        "status": "complete", "completed_steps": 2, "total_steps": 2,
        "findings": [
            {"title": "SQL Injection", "severity": "critical", "source_tool": "sqlmap_scan",
             "dedupe_key": "sqli_login"},
        ]})

    cmp = mgr.compare_campaigns(camp_a["id"], camp_b["id"])
    assert "error" not in cmp

    # Overlap: ssh_weak_ciphers found in BOTH
    assert cmp["overlap_count"] == 1, f"overlap={cmp['overlap_count']}"
    ov = cmp["overlap"][0]
    assert ov["dedupe_key"] == "ssh_weak_ciphers"
    assert ov["persistent"] is True, "same host (10.0.0.1) in both → persistent"
    assert ov["shared_targets"] == ["10.0.0.1"]

    # Uniques: A-only = port_22_open + apache_exposed; B-only = sqli_login
    assert cmp["unique_a_count"] == 2
    assert cmp["unique_b_count"] == 1
    assert {u["dedupe_key"] for u in cmp["unique_a"]} == {"port_22_open", "apache_exposed"}
    assert cmp["unique_b"][0]["dedupe_key"] == "sqli_login"

    # Common target = 10.0.0.1, with its persistent vuln listed
    assert cmp["common_targets"] == ["10.0.0.1"]
    assert len(cmp["per_target_overlap"]) == 1
    assert cmp["per_target_overlap"][0]["target"] == "10.0.0.1"
    assert cmp["per_target_overlap"][0]["vulns"][0]["dedupe_key"] == "ssh_weak_ciphers"

    # Attack paths: shared contains ssh_weak_ciphers; a_only/b_only are disjoint
    shared_keys = {s["dedupe_key"] for s in cmp["attack_paths"]["shared"]}
    assert "ssh_weak_ciphers" in shared_keys
    a_only_keys = {s["dedupe_key"] for s in cmp["attack_paths"]["a_only"]}
    b_only_keys = {s["dedupe_key"] for s in cmp["attack_paths"]["b_only"]}
    assert "sqli_login" in b_only_keys
    assert not (a_only_keys & shared_keys) and not (b_only_keys & shared_keys)

    # Risk side-by-side: B has a critical finding → higher risk score
    assert cmp["campaign_a"]["risk"]["score"] >= 0
    assert cmp["campaign_b"]["risk"]["score"] > cmp["campaign_a"]["risk"]["score"], \
        f"B({cmp['campaign_b']['risk']['score']}) should outrank A({cmp['campaign_a']['risk']['score']})"
    assert cmp["campaign_b"]["severity_counts"]["critical"] == 1
    assert cmp["campaign_a"]["findings_total"] == 3
    assert cmp["campaign_b"]["findings_total"] == 2
    print("  comparison: OK")


def test_compare_errors():
    print("\n── campaign comparison errors ──")
    mgr = CampaignManager(tasks_dir="/tmp/rt_campaign_tests")
    camp = mgr.create_campaign("Only", ["10.0.0.9"], workflow="x")
    # Missing campaign
    assert "error" in mgr.compare_campaigns(camp["id"], "nope")
    assert "error" in mgr.compare_campaigns("nope", camp["id"])
    # No findings on either side → empty overlap, clean structure
    camp2 = mgr.create_campaign("Empty", ["10.0.0.8"], workflow="x")
    cmp = mgr.compare_campaigns(camp["id"], camp2["id"])
    assert "error" not in cmp
    assert cmp["overlap_count"] == 0
    assert cmp["unique_a_count"] == 0 and cmp["unique_b_count"] == 0
    assert cmp["common_targets"] == []
    print("  comparison errors: OK")


# ═══════════════════════════════════════════════════════════════
# 9. Comparison REST route wiring (registered BEFORE dynamic route)
# ═══════════════════════════════════════════════════════════════
def test_compare_route_wiring():
    print("\n── comparison REST route wiring ──")
    srv_src = open(os.path.join(os.path.dirname(__file__), "..",
                                "dashboard", "server.py")).read()
    # Route exists and is registered before the dynamic <campaign_id> route.
    # Match the DECORATOR lines (the server comment also mentions the dynamic
    # route text, so a bare .index() would hit the comment instead).
    assert '"/api/campaigns/compare"' in srv_src
    dec_cmp = '@app.route("/api/campaigns/compare")'
    dec_dyn = '@app.route("/api/campaigns/<campaign_id>")'
    assert dec_cmp in srv_src and dec_dyn in srv_src
    assert srv_src.index(dec_cmp) < srv_src.index(dec_dyn), \
        "compare route must be registered before the dynamic route (Flask path capture)"
    assert "compare_campaigns(a, b)" in srv_src
    assert 'Cannot compare a campaign with itself' in srv_src
    print("  compare route wiring: OK")


test_creation()
test_progress_bars()
test_heatmap()
test_drift_gauges()
test_risk_scoring()
test_aggregates()
test_no_findings_double_count()
test_realtime_wiring()
test_compare_campaigns()
test_compare_errors()
test_compare_route_wiring()

print("\n=== ALL CAMPAIGN DASHBOARD TESTS PASSED ===")
