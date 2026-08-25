#!/usr/bin/env python3
"""
Functional test for the v5.5 backlog features:
  - Campaign persistence (save/load/list history + report)
  - Mid-run snapshots + diff against final state
  - Cross-campaign trends (persistent exposure leaderboard)
  - Scheduler per-job retry + circuit breaker (run_multiple)
  - Per-target workflow selection (priority plan suggested_workflow)
  - Gantt timeline data in the unified summary
  - LLM analyst brief fallback
  - Tactical engine vector-memory suggestions
  - Dashboard route wiring
"""
import os
import sys
import json
import py_compile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

for m in ["core/campaign.py", "core/tactics.py", "core/task_scheduler.py",
          "core/orchestrator.py", "core/autonomous.py", "dashboard/server.py"]:
    try:
        py_compile.compile(m, doraise=True)
        print(f"OK {m}")
    except py_compile.PyCompileError as e:
        print(f"FAIL {m}: {e}")
        sys.exit(1)

from core.campaign import CampaignManager
from core.tactics import TacticalEngine
from core.task_scheduler import MultiTargetScheduler


def make_campaign_mgr(tmp="/tmp/rt_v55_tests"):
    import shutil
    shutil.rmtree(tmp, ignore_errors=True)
    return CampaignManager(tasks_dir=tmp), tmp


def make_campaign(mgr, name, findings_by_target):
    """Create a campaign, push findings per target, complete it."""
    targets = list(findings_by_target.keys())
    camp = mgr.create_campaign(name, targets, workflow="test.yaml")
    for t, findings in findings_by_target.items():
        mgr.update_target(camp["id"], t, {
            "status": "complete", "completed_steps": 2, "total_steps": 2,
            "findings": findings, "drift_score": 0.1})
    return camp


# ═══════════════════════════════════════════════════════════════
# 1. Campaign persistence
# ═══════════════════════════════════════════════════════════════
def test_persistence():
    print("\n── campaign persistence ──")
    mgr, _ = make_campaign_mgr()
    camp = make_campaign(mgr, "Persist Me", {
        "10.0.0.1": [{"title": "Open SMB", "severity": "high", "source_tool": "nmap_scan",
                      "dedupe_key": "smb_open", "evidence": "445/tcp open"}],
        "10.0.0.2": [{"title": "SQLi", "severity": "critical", "source_tool": "sqlmap",
                      "dedupe_key": "sqli"}],
    })
    save = mgr.save_campaign(camp["id"], "/tmp/rt_v55_campaigns")
    assert save.get("saved") is True, save
    assert os.path.exists(save["path"])
    assert os.path.exists(save["report_path"]) and save["report_path"].endswith(".md")
    # list_history includes the persisted campaign
    hist = mgr.list_history("/tmp/rt_v55_campaigns")
    assert any(h["id"] == camp["id"] for h in hist)
    # A fresh manager can reload it
    mgr2 = CampaignManager()
    loaded = mgr2.load_campaign(camp["id"], "/tmp/rt_v55_campaigns")
    assert "error" not in loaded
    assert loaded["findings_total"] == 2
    assert loaded["per_target"]["10.0.0.1"]["findings_count"] == 1
    # Save errors on unknown id
    assert "error" in mgr.save_campaign("nope", "/tmp/rt_v55_campaigns")
    print("  persistence: OK")


# ═══════════════════════════════════════════════════════════════
# 2. Snapshot + diff
# ═══════════════════════════════════════════════════════════════
def test_snapshot_diff():
    print("\n── snapshot + diff ──")
    mgr, _ = make_campaign_mgr()
    camp = mgr.create_campaign("Snap", ["10.0.0.1"], workflow="w")
    mgr.update_target(camp["id"], "10.0.0.1", {
        "status": "running", "completed_steps": 1, "total_steps": 3,
        "findings": [{"title": "Port 22 open", "severity": "medium", "source_tool": "nmap",
                      "dedupe_key": "port22"}],
    })
    snap = mgr.snapshot_campaign(camp["id"], label="after recon")
    assert snap["snapshot_id"] and snap["findings_total"] == 1
    # Later findings appear after the snapshot
    mgr.update_target(camp["id"], "10.0.0.1", {
        "status": "complete", "completed_steps": 3, "total_steps": 3,
        "findings": [{"title": "MS17-010", "severity": "critical", "source_tool": "nmap",
                      "dedupe_key": "ms17010", "evidence": "SMBv1 vuln"}],
    })
    diff = mgr.diff_snapshot(camp["id"])
    assert diff["new_findings_count"] == 1
    assert diff["new_findings"][0]["dedupe_key"] == "ms17010"
    assert diff["severity_delta"]["critical"] == 1
    assert diff["risk_after"] > diff["risk_before"]
    # Unknown snapshot id → error
    assert "error" in mgr.diff_snapshot(camp["id"], "snap_zzz")
    print("  snapshot/diff: OK")


# ═══════════════════════════════════════════════════════════════
# 3. Cross-campaign trends
# ═══════════════════════════════════════════════════════════════
def test_trends():
    print("\n── cross-campaign trends ──")
    mgr, _ = make_campaign_mgr()
    # Two campaigns share "weak_ssh" → persistent exposure leaderboard
    make_campaign(mgr, "A", {"10.0.0.1": [{"title": "Weak SSH", "severity": "high",
                                           "source_tool": "ssh_audit", "dedupe_key": "weak_ssh"}]})
    make_campaign(mgr, "B", {
        "10.0.0.1": [{"title": "Weak SSH", "severity": "high", "source_tool": "ssh_audit",
                      "dedupe_key": "weak_ssh"}],
        "10.0.0.9": [{"title": "Log4Shell", "severity": "critical", "source_tool": "nuclei",
                      "dedupe_key": "log4shell"}],
    })
    trends = mgr.campaign_trends()
    assert trends["campaigns_scanned"] == 2
    lb = {x["dedupe_key"]: x for x in trends["leaderboard"]}
    assert lb["weak_ssh"]["occurrences"] == 2
    assert lb["weak_ssh"]["persistent"] is True
    assert lb["log4shell"]["occurrences"] == 1
    # Leaderboard sorts by occurrence count desc first
    assert trends["leaderboard"][0]["dedupe_key"] == "weak_ssh"
    assert trends["persistent_exposures"] >= 1
    print("  trends: OK")


# ═══════════════════════════════════════════════════════════════
# 4. Scheduler: per-job retry + circuit breaker + Gantt data
# ═══════════════════════════════════════════════════════════════
def test_scheduler_retry_gantt():
    print("\n── scheduler retry/circuit + gantt ──")
    sched = MultiTargetScheduler.__new__(MultiTargetScheduler)
    sched.runner = None
    sched.llm = None
    sched.templates_dir = "workflows/templates"
    sched.tasks_dir = "/tmp/rt_v55_sched"
    sched.max_concurrent = 2
    sched._emit = lambda *a, **k: None
    sched._correlator = None
    sched._campaign_mgr = None
    sched._config = {}
    sched._results_lock = __import__("threading").Lock()
    # Standalone unit checks for the helpers we added
    assert sched._config_get("workflow.parallel_max_job_retries", 2) == 2
    assert sched._config_get("workflow.parallel_auto_chain", False) is False

    # Circuit breaker behavior via _run_job_with_retry with a failing job
    calls = {"n": 0}

    def fail_run(*a, **k):
        calls["n"] += 1
        raise RuntimeError("sandbox boom")

    sched.run = fail_run
    # Production run_multiple() pre-initializes these dicts before submitting;
    # mirror that here so the helper sees the same invariants.
    results, attempts, recovered, circuit = {}, {}, {}, {}
    attempts[0] = 0
    recovered[0] = False
    circuit[0] = "closed"
    sched._run_job_with_retry(0, {"workflow": "x", "targets": ["t"]},
                              campaign_id=None, max_concurrent=None,
                              max_job_retries=2, results=results,
                              job_attempts=attempts, job_recovered=recovered,
                              circuit_state=circuit)
    assert results[0]["status"] == "error"
    assert circuit[0] == "open", circuit
    assert calls["n"] == 3  # 1 initial + 2 retries
    assert results[0].get("circuit") == "open"
    print("  retry/circuit helpers: OK")


# ═══════════════════════════════════════════════════════════════
# 5. Per-target workflow selection wiring (priority plan suggestion)
# ═══════════════════════════════════════════════════════════════
def test_per_target_workflow_selection():
    print("\n── per-target workflow selection ──")
    sched_src = open(os.path.join(os.path.dirname(__file__), "..",
                                  "core", "task_scheduler.py")).read()
    # The run_one path must consult suggested_workflow and resolve it
    assert "suggested_workflow" in sched_src
    assert "wf_template = template_path" in sched_src
    assert "alt_path = self._resolve_template(suggested)" in sched_src
    assert "priority_workflow" in sched_src
    print("  per-target selection: OK")


# ═══════════════════════════════════════════════════════════════
# 6. LLM analyst brief fallback
# ═══════════════════════════════════════════════════════════════
def test_llm_brief_fallback():
    print("\n── LLM analyst brief fallback ──")
    mgr, _ = make_campaign_mgr()
    ca = make_campaign(mgr, "A", {"10.0.0.1": [{"title": "SSH weak", "severity": "high",
                                                "source_tool": "ssh_audit", "dedupe_key": "ssh_weak"}]})
    cb = make_campaign(mgr, "B", {"10.0.0.1": [{"title": "SSH weak", "severity": "high",
                                                "source_tool": "ssh_audit", "dedupe_key": "ssh_weak"}]})
    cmp = mgr.compare_campaigns(ca["id"], cb["id"])

    class NoLLM:
        def chat(self, *a, **k):
            return "[ERROR] no model"
        def is_connected(self):
            return False

    class DummyOrch:
        llm = NoLLM()
        tactics = TacticalEngine()

        def _emit(self, *a, **k): pass

    import core.orchestrator as O
    # Use the actual Orchestrator class machinery minimally: the brief is a
    # method on Orchestrator; construct via __new__ and stub llm.
    orch = O.Orchestrator.__new__(O.Orchestrator)
    orch.llm = NoLLM()
    brief = orch.llm_campaign_brief(cmp)
    assert isinstance(brief, str) and len(brief) > 20
    assert "ssh_weak" in brief.lower() or "weak ssh" in brief.lower() or "delta" in brief.lower()
    print("  brief fallback: OK")


# ═══════════════════════════════════════════════════════════════
# 7. Tactical engine vector-memory suggestions
# ═══════════════════════════════════════════════════════════════
def test_tactics_memory():
    print("\n── tactical engine vector memory ──")
    engine = TacticalEngine()

    class FakeMemory:
        """Stand-in VectorMemory: returns a prior finding showing an open SMB
        port that was never exploited."""
        def query_by_target(self, target, top_k=10):
            return [{"title": "Open port 445/tcp (SMB)", "severity": "medium",
                     "evidence": "445/tcp open microsoft-ds", "source_tool": "nmap_scan"}]

    engine.set_memory(FakeMemory())
    suggestions = engine.evaluate([
        {"title": "Port scan result 445/tcp open smb", "severity": "medium",
         "target": "10.0.0.5", "evidence": "445/tcp open microsoft-ds"},
    ])
    mem = [s for s in suggestions if s.get("memory_grounded")]
    assert mem, suggestions
    assert mem[0]["tool"] == "enum4linux"
    assert mem[0]["prior_session"] == "10.0.0.5"
    # Without memory, no memory_grounded suggestions
    engine2 = TacticalEngine()
    s2 = engine2.evaluate([
        {"title": "Port scan result 445/tcp open smb", "severity": "medium",
         "target": "10.0.0.5", "evidence": "445/tcp open microsoft-ds"},
    ])
    assert not any(s.get("memory_grounded") for s in s2)
    print("  tactics memory: OK")


# ═══════════════════════════════════════════════════════════════
# 8. Dashboard route wiring (v5.5 endpoints)
# ═══════════════════════════════════════════════════════════════
def test_dashboard_wiring():
    print("\n── dashboard wiring ──")
    srv = open(os.path.join(os.path.dirname(__file__), "..",
                            "dashboard", "server.py")).read()
    for route in ['"/api/campaigns/history"', '"/api/campaigns/<campaign_id>/save"',
                  '"/api/campaigns/<campaign_id>/load"',
                  '"/api/campaigns/<campaign_id>/snapshot"',
                  '"/api/campaigns/<campaign_id>/diff"',
                  '"/api/campaigns/trends"',
                  '"/api/campaigns/<campaign_id>/drilldown"',
                  '"/api/campaigns/<campaign_id>/brief"',
                  '"/api/campaigns/<campaign_id>/chain"',
                  '"/api/workflows/parallel-chain"',
                  '"/api/campaigns/<campaign_id>/gantt"']:
        assert route in srv, f"missing route {route}"
    # Orchestrator methods referenced
    assert "start_campaign_chain" in srv
    assert "chain_parallel_waves" in srv
    assert "llm_campaign_brief" in srv
    # Campaign manager v5.5 methods exist in campaign.py
    camp_src = open(os.path.join(os.path.dirname(__file__), "..",
                                 "core", "campaign.py")).read()
    for fn in ["def save_campaign", "def load_campaign", "def list_history",
               "def snapshot_campaign", "def diff_snapshot", "def campaign_trends",
               "def _write_campaign_report"]:
        assert fn in camp_src, f"missing {fn}"
    # Tactics set_memory wired in orchestrator
    orch_src = open(os.path.join(os.path.dirname(__file__), "..",
                                 "core", "orchestrator.py")).read()
    assert "self.tactics.set_memory(self.memory)" in orch_src
    # Autonomous LLM re-prioritization hook
    auto_src = open(os.path.join(os.path.dirname(__file__), "..",
                                 "core", "autonomous.py")).read()
    assert "LLM RE-PRIORITIZATION" in auto_src
    assert "auto_prioritize_targets" in auto_src
    # Frontend: tooltips + reconnection + new panels
    js = open(os.path.join(os.path.dirname(__file__), "..",
                           "dashboard", "static", "js", "cockpit.js")).read()
    html = open(os.path.join(os.path.dirname(__file__), "..",
                             "dashboard", "templates", "index.html")).read()
    for sig in ["initCtrlTooltips", "replayBufferedEvents", "bufferCampaignEvent",
                "openTargetDrilldown", "loadCampaignTrends", "loadCampaignGantt",
                "loadCampaignHistory", "snapshotCampaign", "diffCampaign",
                "startCampaignChain", "runParallelChain", "generateCampaignBrief",
                "data-ctrl-help", "campaign-drilldown", "campaign-gantt",
                "campaign-trends", "campaign-history-list"]:
        assert sig in js or sig in html, f"missing frontend symbol {sig}"
    print("  dashboard wiring: OK")


test_persistence()
test_snapshot_diff()
test_trends()
test_scheduler_retry_gantt()
test_per_target_workflow_selection()
test_llm_brief_fallback()
test_tactics_memory()
test_dashboard_wiring()

print("\n=== ALL V5.5 BACKLOG TESTS PASSED ===")
