#!/usr/bin/env python3
"""Functional test for Parallel Multi-Workflow execution with cross-workflow
correlation (v5.3).

Covers: correlate_cross_workflow merging findings across workflow sources,
MultiTargetScheduler.run_multiple producing a unified campaign report with
cross-workflow attack paths (fake runner), the finalize_campaign guard (a
shared campaign is not finalized per-job), orchestrator + dashboard wiring.
"""
import os
import sys
import py_compile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

for m in ["core/task_scheduler.py", "core/correlation.py",
          "core/orchestrator.py", "dashboard/server.py"]:
    try:
        py_compile.compile(m, doraise=True)
        print(f"OK {m}")
    except py_compile.PyCompileError as e:
        print(f"FAIL {m}: {e}")
        sys.exit(1)

from core.correlation import FindingCorrelator
from core.campaign import CampaignManager


# ── Fakes ──
class FakeRunner:
    def execute(self, tool, args, timeout=300, **kw):
        return {"stdout": "ok", "stderr": "", "exit_code": 0,
                "duration": 0.01, "command": f"{tool} {args}"}


def make_sched():
    from core.task_scheduler import MultiTargetScheduler
    sched = MultiTargetScheduler.__new__(MultiTargetScheduler)
    sched.runner = FakeRunner()
    sched.llm = None  # __new__ bypasses __init__; run_one() reads self.llm
    sched.templates_dir = "workflows/templates"
    sched.tasks_dir = "/tmp/rt_parallel_cross"
    sched.max_concurrent = 3
    sched._emit = lambda *a, **k: None
    sched._results_lock = __import__("threading").Lock()
    sched._correlator = FindingCorrelator()
    sched._campaign_mgr = CampaignManager(tasks_dir="/tmp/rt_parallel_cross_camp")
    sched._log = lambda *a, **k: None
    sched._compute_combined_risk = lambda *a, **k: {
        "total": 42, "rating": "HIGH", "breakdown": {}}
    return sched


def ensure_templates():
    os.makedirs("workflows/templates", exist_ok=True)
    for name in ("wf_a", "wf_b"):
        path = f"workflows/templates/{name}.yaml"
        if not os.path.exists(path):
            with open(path, "w") as f:
                f.write(f"name: {name}\nsteps:\n"
                        f"  - name: ping\n    tool: nmap_scan\n"
                        f"    args: {{target: '{{{{target}}}}'}}\n")


# ═══════════════════════════════════════════════════════════════
# 1. correlate_cross_workflow merges findings from multiple workflows
# ═══════════════════════════════════════════════════════════════
def test_cross_workflow_merge():
    print("\n── correlate_cross_workflow merge ──")
    corr = FindingCorrelator()
    # Realistic findings that MATCH correlation rules. The trigger finding
    # (MS17-010) lives in workflow A while its companion (open SMB port)
    # lives in workflow B — so a path can only form by chaining ACROSS
    # workflows, which is exactly what this feature must do.
    wf1 = {"workflow_name": "net_recon", "target": "10.0.0.1",
           "findings": [{"title": "MS17-010 EternalBlue vulnerable",
                         "severity": "critical",
                         "dedupe_key": "ms17-010", "source_tool": "nmap_scan",
                         "category": "vulnerability",
                         "evidence": "MS17-010: SMBv1 enabled"}]}
    wf2 = {"workflow_name": "svc_recon", "target": "10.0.0.1",
           "findings": [{"title": "Open port 445/tcp (SMB)",
                         "severity": "medium",
                         "dedupe_key": "445/tcp-open", "source_tool": "nmap_scan",
                         "category": "recon",
                         "evidence": "445/tcp open microsoft-ds 10.0.0.1"}]}
    paths = corr.correlate_cross_workflow([wf1, wf2])
    assert len(paths) >= 1, "expected at least one cross-workflow path"
    # Every path should carry remediation + ATT&CK mapping
    for p in paths:
        assert "remediation" in p and p["remediation"], "path must have remediation"
        assert p.get("attack_techniques"), "path must have ATT&CK techniques"
    # finding_details should carry cross-workflow attribution
    details = paths[0].get("finding_details", [])
    workflows = {d.get("source_workflow") for d in details}
    assert "net_recon" in workflows or "svc_recon" in workflows, \
        f"finding_details missing source_workflow: {workflows}"
    print(f"  {len(paths)} cross-workflow paths (workflows: {workflows}): OK")


# ═══════════════════════════════════════════════════════════════
# 2. run_multiple produces a unified campaign-level report
# ═══════════════════════════════════════════════════════════════
def test_run_multiple_unified():
    print("\n── run_multiple unified campaign report ──")
    ensure_templates()
    sched = make_sched()
    # Patch the report writer so we can verify it's called with a parallel flag
    calls = {}
    orig = sched._write_parallel_report

    def spy_report(summary):
        calls["parallel"] = summary.get("parallel")
        calls["jobs"] = summary.get("jobs")
        return "/tmp/rt_parallel_cross/report.md"

    sched._write_parallel_report = staticmethod(spy_report)

    jobs = [
        {"workflow": "wf_a", "targets": ["10.0.0.1"]},
        {"workflow": "wf_b", "targets": ["10.0.0.2"]},
    ]
    result = sched.run_multiple(jobs)
    assert "error" not in result, f"run_multiple error: {result.get('error')}"
    assert result["parallel"] is True
    assert len(result["jobs"]) == 2
    assert result["status"] in ("complete", "partial", "failed")
    # All targets across both workflows present
    assert set(result["targets"]) == {"10.0.0.1", "10.0.0.2"}
    # Campaign created + marked complete (all jobs finished)
    assert result["campaign_id"] is not None
    camp = sched._campaign_mgr.get_campaign(result["campaign_id"])
    assert "error" not in camp
    assert camp["status"] in ("complete", "failed", "running")
    # The parallel report writer was invoked with the right summary
    assert calls.get("parallel") is True
    assert len(calls.get("jobs", {})) == 2
    print("  run_multiple unified: OK")


# ═══════════════════════════════════════════════════════════════
# 3. Invalid jobs / missing template are rejected fast
# ═══════════════════════════════════════════════════════════════
def test_run_multiple_validation():
    print("\n── run_multiple validation ──")
    sched = make_sched()
    assert "error" in sched.run_multiple([]), "no jobs → error"
    bad = sched.run_multiple([{"workflow": "does_not_exist_xyz",
                               "targets": ["10.0.0.1"]}])
    assert "error" in bad, "missing template → error"
    print("  validation: OK")


# ═══════════════════════════════════════════════════════════════
# 4. Orchestrator + dashboard wiring
# ═══════════════════════════════════════════════════════════════
def test_wiring():
    print("\n── orchestrator + dashboard wiring ──")
    sched_src = open(os.path.join(os.path.dirname(__file__), "..",
                                  "core", "task_scheduler.py")).read()
    orch_src = open(os.path.join(os.path.dirname(__file__), "..",
                                 "core", "orchestrator.py")).read()
    srv_src = open(os.path.join(os.path.dirname(__file__), "..",
                                "dashboard", "server.py")).read()

    # Scheduler: run_multiple + cross-workflow correlation + parallel report
    assert "def run_multiple" in sched_src
    assert "correlate_cross_workflow" in sched_src
    assert "def _write_parallel_report" in sched_src
    assert "finalize_campaign: bool = True" in sched_src, "run() needs finalize guard"
    assert "finalize_campaign=False" in sched_src, "parallel jobs must not finalize per-job"
    assert '"parallel": True' in sched_src
    assert "Parallel Campaign Report" in sched_src
    # Orchestrator exposes the entry point
    assert "def run_parallel_workflows" in orch_src
    assert "self.scheduler.run_multiple" in orch_src
    # Dashboard: REST route + SocketIO handler + event forwarding
    assert '"/api/workflows/parallel"' in srv_src
    assert "orchestrator.run_parallel_workflows(" in srv_src
    assert 'socketio.on("run_parallel_workflows")' in srv_src
    assert 'emit("parallel_started"' in srv_src
    assert 'emit("parallel_complete"' in srv_src
    print("  wiring: OK")


test_cross_workflow_merge()
test_run_multiple_unified()
test_run_multiple_validation()
test_wiring()

print("\n=== ALL PARALLEL CROSS-WORKFLOW TESTS PASSED ===")
