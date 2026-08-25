#!/usr/bin/env python3
"""Test parallel workflow execution enhancements (v5.0)."""
import sys
import os
import py_compile

# Add parent dir so 'core' package resolves when run from tests/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# 1. Compile check
modules = [
    "core/task_scheduler.py",
    "core/correlation.py",
    "core/workflow_engine.py",
    "core/orchestrator.py",
    "core/campaign.py",
    "dashboard/server.py",
    # v5.7: per-domain blueprint modules (split out of server.py)
    "dashboard/blueprints/__init__.py",
    "dashboard/blueprints/core.py",
    "dashboard/blueprints/workflows.py",
    "dashboard/blueprints/campaigns.py",
    "dashboard/blueprints/msf.py",
    "dashboard/blueprints/replay.py",
    "dashboard/blueprints/memory_kb.py",
]
ok = True
for m in modules:
    try:
        py_compile.compile(m, doraise=True)
        print(f"OK {m}")
    except py_compile.PyCompileError as e:
        print(f"FAIL {m}: {e}")
        ok = False
if not ok:
    sys.exit(1)

# 2. Risk computation
from core.task_scheduler import MultiTargetScheduler
from core.correlation import FindingCorrelator

sched = MultiTargetScheduler.__new__(MultiTargetScheduler)
sched._correlator = FindingCorrelator()

counts = {"critical": 2, "high": 3, "medium": 5, "low": 1, "info": 0}
paths = [
    {"severity": "critical", "score": 10, "confidence": 0.8,
     "kill_chain_phases": ["recon", "exploitation", "actions_objectives"],
     "attack_techniques": [{"id": "T1210"}, {"id": "T1021.002"}]},
    {"severity": "high", "score": 7, "confidence": 0.6,
     "kill_chain_phases": ["exploitation"],
     "attack_techniques": [{"id": "T1190"}]},
]
risk = sched._compute_combined_risk(counts, 5, 4, paths)
print(f"\nRisk score: {risk['total']}/100 ({risk['rating']})")
print(f"Breakdown: {risk['breakdown']}")
assert 0 <= risk["total"] <= 100, f"Risk out of range: {risk['total']}"
assert risk["rating"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "MINIMAL")
print("Risk computation: OK")

# 3. Correlation integration
test_findings = [
    {"title": "Open port 445/tcp (SMB)", "severity": "medium", "category": "recon",
     "evidence": "445/tcp open microsoft-ds 192.168.1.10", "dedupe_key": "445/tcp-open",
     "source_tool": "nmap_scan", "target": "192.168.1.10"},
    {"title": "MS17-010 EternalBlue vulnerable", "severity": "critical", "category": "vulnerability",
     "evidence": "MS17-010: SMBv1 enabled", "dedupe_key": "ms17-010",
     "source_tool": "nmap_scan", "target": "192.168.1.10"},
    {"title": "Open port 445/tcp (SMB)", "severity": "medium", "category": "recon",
     "evidence": "445/tcp open microsoft-ds 192.168.1.20", "dedupe_key": "445/tcp-open",
     "source_tool": "nmap_scan", "target": "192.168.1.20"},
]
corr = FindingCorrelator()
paths = corr.correlate(test_findings)
aug = corr.augment_findings(test_findings)
print(f"\nCorrelation: {len(paths)} paths from {len(test_findings)} findings")
print(f"Augmented: {len(aug)} findings with remediation")
assert len(paths) > 0, "Should find at least 1 path"
assert all(len(f.get("remediation", [])) > 0 for f in aug), "All findings need remediation"
print("Correlation integration: OK")

# 4. Report generation test
summary = {
    "combined_id": "test_123",
    "workflow": "test.yaml",
    "targets": ["192.168.1.10", "192.168.1.20"],
    "started": "2025-01-01T00:00:00",
    "status": "complete",
    "per_target": {
        "192.168.1.10": {"status": "complete", "steps_count": 5, "total_steps": 5,
                         "findings_count": 2, "drift_score": 0.1},
        "192.168.1.20": {"status": "complete", "steps_count": 5, "total_steps": 5,
                         "findings_count": 0, "drift_score": 0.0},
    },
    "pooled_findings": test_findings,
    "augmented_findings": aug,
    "findings_summary": {"critical": 1, "high": 0, "medium": 2, "low": 0, "info": 0},
    "chain_values": {},
    "correlated_paths": paths,
    "attack_graph": paths[0].get("graph", {}) if paths else {},
    "attack_techniques": ["T1210", "T1021.002"],
    "kill_chain_phases": ["recon", "exploitation", "actions_objectives"],
    "risk_score": risk,
    "campaign_id": None,
    "root": "/tmp/test_report",
}
import os
os.makedirs("/tmp/test_report", exist_ok=True)
report_path = MultiTargetScheduler._write_combined_report(summary)
assert os.path.exists(report_path), f"Report not created: {report_path}"
with open(report_path) as f:
    report = f.read()
assert "Executive Summary" in report, "Missing Executive Summary section"
assert "Correlated Attack Paths" in report, "Missing Correlated Attack Paths"
assert "ATT&CK" in report, "Missing ATT&CK coverage"
assert "Risk Score" in report, "Missing Risk Score"
print(f"\nReport: {len(report)} chars, written to {report_path}")
print("Report generation: OK")

# 5. Verify campaign integration
from core.campaign import CampaignManager
mgr = CampaignManager()
camp = mgr.create_campaign("test", ["192.168.1.10", "192.168.1.20"], "test.yaml")
assert "id" in camp, "Campaign should have an ID"
mgr.mark_target_started(camp["id"], "192.168.1.10")
mgr.update_target(camp["id"], "192.168.1.10", {
    "status": "complete", "completed_steps": 5, "total_steps": 5,
    "findings": [{"severity": "critical", "title": "test", "source_tool": "nmap"}],
    "drift_score": 0.1,
})
mgr.mark_campaign_complete(camp["id"])
updated = mgr.get_campaign(camp["id"])
assert updated["completed_targets"] == 1, f"Expected 1 completed, got {updated['completed_targets']}"
assert updated["findings_total"] == 1, f"Expected 1 finding, got {updated['findings_total']}"
assert updated["risk_score"] > 0, "Risk should be > 0"
print(f"\nCampaign: completed={updated['completed_targets']}, findings={updated['findings_total']}, risk={updated['risk_score']}")
print("Campaign integration: OK")

print("\n=== ALL 5 TESTS PASSED ===")
