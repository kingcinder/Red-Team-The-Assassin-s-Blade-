"""
Behavior-parity tests for the unified report writer (core/report.py).

Candidate #4 consolidated eight hand-rolled markdown writers into ONE deep
module. These tests lock the output shape of every writer so future changes
to the report module can't silently drift from what callers expect. Each test
builds minimal realistic data and asserts the structural sections that callers
(and downstream report consumers) depend on.
"""
import os
import sys
import py_compile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.report import (
    findings_section,
    workflow_report,
    chain_report,
    parallel_report,
    combined_report,
    campaign_report,
    autonomous_report,
    report_prompt,
    autonomous_report_prompt,
)

SAMPLE_FINDINGS = [
    {
        "severity": "critical",
        "title": "SMB EternalBlue vulnerable",
        "category": "remote_code_execution",
        "source_tool": "nmap",
        "source_step": "scan",
        "evidence": "445/tcp open, ms17-010 detected",
        "context": "SMBv1 enabled on 10.0.0.5",
        "target": "10.0.0.5",
        "phase": "vuln",
        "tool": "nmap",
        "summary": "MS17-010 remote code execution",
    },
    {
        "severity": "high",
        "title": "Apache path traversal",
        "category": "web",
        "source_tool": "nikto",
        "source_step": "web_scan",
        "evidence": "CVE-2021-41773",
        "target": "10.0.0.5",
        "phase": "exploit",
        "tool": "nikto",
        "summary": "Path traversal in Apache 2.4.49",
    },
    {
        "severity": "info",
        "title": "SSH banner exposed",
        "category": "recon",
        "source_tool": "nmap",
        "source_step": "scan",
        "evidence": "OpenSSH 8.2p1",
        "target": "10.0.0.6",
        "phase": "recon",
        "tool": "nmap",
        "summary": "SSH version disclosed",
    },
]

COMPLETED_STEPS = [
    {"step": "scan", "tool": "nmap", "status": "complete", "stdout": "445/tcp open"},
    {"step": "web_scan", "tool": "nikto", "status": "complete", "stdout": "CVE-2021-41773"},
]

TOOL_LOG = [
    {"tool": "nmap", "args": "-sV 10.0.0.5"},
    {"tool": "nikto", "args": "-h http://10.0.0.5"},
]


def _check(name, fn):
    try:
        fn()
        print(f"  {name}: OK")
    except AssertionError as e:
        print(f"  {name}: FAIL — {e}")
        raise


# ═══════════════════════════════════════════════════════════════
# findings_section
# ═══════════════════════════════════════════════════════════════
def test_findings_section():
    md = findings_section(SAMPLE_FINDINGS)
    assert "Overall Risk Score:" in md, "risk score header missing"
    assert "| Severity | Count |" in md, "severity table missing"
    assert "### 🔴 CRITICAL Findings" in md, "critical section missing"
    assert "### 🟠 HIGH Findings" in md, "high section missing"
    assert "SMB EternalBlue vulnerable" in md, "finding title missing"
    assert "**Remediation**:" in md, "remediation block missing"
    assert "source_tool" not in md, "raw key leaked — key names must not appear"

    empty = findings_section([])
    assert "No findings extracted during this run." in empty


# ═══════════════════════════════════════════════════════════════
# workflow_report
# ═══════════════════════════════════════════════════════════════
def test_workflow_report():
    md = workflow_report(
        workflow="Network Recon",
        category="recon",
        attack_vector="Remote — service enumeration",
        task_id="T-1",
        status="complete",
        started="2026-01-01T00:00:00",
        finished="2026-01-01T00:05:00",
        steps_completed=2,
        total_steps=2,
        findings=SAMPLE_FINDINGS,
        completed=COMPLETED_STEPS,
        warnings=[],
        chain_values={"host": "10.0.0.5"},
        paths=[],
        narrative="Executive narrative here.",
        deep_dive="Technical deep dive here.",
    )
    assert "# Penetration Test Report — Network Recon" in md
    assert "## 1. Executive Summary" in md
    assert "Risk Score:" in md
    # No paths in this call → findings heading is ## 3 (## 4 only with paths)
    assert "## 3. Findings" in md, "findings section heading missing"
    assert "### 🔴 CRITICAL Findings" in md
    assert "## 2. Methodology / Steps Executed" in md
    assert "Executive narrative here." in md, "narrative not embedded"
    assert "Technical deep dive here." in md, "deep dive not embedded"
    assert "Steps completed" in md


# ═══════════════════════════════════════════════════════════════
# chain_report
# ═══════════════════════════════════════════════════════════════
def test_chain_report():
    md = chain_report(
        chain_id="CH-1",
        status="complete",
        links=[
            {"objective": "Enumerate hosts",
             "execution": {"workflow": "Recon", "status": "complete",
                            "completed_steps": 2, "total_steps": 2}},
            {"objective": "Exploit SMB",
             "execution": {"workflow": "Exploit", "status": "partial",
                            "completed_steps": 1, "total_steps": 2}},
        ],
        findings=SAMPLE_FINDINGS,
    )
    assert "# Chained Workflow Report — CH-1" in md
    assert "CH-1" in md
    assert "Enumerate hosts" in md and "Exploit SMB" in md
    assert "Recon" in md and "Exploit" in md
    assert "## Findings Summary" in md
    assert "**CRITICAL**: 1" in md


# ═══════════════════════════════════════════════════════════════
# parallel_report + combined_report
# ═══════════════════════════════════════════════════════════════
def _campaign_summary():
    return {
        "workflow": "recon",
        "targets": ["10.0.0.5", "10.0.0.6"],
        "started": "2026-01-01T00:00:00",
        "status": "complete",
        "risk_score": {"total": 72, "rating": "High"},
        "findings_summary": {"critical": 1, "high": 1, "info": 1},
        "pooled_findings": SAMPLE_FINDINGS,
        "correlated_paths": [{"id": "P1", "findings": ["F1"], "score": 0.9,
                              "severity": "high", "title": "SMB → RCE",
                              "confidence": 0.8, "kill_chain_progress": 0.75,
                              "attack_techniques": [{"id": "T1210", "name": "Exploit Public-Facing Application"}],
                              "remediation": ["Patch MS17-010"],
                              "finding_details": [{"severity": "critical",
                                                    "title": "SMB EternalBlue",
                                                    "source_tool": "nmap"}]}],
        "per_target": {
            "10.0.0.5": {"status": "complete", "steps_count": 2,
                          "total_steps": 2, "findings_count": 2,
                          "drift_score": 0.2},
            "10.0.0.6": {"status": "complete", "steps_count": 1,
                          "total_steps": 2, "findings_count": 1,
                          "drift_score": 0.1},
        },
        "campaign_id": "CMP-1",
        "jobs": {
            "job1": {"workflow": "recon", "targets": ["10.0.0.5"],
                     "status": "complete", "findings_count": 2},
        },
        "priority_plan": [
            {"rank": 1, "target": "10.0.0.5", "score": 92, "tier": "high",
             "aggressiveness": 1.5, "rationale": "SMB exposed"},
        ],
        "root": "/tmp",
    }


def test_parallel_report():
    md = parallel_report(_campaign_summary())
    assert "# Parallel Campaign Report — recon" in md
    assert "## 1. Workflow Jobs" in md
    assert "## 2. Executive Summary" in md
    assert "## 3. Cross-Workflow Attack Paths" in md
    assert "10.0.0.5" in md
    # Priority plan renders only in combined_report (matches old writers)
    assert "## 0. Target Priority Plan" not in md


def test_combined_report():
    md = combined_report(_campaign_summary())
    assert "# Combined Engagement Report — recon" in md
    assert "## 0. Target Priority Plan" in md
    assert "## 1. Executive Summary" in md
    assert "CMP-1" in md


# ═══════════════════════════════════════════════════════════════
# campaign_report
# ═══════════════════════════════════════════════════════════════
def test_campaign_report():
    data = {
        "id": "CMP-1",
        "name": "Night Ops",
        "workflow": "recon",
        "status": "complete",
        "created": "2026-01-01T00:00:00",
        "risk_score": 72,
        "drift_avg": 0.3,
        "per_target": {
            "10.0.0.5": {
                "status": "complete", "progress": 100, "findings_count": 2,
                "drift_score": 0.2,
                "findings_by_severity": {"critical": 1, "high": 1},
                "findings": [
                    {"severity": "critical", "title": "SMB EternalBlue",
                     "evidence": "ms17-010"},
                ],
            },
        },
    }

    def _rating(score):
        return "HIGH" if score >= 70 else "MEDIUM"

    md = campaign_report(data, _rating)
    assert "# Campaign Report — Night Ops" in md
    assert "**Risk Score**: 72/100 (HIGH)" in md, "risk rating callable not applied"
    assert "## Targets" in md
    assert "10.0.0.5" in md
    assert "## Findings by Severity" in md
    assert "CRITICAL: 1" in md
    assert "SMB EternalBlue" in md


# ═══════════════════════════════════════════════════════════════
# autonomous_report
# ═══════════════════════════════════════════════════════════════
def test_autonomous_report():
    md = autonomous_report(
        objective="Compromise the web tier",
        generated_at="2026-01-01T00:05:00",
        duration="2026-01-01T00:00:00 → 2026-01-01T00:05:00",
        state="complete",
        targets_count=2,
        total_steps=4,
        findings=SAMPLE_FINDINGS,
        target_summaries=["- **10.0.0.5**: vuln=1, exploit=1"],
        kill_chain_counts={
            "10.0.0.5": {"recon": 0, "vuln": 1, "exploit": 1, "postex": 0},
        },
    )
    assert "# Autonomous Engagement Report" in md
    assert "| Metric | Value |" in md
    assert "| Critical | 1 |" in md
    assert "## Targets" in md
    assert "10.0.0.5" in md
    assert "## Kill Chain Coverage" in md
    assert "VULN: 1 findings" in md
    # Zero-count phases must be suppressed
    assert "POSTEX: 0" not in md


# ═══════════════════════════════════════════════════════════════
# report_prompt + autonomous_report_prompt
# ═══════════════════════════════════════════════════════════════
def test_report_prompt():
    p = report_prompt(SAMPLE_FINDINGS, TOOL_LOG)
    assert "Generate a structured markdown report" in p
    assert "## Tools Executed" in p
    assert "nmap" in p
    assert "## Findings" in p
    # report_prompt preserves stored severity case (old builder did too)
    assert "[critical]" in p
    assert "[INST]" not in p  # sanitization must strip injected tags


def test_autonomous_report_prompt():
    p = autonomous_report_prompt(
        objective="Compromise the web tier",
        duration="2026-01-01T00:00:00 → 2026-01-01T00:05:00",
        targets=["10.0.0.5", "10.0.0.6"],
        target_summaries=["- **10.0.0.5**: vuln=1"],
        total_steps=4,
        findings=SAMPLE_FINDINGS,
    )
    assert "autonomous engagement" in p
    assert "## Objective" in p
    assert "Compromise the web tier" in p
    assert "## Targets (2)" in p
    assert "## Key Findings" in p
    assert "10.0.0.5" in p
    assert "[CRITICAL]" in p


# ═══════════════════════════════════════════════════════════════
# Module hygiene
# ═══════════════════════════════════════════════════════════════
def test_module_compiles():
    py_compile.compile(
        os.path.join(os.path.dirname(__file__), "..", "core", "report.py"),
        doraise=True,
    )


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in tests:
        _check(fn.__name__, fn)
    print(f"\nAll {len(tests)} report-writer tests PASSED.")
