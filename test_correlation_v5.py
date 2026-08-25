#!/usr/bin/env python3
"""Functional test for the enhanced Finding Correlation Engine v5.0."""
import sys
import py_compile

# 1. Compile check
for m in ["core/correlation.py", "core/workflow_engine.py"]:
    try:
        py_compile.compile(m, doraise=True)
        print(f"OK {m}")
    except py_compile.PyCompileError as e:
        print(f"FAIL {m}: {e}")
        sys.exit(1)

from core.correlation import FindingCorrelator

corr = FindingCorrelator()

# 2. Test correlate() with realistic mixed findings
test_findings = [
    {"title": "Open port 445/tcp (SMB)", "severity": "medium", "category": "recon",
     "evidence": "445/tcp open microsoft-ds 192.168.1.10", "dedupe_key": "445/tcp-open", "source_tool": "nmap_scan"},
    {"title": "MS17-010 EternalBlue vulnerable", "severity": "critical", "category": "vulnerability",
     "evidence": "MS17-010: SMBv1 enabled on 192.168.1.10", "dedupe_key": "ms17-010", "source_tool": "nmap_scan"},
    {"title": "Anonymous SMB login allowed", "severity": "high", "category": "misconfig",
     "evidence": "SMB anonymous login on 192.168.1.10", "dedupe_key": "smb-anon", "source_tool": "enum4linux"},
    {"title": "SSH weak cipher", "severity": "medium", "category": "vulnerability",
     "evidence": "SSH on 192.168.1.20: diffie-hellman-group1-sha1", "dedupe_key": "ssh-weak", "source_tool": "nmap_scan"},
    {"title": "SQL injection in login", "severity": "critical", "category": "vulnerability",
     "evidence": "sql injection found in /login endpoint", "dedupe_key": "sqli-login", "source_tool": "sqlmap"},
]

paths = corr.correlate(test_findings)
print(f"\nCorrelated paths: {len(paths)}")
for p in paths:
    print(f"  [{p['severity'].upper()}] {p['title']}")
    print(f"    score={p['score']}, confidence={p['confidence']}, kill_chain_progress={p['kill_chain_progress']}")
    tech_ids = [t["id"] for t in p.get("attack_techniques", [])[:5]]
    print(f"    ATT&CK: {tech_ids}")
    print(f"    Findings: {p['findings'][:5]}")
    print(f"    Remediation steps: {len(p['remediation'])}")
    graph = p.get("graph", {})
    print(f"    Graph: {graph.get('metadata', {}).get('total_nodes', 0)} nodes, {graph.get('metadata', {}).get('total_edges', 0)} edges")
    print()

# 3. Test summary_to_markdown
summary = corr.summary_to_markdown(paths, test_findings)
print(f"Summary length: {len(summary)} chars")
assert len(summary) > 100, "Summary should be substantial"
assert "Total Findings" in summary, "Summary should contain finding count"
assert "Correlated Attack Paths" in summary, "Summary should contain path count"
print("summary_to_markdown: OK")

# 4. Test augment_findings
aug = corr.augment_findings(test_findings)
for f in aug:
    techs = [t["id"] for t in f.get("attack_techniques", [])]
    rem = f.get("remediation", [])
    print(f"  Augmented: {f['title']} -- techs={techs[:2]}, remediation={len(rem)} steps")
    assert len(rem) > 0, "Every finding should have remediation"
print("augment_findings: OK")

# 5. Test cross-workflow correlation
wf1 = {"workflow_name": "recon", "target": "192.168.1.10", "findings": test_findings[:3]}
wf2 = {"workflow_name": "exploit", "target": "192.168.1.10", "findings": test_findings[3:]}
cross_paths = corr.correlate_cross_workflow([wf1, wf2])
print(f"\nCross-workflow paths: {len(cross_paths)}")
for p in cross_paths:
    print(f"  [{p['severity'].upper()}] {p['title']} -- score={p['score']}")
print("correlate_cross_workflow: OK")

# 6. Test remediation_for
for f in test_findings:
    rem = corr.remediation_for(f)
    assert len(rem) > 0, f"remediation_for({f['title']}) returned empty"
print("remediation_for: OK")

# 7. Test paths_to_markdown
md = corr.paths_to_markdown(paths)
assert "Correlated Attack Paths" in md, "paths_to_markdown should contain header"
assert "REMEDIATION" in md.upper() or "Remediation" in md, "Should contain remediation"
print(f"paths_to_markdown: OK ({len(md)} chars)")

# 8. Verify kill chain progress
for p in paths:
    kcp = p.get("kill_chain_progress", 0)
    assert 0.0 <= kcp <= 1.0, f"kill_chain_progress out of range: {kcp}"
print("kill_chain_progress ranges: OK")

# 9. Verify confidence scores
for p in paths:
    conf = p.get("confidence", 0)
    assert 0.0 <= conf <= 1.0, f"confidence out of range: {conf}"
print("confidence ranges: OK")

# 10. Verify ATT&CK techniques are non-empty for critical paths
crit_paths = [p for p in paths if p["severity"] == "critical"]
for p in crit_paths:
    assert len(p.get("attack_techniques", [])) > 0, f"Critical path missing ATT&CK techniques: {p['title']}"
print("ATT&CK techniques on critical paths: OK")

print("\n=== ALL 10 TESTS PASSED ===")
