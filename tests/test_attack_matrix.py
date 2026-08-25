#!/usr/bin/env python3
"""Functional test for the MITRE ATT&CK tactic × technique matrix heatmap
(v5.4).

Covers: build_attack_matrix structure (tactic membership, worst-severity
aggregation, evidence + attack path linking), on-the-fly technique mapping for
raw findings, empty-input handling, and dashboard endpoint wiring.
"""
import os
import sys
import py_compile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

for m in ["core/correlation.py", "dashboard/server.py"]:
    try:
        py_compile.compile(m, doraise=True)
        print(f"OK {m}")
    except py_compile.PyCompileError as e:
        print(f"FAIL {m}: {e}")
        sys.exit(1)

from core.correlation import build_attack_matrix, ATTACK_TACTICS, \
    ATTACK_TACTIC_ORDER, TECHNIQUE_NAMES


# ── Fixtures ──
def make_findings():
    """Augmented-style findings (carry attack_techniques) + one raw finding
    (no techniques — exercises on-the-fly mapping)."""
    return [
        {"title": "MS17-010 EternalBlue vulnerable", "severity": "critical",
         "dedupe_key": "ms17-010", "source_tool": "nmap_scan",
         "target": "10.0.0.1", "category": "vulnerability",
         "evidence": "MS17-010: SMBv1 enabled on 10.0.0.1",
         "attack_techniques": [{"id": "T1210", "name": "Exploitation of Remote Services"}]},
        {"title": "Open port 445/tcp (SMB)", "severity": "medium",
         "dedupe_key": "445/tcp-open", "source_tool": "nmap_scan",
         "target": "10.0.0.1", "category": "recon",
         "evidence": "445/tcp open microsoft-ds 10.0.0.1",
         "attack_techniques": [{"id": "T1046", "name": "Network Service Discovery"}]},
        # Raw finding — no attack_techniques; must map via keywords
        {"title": "SQL injection in login form", "severity": "high",
         "dedupe_key": "sqli-login", "source_tool": "sqlmap",
         "target": "10.0.0.2", "category": "vulnerability",
         "evidence": "error-based SQLi on /login"},
    ]


def make_paths():
    return [
        {"title": "EternalBlue → remote code execution", "severity": "critical",
         "score": 85, "attack_techniques": [{"id": "T1210", "name": "Exploitation of Remote Services"}],
         "finding_details": [{"severity": "critical", "title": "MS17-010", "source_tool": "nmap_scan"}]},
    ]


# ═══════════════════════════════════════════════════════════════
# 1. Structure + tactic membership
# ═══════════════════════════════════════════════════════════════
def test_matrix_structure():
    print("\n── matrix structure + tactic membership ──")
    m = build_attack_matrix(make_findings(), make_paths())
    assert m["total_findings"] == 3
    assert m["total_paths"] == 1
    assert m["total_techniques"] == 3, m["rows"]
    ids = {r["id"] for r in m["rows"]}
    assert ids == {"T1210", "T1046", "T1190"}, ids
    # Tactic columns ordered + every row has a tactic
    assert m["tactics"][0] == "Reconnaissance"
    for r in m["rows"]:
        assert r["tactic"] in m["tactics"]
    # Technique names resolved (including rule-sourced T1210 via lookup)
    by_id = {r["id"]: r for r in m["rows"]}
    assert by_id["T1210"]["name"] == "Exploitation of Remote Services"
    assert ATTACK_TACTICS["T1210"] == "Lateral Movement"
    # T1046 is MITRE-correct "Discovery" — drift fix: the old local table
    # wrongly claimed "Reconnaissance"; the KB catalogue now owns the truth.
    assert ATTACK_TACTICS["T1046"] == "Discovery"
    assert ATTACK_TACTICS["T1190"] == "Initial Access"
    # Standard 14-column order is a prefix of the returned tactic list
    assert m["tactics"][:len(ATTACK_TACTIC_ORDER)] == ATTACK_TACTIC_ORDER
    # Offline table covers every technique name the harness can emit
    assert TECHNIQUE_NAMES["T1210"] == "Exploitation of Remote Services"
    print(f"  {m['total_techniques']} techniques, {len(m['tactics'])} columns: OK")


# ═══════════════════════════════════════════════════════════════
# 2. Worst-severity aggregation per technique
# ═══════════════════════════════════════════════════════════════
def test_severity_aggregation():
    print("\n── worst-severity aggregation ──")
    findings = make_findings()
    # Add a LOW-severity finding for the same T1210 technique → worst stays critical
    findings.append({"title": "SMB signing disabled", "severity": "low",
                     "dedupe_key": "smb-signing", "source_tool": "nmap_scan",
                     "target": "10.0.0.1", "category": "config",
                     "evidence": "message signing not required",
                     "attack_techniques": [{"id": "T1210", "name": ""}]})
    m = build_attack_matrix(findings, make_paths())
    by_id = {r["id"]: r for r in m["rows"]}
    assert by_id["T1210"]["severity"] == "critical"
    assert by_id["T1210"]["severity_rank"] == 5
    assert by_id["T1210"]["findings_count"] == 2
    # Sorting: critical-severity techniques first
    assert m["rows"][0]["id"] in ("T1210", "T1190")
    print("  T1210 → critical (2 findings): OK")


# ═══════════════════════════════════════════════════════════════
# 3. Evidence + attack path linking
# ═══════════════════════════════════════════════════════════════
def test_evidence_and_paths():
    print("\n── evidence + path linking ──")
    m = build_attack_matrix(make_findings(), make_paths())
    by_id = {r["id"]: r for r in m["rows"]}
    row = by_id["T1210"]
    assert row["path_count"] == 1
    assert "EternalBlue → remote code execution" in row["paths"]
    assert row["score"] == 85
    assert any("MS17-010: SMBv1" in e for e in row["evidence"])
    assert row["sources"] == ["nmap_scan"]
    assert row["targets"] == ["10.0.0.1"]
    # Evidence is deduped + truncated
    assert len(row["evidence"]) == 1
    print("  T1210 evidence + path + score: OK")


# ═══════════════════════════════════════════════════════════════
# 4. Raw findings map on the fly; empty input is safe
# ═══════════════════════════════════════════════════════════════
def test_raw_findings_and_empty():
    print("\n── raw findings + empty input ──")
    # The SQLi finding has no attack_techniques → mapped by keyword to T1190
    m = build_attack_matrix([make_findings()[2]], [])
    by_id = {r["id"]: r for r in m["rows"]}
    assert "T1190" in by_id, by_id.keys()
    assert by_id["T1190"]["severity"] == "high"
    # Empty
    e = build_attack_matrix([], [])
    assert e["rows"] == [] and e["total_techniques"] == 0
    assert e["total_findings"] == 0 and e["total_paths"] == 0
    # Findings that map to nothing
    n = build_attack_matrix([{"title": "zzz no keywords", "severity": "low",
                              "dedupe_key": "x", "target": "t"}], [])
    assert n["rows"] == [] and n["total_findings"] == 1
    print("  T1190 from raw finding + empty handled: OK")


# ═══════════════════════════════════════════════════════════════
# 5. Dashboard wiring
# ═══════════════════════════════════════════════════════════════
def test_wiring():
    print("\n── dashboard wiring ──")
    srv = open(os.path.join(os.path.dirname(__file__), "..",
                            "dashboard", "server.py")).read()
    html = open(os.path.join(os.path.dirname(__file__), "..",
                             "dashboard", "templates", "index.html")).read()
    js = open(os.path.join(os.path.dirname(__file__), "..",
                           "dashboard", "static", "js", "cockpit.js")).read()
    assert '"/api/attack/matrix"' in srv
    assert "build_attack_matrix(findings, paths)" in srv
    assert 'task_id="|<campaign_id=' in srv or 'task_id' in srv
    assert 'data-tab="attackmatrix"' in html
    assert 'id="results-attackmatrix"' in html
    assert 'loadAttackMatrixSources()' in js
    assert 'function renderAttackMatrix()' in js
    assert 'function showAttackMatrixDetail(' in js
    print("  server + html + js wiring: OK")


test_matrix_structure()
test_severity_aggregation()
test_evidence_and_paths()
test_raw_findings_and_empty()
test_wiring()

print("\n=== ALL ATTACK MATRIX TESTS PASSED ===")
