import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import scripts.health_check as hc


def _finding(cat, where, sev, fid="X"):
    return {"id": fid, "category": cat, "severity": sev, "what": "w",
            "where": where, "when": "t", "why": "w", "how": "h",
            "evidence": "e", "recommended_correction": "c", "status": "new"}


def test_signature_uses_category_and_where():
    assert (hc.finding_signature(_finding("a", "/x/y", "high"))
            == "a::/x/y")
    assert (hc.finding_signature(_finding("a", "/x/y/", "high"))
            == "a::/x/y")


def test_compare_detects_new_and_resolved():
    baseline = {"findings": {"a::/x": {}, "b::/y": {}}}
    current = [_finding("a", "/x", "high"), _finding("c", "/z", "low")]
    result = hc.compare(baseline, current)
    assert [i["category"] for i in result["new"]] == ["c"]
    assert result["resolved"] == ["b::/y"]


def test_compare_empty_baseline_flags_everything():
    result = hc.compare({"findings": {}}, [_finding("a", "/x", "high")])
    assert len(result["new"]) == 1


def test_fail_on_high_ignores_medium():
    # compare-level logic: medium-only new findings never trip the high bar
    result = hc.compare({"findings": {}}, [_finding("a", "/x", "medium")])
    assert len(result["new"]) == 1
    new_high = [i for i in result["new"] if hc.severity_of(i) == "high"]
    assert not new_high


def test_missing_baseline_is_empty(tmp_path, monkeypatch, capsys):
    baseline = tmp_path / "b.json"
    current = [_finding("a", "/x", "high")]

    monkeypatch.setattr(hc, "run_scan",
                        lambda j, m: (0, "DISCOVERY_COMPLETE"))
    monkeypatch.setattr(hc, "DEFAULT_BASELINE", str(baseline))
    with open(tmp_path / "scan.json", "w") as h:
        json.dump({"findings": current}, h)
    rc = hc.main(["--baseline", str(baseline),
                  "--json", str(tmp_path / "scan.json"),
                  "--md", str(tmp_path / "scan.md")])
    out = capsys.readouterr().out
    assert rc == 1  # everything is new on first run without baseline
    assert "HEALTH-ALERT" in out


def test_no_new_findings_exit_zero(tmp_path, monkeypatch, capsys):
    baseline = tmp_path / "b.json"
    current = [_finding("a", "/x", "high")]
    baseline_data = {"findings": {hc.finding_signature(i): {} for i in current}}
    with open(baseline, "w") as h:
        json.dump(baseline_data, h)

    monkeypatch.setattr(hc, "run_scan",
                        lambda j, m: (0, "DISCOVERY_COMPLETE"))
    with open(tmp_path / "scan.json", "w") as h:
        json.dump({"findings": current}, h)
    rc = hc.main(["--baseline", str(baseline),
                  "--json", str(tmp_path / "scan.json"),
                  "--md", str(tmp_path / "scan.md")])
    out = capsysread(capsys)
    assert rc == 0
    assert "HEALTH-OK" in out


def test_update_baseline_writes_file(tmp_path, monkeypatch):
    baseline = tmp_path / "b.json"
    current = [_finding("a", "/x", "high"), _finding("b", "/y", "medium")]
    monkeypatch.setattr(hc, "run_scan",
                        lambda j, m: (0, "DISCOVERY_COMPLETE"))
    with open(tmp_path / "scan.json", "w") as h:
        json.dump({"findings": current}, h)
    rc = hc.main(["--baseline", str(baseline),
                  "--json", str(tmp_path / "scan.json"),
                  "--md", str(tmp_path / "scan.md"),
                  "--update-baseline"])
    assert rc == 0
    data = json.load(open(baseline))
    assert len(data["findings"]) == 2
    assert "updated_at" in data


def test_scanner_failure_is_error_not_alert(tmp_path, monkeypatch):
    monkeypatch.setattr(hc, "run_scan", lambda j, m: (2, "boom"))
    rc = hc.main(["--baseline", str(tmp_path / "b.json"),
                  "--json", str(tmp_path / "s.json"),
                  "--md", str(tmp_path / "s.md")])
    assert rc == 2


def capsysread(capsys):
    return capsys.readouterr().out
