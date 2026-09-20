import os
import pathlib
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scripts.discover_system_bugs import (inspect_path, run_safe_probe,
                                          scan_repo_root_leaks,
                                          scan_repository)


def test_probe_isolation_keeps_debris_out_of_cwd(tmp_path, monkeypatch):
    """A probe that writes a relative-path file must land in scratch, not cwd."""
    monkeypatch.chdir(tmp_path)
    result = run_safe_probe(["touch", "probe_leak_test.txt"], timeout=5)
    assert result["returncode"] == 0
    assert not (tmp_path / "probe_leak_test.txt").exists()


def test_probe_isolation_redirects_home(tmp_path, monkeypatch):
    """A probe writing into $HOME must land in scratch, not the real home."""
    monkeypatch.chdir(tmp_path)
    result = run_safe_probe(
        ["sh", "-c", 'touch "$HOME/probe_home_test.txt"'], timeout=5)
    assert result["returncode"] == 0
    assert not (pathlib.Path.home() / "probe_home_test.txt").exists()


def test_probe_still_captures_output():
    result = run_safe_probe(["printf", "hello"], timeout=5)
    assert result["returncode"] == 0
    assert "hello" in result["output"]


def test_leak_detector_flags_new_empty_file(tmp_path):
    (tmp_path / "mystery").write_text("")
    findings = scan_repo_root_leaks(tmp_path, {})
    assert len(findings) == 1
    assert findings[0]["id"] == "SCAN-ROOT-LEAK-mystery"
    assert findings[0]["status"] == "inconclusive"


def test_leak_detector_ignores_known_and_nonempty(tmp_path):
    (tmp_path / "known").write_text("")
    (tmp_path / "newdata").write_text("payload")
    before = {"known": (0, 0.0)}
    findings = scan_repo_root_leaks(tmp_path, before)
    assert findings == []


def test_leak_detector_never_deletes(tmp_path):
    (tmp_path / "mystery").write_text("")
    scan_repo_root_leaks(tmp_path, {})
    assert (tmp_path / "mystery").exists()


def test_classifies_dangling_symlink(tmp_path):
    link = tmp_path / "dead"
    link.symlink_to(tmp_path / "missing")
    finding = inspect_path(link)
    assert finding["category"] == "dangling-symlink"


def test_classifies_missing_shebang_interpreter(tmp_path):
    script = tmp_path / "bad-script"
    script.write_text("#!/missing/interpreter\n")
    script.chmod(0o755)
    finding = inspect_path(script)
    assert finding["category"] == "missing-interpreter"


def test_scanner_does_not_modify_files(tmp_path):
    path = tmp_path / "x"
    path.write_text("x")
    scan_repository(path)
    assert path.read_text() == "x"
