"""
Tests for core/task_isolation.py — the TaskSandbox seam (candidate #6).

Per-workflow sandboxed task directories: setup tree, output writes, artifact
saves, atomic state checkpointing (via StateStore), output size limits,
task listing, resume-state lookup, and cleanup.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.task_isolation import TaskSandbox


def _check(name, fn):
    try:
        fn()
        print(f"  {name}: OK")
    except AssertionError as e:
        print(f"  {name}: FAIL — {e}")
        raise


def test_setup_tree():
    base = tempfile.mkdtemp()
    sb = TaskSandbox("web_scan", base_dir=base)
    root = sb.setup()
    assert os.path.isdir(root)
    for sub in ("output", "artifacts", "logs"):
        assert os.path.isdir(os.path.join(root, sub)), f"missing {sub}/"
    assert sb.root == root


def test_output_roundtrip():
    base = tempfile.mkdtemp()
    sb = TaskSandbox("web_scan", base_dir=base)
    sb.setup()
    sb.write_output("scan", "open ports: 80,443", "warn")
    out_path = sb.get_output_path("scan")
    assert os.path.exists(out_path)
    assert sb.read_output("scan") == "open ports: 80,443"


def test_state_checkpoint_roundtrip():
    base = tempfile.mkdtemp()
    sb = TaskSandbox("web_scan", base_dir=base)
    sb.setup()
    state = {"findings": [{"title": "X"}], "current_step": 2, "status": "running"}
    sb.save_state(state)
    loaded = sb.load_state()
    assert loaded["findings"] == [{"title": "X"}]
    assert loaded["current_step"] == 2
    assert "last_updated" in loaded, "save_state must stamp last_updated"


def test_artifact_and_log():
    base = tempfile.mkdtemp()
    sb = TaskSandbox("web_scan", base_dir=base)
    sb.setup()
    sb.save_artifact("payload.bin", b"\x00\x01\x02")
    # save_artifact writes but returns None; verify via the sandbox path
    artifact = os.path.join(sb.root, "artifacts", "payload.bin")
    assert os.path.exists(artifact)
    with open(artifact, "rb") as f:
        assert f.read() == b"\x00\x01\x02"
    sb.write_log("debug", "line1")
    log_path = os.path.join(sb.root, "logs", "debug.log")
    assert os.path.exists(log_path)


def test_size_guard():
    base = tempfile.mkdtemp()
    sb = TaskSandbox("web_scan", base_dir=base)
    sb.setup()
    sb.write_output("big", "y" * 10000, "")
    assert sb.get_total_size_mb() > 0


def test_list_tasks_and_latest_state():
    base = tempfile.mkdtemp()
    for i in range(2):
        sb = TaskSandbox("recon", base_dir=base)
        sb.setup()
        sb.save_state({"status": "running", "current_step": i})
    # list_tasks is an instance method scoped to its workflow
    tasks = TaskSandbox("recon", base_dir=base).list_tasks()
    assert len(tasks) >= 2
    assert tasks[0]["task_id"].startswith("recon_")
    latest = TaskSandbox.find_latest_state("recon", base_dir=base)
    assert latest is not None
    assert latest["status"] == "running"
    assert latest["_task_id"].startswith("recon_")


def test_cleanup():
    base = tempfile.mkdtemp()
    sb = TaskSandbox("web_scan", base_dir=base)
    root = sb.setup()
    assert os.path.exists(root)
    sb.cleanup()
    assert not os.path.exists(root)


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in tests:
        _check(fn.__name__, fn)
    print(f"\nAll {len(tests)} task-isolation tests PASSED.")
