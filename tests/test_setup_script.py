import subprocess
from pathlib import Path


ROOT = Path(__file__).parents[1]


def run_setup(*args):
    return subprocess.run(
        ["bash", str(ROOT / "setup.sh"), *args],
        cwd=ROOT, capture_output=True, text=True, timeout=60,
    )


def test_setup_verify_completes_successfully():
    result = run_setup("--verify")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "All verification checks passed" in result.stdout


def test_setup_installer_completes_successfully():
    result = run_setup()
    assert result.returncode == 0, result.stdout + result.stderr
    assert "INSTALLED" in result.stdout
    assert "Offline air-gap setup:" in result.stdout
    assert "Offline air-gap setup:echo" not in result.stdout
