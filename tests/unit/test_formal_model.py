import subprocess
import sys
from pathlib import Path


def test_bounded_formal_model_invariants_hold():
    root = Path(__file__).resolve().parents[2]
    result = subprocess.run(
        [sys.executable, str(root / "formal" / "check_model.py")],
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "reachable states checked" in result.stdout
