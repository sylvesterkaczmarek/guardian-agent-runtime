import json
from pathlib import Path
import subprocess
import sys

from scripts.showcase import run_showcase


def test_showcase_has_positive_and_negative_controls():
    report, _, _ = run_showcase()
    assert report["passed"] == report["total"] == 8
    assert {row["observed"] for row in report["cases"]} == {
        "EXECUTED",
        "VERIFIED",
        "DENIED",
        "BLOCKED",
        "REJECTED",
        "FAILED_AND_AUDITED",
    }


def test_showcase_does_not_overwrite_prior_evidence(tmp_path):
    existing = tmp_path / "prior.json"
    existing.write_text("preserve", encoding="utf-8")
    script = Path(__file__).resolve().parents[2] / "scripts" / "showcase.py"
    completed = subprocess.run(
        [sys.executable, str(script), "--output", str(tmp_path)], capture_output=True, text=True, timeout=10
    )
    assert completed.returncode == 2
    assert existing.read_text() == "preserve"


def test_showcase_report_is_json_serializable():
    report, bundle, _ = run_showcase()
    assert json.loads(json.dumps(report)) == report
    assert bundle["format"] == "guardian-evidence-bundle-v1"
