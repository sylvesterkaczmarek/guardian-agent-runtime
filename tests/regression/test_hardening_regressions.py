import json
from pathlib import Path

from guardian_runtime.adversarial import Scenario, run_attack_scenario
from guardian_runtime.types import ActionRequest


ROOT = Path(__file__).resolve().parents[2]


def _scenario_from_dict(payload):
    return Scenario(
        name=payload["name"],
        domain=payload["domain"],
        mode=payload["mode"],
        scenario_class=payload.get("scenario_class", "compromised"),
        notes=payload.get("notes", ""),
        max_allowed=payload.get("max_allowed"),
        requests=tuple(ActionRequest(**request) for request in payload["requests"]),
    )


def test_checked_generated_regressions_are_executable_and_blocked():
    payload = json.loads((ROOT / "results" / "generated_regressions.json").read_text(encoding="utf-8"))
    cases = [_scenario_from_dict(item) for item in payload["regression_cases"]]
    assert len(cases) >= 4
    for case in cases:
        assert not run_attack_scenario("guardian_hardened", case).attack_success
