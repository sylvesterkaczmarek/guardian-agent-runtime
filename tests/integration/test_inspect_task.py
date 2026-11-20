"""Offline end-to-end checks when the Inspect extra is installed."""
import json

import pytest

pytest.importorskip("inspect_ai")


def test_installed_task_replays_foreign_proposals_and_scores_destination(tmp_path):
    from inspect_ai import eval
    from guardian_runtime.study.inspect_task import observation_contract
    from guardian_runtime.study.workflows import proposal

    input_path = tmp_path / "recorded.json"
    fault = {"family": "file", "mode": "committed_error", "proposal": proposal("file").to_dict()}
    no_op = {"family": "file", "mode": "acknowledged_noop", "proposal": proposal("file").to_dict()}
    other_goal = {"family": "file", "mode": "normal", "proposal": proposal("file", 3).to_dict()}
    input_path.write_text(json.dumps([fault, no_op, other_goal]))
    log, = eval(observation_contract(str(input_path)), model="mockllm/model", log_dir=str(tmp_path / "logs"), display="none")
    assert log.status == "success"
    scores = [next(iter(s.scores.values())) for s in log.samples]
    assert [s.value for s in scores] == [1.0, 0.0, 0.0]
    assert [s.metadata["tool_ok"] for s in scores] == [False, True, True]
