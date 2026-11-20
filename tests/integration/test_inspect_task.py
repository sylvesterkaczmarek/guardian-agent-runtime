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
    unassigned = {"family": "file", "mode": "normal", "proposal": proposal("joint").to_dict()}
    input_path.write_text(json.dumps([fault, no_op, other_goal, unassigned]))
    log, = eval(observation_contract(str(input_path)), model="mockllm/model", log_dir=str(tmp_path / "logs"), display="none")
    assert log.status == "success"
    scores = [next(iter(s.scores.values())) for s in log.samples]
    assert [s.value for s in scores] == [1.0, 0.0, 0.0, 0.0]
    assert [s.metadata["tool_ok"] for s in scores] == [False, True, True, None]
    assert scores[-1].metadata["admitted"] is None


def test_solver_metadata_does_not_change_fixture(tmp_path):
    from inspect_ai import eval
    from inspect_ai.model import ModelOutput
    from inspect_ai.solver import solver
    from guardian_runtime.study.inspect_task import observation_contract
    from guardian_runtime.study.workflows import proposal

    @solver
    def annotate():
        async def solve(state, generate):
            state.metadata.update(family="file", mode="normal")
            state.output = ModelOutput.from_content("recorded", json.dumps(state.metadata["proposal"]))
            return state
        return solve

    path = tmp_path / "records.json"
    path.write_text(json.dumps([{"family": "file", "mode": "acknowledged_noop", "proposal": proposal("file").to_dict()}]))
    log, = eval(observation_contract(str(path)), solver=annotate(), model="mockllm/model",
                log_dir=str(tmp_path / "logs"), display="none")
    assert log.status == "success"
    score = next(iter(log.samples[0].scores.values()))
    assert score.metadata["admitted"] and score.metadata["tool_ok"]
    assert score.value == 0 and score.metadata["claims"]["completion"] is False
