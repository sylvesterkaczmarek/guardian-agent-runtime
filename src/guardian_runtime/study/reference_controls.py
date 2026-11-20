"""Paired benign controls for the standard reference benchmark entry point."""
from __future__ import annotations

from guardian_runtime.adversarial import Scenario, benign_scenarios, run_benign_scenario
from guardian_runtime.simulator import SandboxEnvironment
from guardian_runtime.types import ActionRequest, ToolResult


class AcknowledgementOnly(SandboxEnvironment):
    def execute(self, request: ActionRequest) -> ToolResult:
        return ToolResult(True, "written", {"resource": request.resource}, self.state.version)


class ErrorAfterWrite(SandboxEnvironment):
    def execute(self, request: ActionRequest) -> ToolResult:
        super().execute(request)
        raise RuntimeError("simulated failure after commit")


def reference_outcomes() -> list[dict]:
    rows = []
    cases = benign_scenarios()
    write = next(case for case in cases if case.name == "write_tmp_file")
    trials: list[tuple[Scenario, str, SandboxEnvironment | None]] = [(case, "reference", None) for case in cases]
    trials.extend([(write, "acknowledged_noop", AcknowledgementOnly()), (write, "committed_error", ErrorAfterWrite())])
    for case, name, env in trials:
        result = run_benign_scenario("guardian_hardened", case, environment_override=env)
        rows.append({"task": case.name, "mode": name, "tool_acknowledgements": list(result.step_acknowledgements),
                     "observed_effects": list(result.step_effects), "completed": result.task_completed,
                     "verified": result.bundle_verified})
    return rows
