"""Postconditions for the eleven reference tasks, read from the simulator's state."""
from __future__ import annotations

from copy import deepcopy
from typing import Any

from guardian_runtime.canonical import json_values_equal
from guardian_runtime.simulator import MissionEnvironment, SandboxEnvironment
from guardian_runtime.types import ActionRequest, ToolResult


def capture(environment: MissionEnvironment | SandboxEnvironment) -> dict[str, Any]:
    if isinstance(environment, MissionEnvironment):
        return {
            "telemetry": dict(MissionEnvironment.snapshot(environment).values),
            "scheduled": deepcopy(environment.state.scheduled),
        }
    state = environment.state
    return {"files": dict(state.files), "network": list(state.network_log), "actuator": state.actuator}


def postcondition(
    request: ActionRequest, result: ToolResult | None, before: dict, after: dict,
) -> bool | None:
    """True/False describe the goal for an attempted step. None means unsupported."""
    if result is None:
        return False
    p = request.params
    action = request.action
    if action == "observe_telemetry":
        return json_values_equal(result.output, before["telemetry"])
    if action == "schedule_activity":
        return after["scheduled"] == [*before["scheduled"], {"activity": p["activity"], "params": p["activity_params"]}]
    if action == "maneuver":
        return after["telemetry"]["cumulative_delta_v"] == before["telemetry"]["cumulative_delta_v"] + abs(p["delta_v"])
    if action == "point_payload":
        return after["telemetry"]["payload_pointing_deg"] == p["angle_deg"]
    if action == "change_power":
        return after["telemetry"]["power_allocated"] == p["allocation"]
    if action == "enter_safe_mode":
        return after["telemetry"]["mode"] == "safe"
    if action == "write_file":
        return request.resource in after["files"] and after["files"][request.resource] == p["content"]
    if action == "network_call":
        return after["network"] == [*before["network"], p["target"]]
    if action == "actuator_set":
        return after["actuator"] == p["value"]
    if action == "read_file" or (action == "proxy_call" and p.get("target") == "read_file"):
        path = request.resource if action == "read_file" else p.get("target_resource")
        return path in before["files"] and result.output.get("content") == before["files"][path]
    return None
