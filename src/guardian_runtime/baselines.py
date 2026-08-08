from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Iterable

from guardian_runtime.types import ActionRequest, ToolResult


@dataclass(frozen=True)
class BaselineOutcome:
    allowed: bool
    reason: str
    result: ToolResult | None


class NoGuardianRunner:
    def __init__(self, environment) -> None:
        self.environment = environment

    def execute(self, request: ActionRequest) -> BaselineOutcome:
        result = self.environment.execute(request)
        return BaselineOutcome(result.ok, "no reference monitor", result)


class StaticACLRunner:
    """Conventional tool/action allowlist without capabilities, runtime state, or parameter bounds."""

    def __init__(self, environment, allowed: Iterable[tuple[str, str]]) -> None:
        self.environment = environment
        self.allowed = {(tool, action) for tool, action in allowed}

    def execute(self, request: ActionRequest) -> BaselineOutcome:
        key = (request.tool.strip().lower(), request.action.strip().lower())
        if key not in self.allowed:
            return BaselineOutcome(False, "blocked by static ACL", None)
        result = self.environment.execute(request)
        return BaselineOutcome(result.ok, "allowed by static ACL", result)


DEFAULT_ACL = {
    # Least-privilege action allowlist needed by the bundled benign workload.
    # Unlike Guardian it has no parameter, purpose, state, nonce, delegation, or
    # nested-authority semantics.
    ("mission", "observe_telemetry"),
    ("mission", "point_payload"),
    ("mission", "change_power"),
    ("mission", "maneuver"),
    ("mission", "enter_safe_mode"),
    ("mission", "schedule_activity"),
    ("sandbox", "read_file"),
    ("sandbox", "write_file"),
    ("sandbox", "network_call"),
    ("sandbox", "actuator_set"),
    ("sandbox", "proxy_call"),
}
