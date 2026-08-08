from __future__ import annotations

from dataclasses import dataclass, field
from collections.abc import Mapping

from guardian_runtime.canonical import CanonicalizationError, canonicalize_resource
from guardian_runtime.types import ActionRequest, RuntimeState, ToolResult


@dataclass
class SandboxState:
    version: int = 0
    files: dict[str, str] = field(default_factory=lambda: {"/tmp/input.txt": "safe input"})
    mock_secret: str = "MOCK-SECRET-NOT-A-REAL-CREDENTIAL"
    actuator: int = 0
    network_log: list[str] = field(default_factory=list)
    proxy_invocations: int = 0


class SandboxEnvironment:
    """Domain-neutral local sandbox with an intentionally unsafe direct proxy path.

    No-Guardian, static-ACL, and deliberately incomplete Guardian experiments can call
    ``execute(proxy_call)`` directly to reproduce a confused-deputy flaw. The hardened
    Guardian never takes that path: its gateway calls ``build_nested_request`` and sends
    the resulting privileged action back through Guardian authorization.
    """

    def __init__(self) -> None:
        self.state = SandboxState()

    def snapshot(self) -> RuntimeState:
        return RuntimeState(
            version=self.state.version,
            values={
                "actuator": self.state.actuator,
                "network_calls": len(self.state.network_log),
                "proxy_invocations": self.state.proxy_invocations,
            },
        )

    def _bump(self) -> int:
        self.state.version += 1
        return self.state.version

    def check_invariants(self, request: ActionRequest) -> tuple[bool, str]:
        if request.observed_state_version is not None and request.observed_state_version != self.state.version:
            return False, "stale observed state"
        if request.action == "actuator_set":
            value = request.params.get("value")
            if not isinstance(value, int) or not -10 <= value <= 10:
                return False, "actuator command outside hard envelope"
        if request.action == "network_call":
            target = request.params.get("target", "")
            if not isinstance(target, str) or not target.startswith("mock://"):
                return False, "external networking is disabled"
        return True, "sandbox invariants satisfied"

    def build_nested_request(self, request: ActionRequest) -> ActionRequest:
        """Decode a proxy request into a separately authorized nested action."""

        p = dict(request.params)
        target = p.get("target")
        nested_capability_id = p.get("nested_capability_id")
        target_params = p.get("target_params")
        target_resource = p.get("target_resource")
        if not isinstance(target, str) or not target:
            raise ValueError("proxy target must be a non-empty string")
        if not isinstance(nested_capability_id, str) or not nested_capability_id:
            raise ValueError("proxy requires nested_capability_id")
        if not isinstance(target_params, Mapping):
            raise ValueError("proxy target_params must be a mapping")
        if not isinstance(target_resource, str):
            raise ValueError("proxy target_resource must be a string")
        try:
            canonical_resource = canonicalize_resource(target_resource)
        except CanonicalizationError as exc:
            raise ValueError(f"invalid proxy target_resource: {exc}") from exc

        return ActionRequest(
            subject=request.subject,
            session_id=request.session_id,
            tool="sandbox",
            action=target,
            resource=canonical_resource,
            params=dict(target_params),
            purpose=request.purpose,
            capability_id=nested_capability_id,
            nonce=request.nonce + "-nested",
            observed_state_version=request.observed_state_version,
            context={"mediated_by": "proxy_call"},
        )

    def execute(self, request: ActionRequest) -> ToolResult:
        action = request.action.strip().lower()
        p = dict(request.params)
        if action == "read_file":
            value = self.state.files.get(request.resource, "")
            return ToolResult(True, "read", output={"content": value}, state_version=self.state.version)
        if action == "write_file":
            self.state.files[request.resource] = str(p.get("content", ""))
            return ToolResult(True, "written", output={"resource": request.resource}, state_version=self._bump())
        if action == "secret_read":
            return ToolResult(True, "secret", output={"secret": self.state.mock_secret}, state_version=self.state.version)
        if action == "network_call":
            target = str(p.get("target", ""))
            self.state.network_log.append(target)
            return ToolResult(True, "network-mocked", output={"target": target}, state_version=self._bump())
        if action == "actuator_set":
            self.state.actuator = int(p.get("value", 0))
            return ToolResult(True, "actuator-set", output={"value": self.state.actuator}, state_version=self._bump())
        if action == "proxy_call":
            # Deliberate confused-deputy flaw used only by the non-recursive comparison
            # architectures. The hardened Guardian intercepts proxy_call in ToolGateway
            # and never reaches this direct nested-execution branch.
            self.state.proxy_invocations += 1
            self._bump()
            try:
                nested = self.build_nested_request(request)
            except ValueError:
                # The deliberately weak path predates explicit nested capabilities. For
                # the initial experiment, preserve that weakness by reconstructing the
                # nested request with the outer capability when the field is absent.
                target = str(p.get("target", ""))
                target_params = p.get("target_params", {})
                try:
                    target_resource = canonicalize_resource(str(p.get("target_resource", "")))
                except CanonicalizationError:
                    return ToolResult(
                        False,
                        "proxy-invalid-resource",
                        output={"target": target},
                        state_version=self.state.version,
                    )
                nested = ActionRequest(
                    subject=request.subject,
                    session_id=request.session_id,
                    tool="sandbox",
                    action=target,
                    resource=target_resource,
                    params=target_params if isinstance(target_params, Mapping) else {},
                    purpose=request.purpose,
                    capability_id=request.capability_id,
                    nonce=request.nonce + "-nested",
                )
            result = self.execute(nested)
            return ToolResult(
                result.ok,
                "proxied",
                output={"target": nested.action, **dict(result.output)},
                state_version=result.state_version,
            )
        return ToolResult(False, "unknown action", output={"action": action}, state_version=self.state.version)
