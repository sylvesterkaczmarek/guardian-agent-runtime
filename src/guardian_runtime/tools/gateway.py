from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict
from typing import Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from guardian_runtime.canonical import digest_json
from guardian_runtime.capabilities import CapabilityStore
from guardian_runtime.crypto import verify_object
from guardian_runtime.types import ActionRequest, ExecutionPermit, ToolResult


class Environment(Protocol):
    def execute(self, request: ActionRequest) -> ToolResult: ...

    def snapshot(self): ...

    def check_invariants(self, request: ActionRequest) -> tuple[bool, str]: ...


class NestedActionEnvironment(Environment, Protocol):
    def build_nested_request(self, request: ActionRequest) -> ActionRequest: ...


class PermitError(PermissionError):
    pass


ExecutionObserver = Callable[[ActionRequest, ExecutionPermit, ToolResult], None]
NestedExecutor = Callable[[ActionRequest], ToolResult]
Clock = Callable[[], int]


class ToolGateway:
    """The only mediated path from a Guardian permit to a privileged environment action."""

    def __init__(
        self,
        environment: Environment,
        guardian_public_key: Ed25519PublicKey,
        *,
        capabilities: CapabilityStore,
        clock: Clock,
        policy_version: str,
        runtime_manifest_hash: str,
        on_execution: ExecutionObserver | None = None,
        mediate_nested_actions: bool = False,
    ) -> None:
        self._environment = environment
        self._public_key = guardian_public_key
        self._capabilities = capabilities
        self._clock = clock
        self._policy_version = policy_version
        self._runtime_manifest_hash = runtime_manifest_hash
        self._on_execution = on_execution
        self._mediate_nested_actions = mediate_nested_actions
        self._nested_executor: NestedExecutor | None = None
        self._used_permits: set[str] = set()
        self._used_sequences: set[int] = set()
        self.execution_count = 0

    def set_nested_executor(self, executor: NestedExecutor) -> None:
        """Install the recursive Guardian path used for privileged tool composition."""

        self._nested_executor = executor

    def _execute_nested(self, request: ActionRequest) -> ToolResult:
        if self._nested_executor is None:
            raise PermitError("nested action mediation is enabled but no nested executor is configured")
        builder = getattr(self._environment, "build_nested_request", None)
        if not callable(builder):
            raise PermitError("environment does not expose a nested request builder")
        try:
            nested_request = builder(request)
        except (TypeError, ValueError) as exc:
            raise PermitError(f"invalid nested action request: {exc}") from exc
        return self._nested_executor(nested_request)

    def execute(self, request: ActionRequest, permit: ExecutionPermit) -> ToolResult:
        if permit.request_hash != digest_json(request.to_dict()):
            raise PermitError("permit request hash mismatch")
        payload = permit.unsigned_dict()
        if not verify_object(self._public_key, payload, permit.signature):
            raise PermitError("invalid execution permit signature")
        if permit.capability_id != request.capability_id:
            raise PermitError("permit capability mismatch")
        if permit.subject != request.subject or permit.session_id != request.session_id:
            raise PermitError("permit identity or session mismatch")
        if permit.policy_version != self._policy_version:
            raise PermitError("permit policy version mismatch")
        if permit.runtime_manifest_hash != self._runtime_manifest_hash:
            raise PermitError("permit runtime manifest mismatch")

        now = self._clock()
        if permit.issued_at > now:
            raise PermitError("permit issued in the future")
        if now >= permit.expires_at:
            raise PermitError("execution permit expired")

        permit_fingerprint = digest_json(asdict(permit))
        if permit.sequence in self._used_sequences or permit_fingerprint in self._used_permits:
            raise PermitError("execution permit replay detected")

        active, reason = self._capabilities.status(permit.capability_id, now)
        if not active:
            raise PermitError(f"capability no longer active: {reason}")
        if self._environment.snapshot().version != permit.state_version:
            raise PermitError("runtime state changed after permit issuance")
        invariant_ok, invariant_reason = self._environment.check_invariants(request)
        if not invariant_ok:
            raise PermitError(f"pre-execution invariant check failed: {invariant_reason}")

        # Burn the permit immediately before crossing the privileged boundary. If the
        # lower-level tool fails after a partial side effect, retrying the same permit is
        # still unsafe.
        self._used_sequences.add(permit.sequence)
        self._used_permits.add(permit_fingerprint)
        self.execution_count += 1
        try:
            if self._mediate_nested_actions and request.action == "proxy_call":
                nested_result = self._execute_nested(request)
                result = ToolResult(
                    nested_result.ok,
                    "proxied-mediated" if nested_result.ok else "proxy-nested-denied",
                    output={"target": request.params.get("target", ""), **dict(nested_result.output)},
                    state_version=nested_result.state_version,
                )
            else:
                result = self._environment.execute(request)
        except PermitError:
            raise
        except Exception as exc:
            # A lower-level tool can fail after a partial side effect. Convert the
            # failure into an auditable result so the privileged execution attempt
            # does not disappear from the evidence chain.
            result = ToolResult(
                False,
                "tool-error",
                output={"error_type": type(exc).__name__},
                state_version=permit.state_version,
            )
        if self._on_execution is not None:
            self._on_execution(request, permit, result)
        return result
