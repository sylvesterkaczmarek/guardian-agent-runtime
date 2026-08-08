from __future__ import annotations

import logging
import time
from collections.abc import Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from guardian_runtime.canonical import CanonicalizationError, canonicalize_request, digest_json
from guardian_runtime.capabilities import CapabilityStore
from guardian_runtime.crypto import sign_object
from guardian_runtime.evidence import EvidenceLog
from guardian_runtime.policy import PolicyEngine, PolicyRuntimeState
from guardian_runtime.telemetry import log_event
from guardian_runtime.tools import PermitError, ToolGateway
from guardian_runtime.types import ActionRequest, Decision, ExecutionPermit, ToolResult


Clock = Callable[[], int]


class GuardianRuntime:
    """Reference monitor that mediates every privileged action through a small decision kernel."""

    def __init__(
        self,
        *,
        capabilities: CapabilityStore,
        policy: PolicyEngine,
        environment,
        signing_key: Ed25519PrivateKey,
        runtime_manifest_hash: str,
        clock: Clock | None = None,
        permit_ttl_seconds: int = 5,
        logger: logging.Logger | None = None,
        mediate_nested_actions: bool = False,
    ) -> None:
        if permit_ttl_seconds <= 0:
            raise ValueError("permit_ttl_seconds must be positive")
        self.capabilities = capabilities
        self.policy = policy
        self.environment = environment
        self.signing_key = signing_key
        self.public_key = signing_key.public_key()
        self.runtime_manifest_hash = runtime_manifest_hash
        self.evidence = EvidenceLog(signing_key, runtime_manifest_hash)
        self.clock = clock or (lambda: int(time.time()))
        self.permit_ttl_seconds = permit_ttl_seconds
        self.logger = logger or logging.getLogger("guardian_runtime.runtime")
        self._permit_sequence = 0
        self._permit_requests: dict[int, ActionRequest] = {}
        self.policy_runtime = PolicyRuntimeState()
        self.gateway = ToolGateway(
            environment,
            self.public_key,
            capabilities=capabilities,
            clock=self.clock,
            policy_version=policy.version,
            runtime_manifest_hash=runtime_manifest_hash,
            on_execution=self._record_executed_action,
            mediate_nested_actions=mediate_nested_actions,
        )
        if mediate_nested_actions:
            self.gateway.set_nested_executor(self._execute_nested_request)

    def _execute_nested_request(self, request: ActionRequest) -> ToolResult:
        """Execute a tool-composition target through a fresh Guardian authorization.

        The nested request has its own capability, nonce, policy decision, permit, and
        evidence record. A denied nested action is surfaced to the outer proxy call as a
        failed tool result rather than falling back to direct execution.
        """

        decision, result = self.execute_request(request)
        if decision.allowed and result is not None and result.ok:
            return result
        return ToolResult(
            False,
            "nested-authorization-denied",
            output={"reason": decision.reason},
            state_version=self.environment.snapshot().version,
        )

    def _record_executed_action(
        self,
        request: ActionRequest,
        permit: ExecutionPermit,
        result: ToolResult,
    ) -> None:
        original_request = self._permit_requests.pop(permit.sequence, request)
        decision = Decision(
            True,
            "authorized and invariant-safe",
            rule_id=permit.rule_id,
            permit=permit,
            normalized_request=request,
        )
        self.evidence.append(
            timestamp=self.clock(),
            request=original_request,
            decision=decision,
            policy_version=permit.policy_version,
            result=result,
        )
        log_event(
            self.logger,
            "guardian.execution",
            allowed=True,
            subject=request.subject,
            session_id=request.session_id,
            tool=request.tool,
            action=request.action,
            capability_id=request.capability_id,
            rule_id=permit.rule_id,
            permit_sequence=permit.sequence,
            tool_status=result.status,
            tool_ok=result.ok,
        )

    def _record_nonexecution(self, request: ActionRequest, decision: Decision) -> None:
        self.evidence.append(
            timestamp=self.clock(),
            request=request,
            decision=decision,
            policy_version=self.policy.version,
            result=None,
        )
        log_event(
            self.logger,
            "guardian.denial",
            allowed=False,
            subject=request.subject if isinstance(request.subject, str) else "<invalid>",
            session_id=request.session_id if isinstance(request.session_id, str) else "<invalid>",
            tool=request.tool if isinstance(request.tool, str) else "<invalid>",
            action=request.action if isinstance(request.action, str) else "<invalid>",
            capability_id=request.capability_id if isinstance(request.capability_id, str) else "<invalid>",
            rule_id=decision.rule_id,
            reason=decision.reason,
        )

    def evaluate(self, request: ActionRequest) -> Decision:
        now = self.clock()
        try:
            normalized = canonicalize_request(request)
        except CanonicalizationError as exc:
            return Decision(False, f"canonicalization failed: {exc}")
        except Exception as exc:
            error_type = f"{type(exc).__module__}.{type(exc).__qualname__}"
            return Decision(False, f"canonicalization failed safely: {error_type}")

        state = self.environment.snapshot()
        capability_ok, capability_reason = self.capabilities.validate(normalized, now, consume=False)
        if not capability_ok:
            return Decision(False, capability_reason, normalized_request=normalized)

        policy_ok, policy_reason, rule_id = self.policy.evaluate(
            normalized, state, now=now, runtime=self.policy_runtime
        )
        if not policy_ok:
            return Decision(False, policy_reason, rule_id=rule_id, normalized_request=normalized)

        invariant_ok, invariant_reason = self.environment.check_invariants(normalized)
        if not invariant_ok:
            return Decision(False, invariant_reason, rule_id=rule_id, normalized_request=normalized)

        # Reserve nonce and invocation budget only after policy and invariant checks pass.
        # This prevents denied requests from exhausting a legitimate capability.
        capability_ok, capability_reason = self.capabilities.validate(normalized, now, consume=True)
        if not capability_ok:
            return Decision(False, capability_reason, rule_id=rule_id, normalized_request=normalized)

        capability = self.capabilities.get(normalized.capability_id)
        if capability is None:  # Defensive fail-closed guard after successful validation.
            return Decision(False, "capability disappeared during authorization", normalized_request=normalized)

        self.policy.record_authorization(
            rule_id, normalized, now=now, runtime=self.policy_runtime
        )

        self._permit_sequence += 1
        unsigned = {
            "request_hash": digest_json(normalized.to_dict()),
            "policy_version": self.policy.version,
            "capability_id": normalized.capability_id,
            "subject": normalized.subject,
            "session_id": normalized.session_id,
            "issued_at": now,
            "expires_at": min(now + self.permit_ttl_seconds, capability.expires_at),
            "sequence": self._permit_sequence,
            "state_version": state.version,
            "rule_id": rule_id,
            "runtime_manifest_hash": self.runtime_manifest_hash,
        }
        permit = ExecutionPermit(**unsigned, signature=sign_object(self.signing_key, unsigned))
        self._permit_requests[permit.sequence] = request
        return Decision(
            True,
            "authorized and invariant-safe",
            rule_id=rule_id,
            permit=permit,
            normalized_request=normalized,
        )

    def execute_request(self, request: ActionRequest) -> tuple[Decision, ToolResult | None]:
        decision = self.evaluate(request)
        if not decision.allowed or not decision.permit or not decision.normalized_request:
            self._record_nonexecution(request, decision)
            return decision, None

        try:
            result = self.gateway.execute(decision.normalized_request, decision.permit)
            # Successful mediated execution is recorded by the gateway observer. This also
            # means an authorized permit executed directly through the gateway still emits
            # evidence rather than silently bypassing the audit trail.
            return decision, result
        except PermitError as exc:
            self._permit_requests.pop(decision.permit.sequence, None)
            rejected = Decision(
                False,
                f"execution permit rejected: {exc}",
                rule_id=decision.rule_id,
                normalized_request=decision.normalized_request,
            )
            self._record_nonexecution(request, rejected)
            return rejected, None
