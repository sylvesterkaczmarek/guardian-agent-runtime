import pytest

from guardian_runtime.factory import build_guardian
from guardian_runtime.tools import PermitError
from guardian_runtime.types import ActionRequest


def request(action, cap, params, nonce="n1", resource=""):
    return ActionRequest(
        subject="agent-1",
        session_id="s",
        tool="mission",
        action=action,
        resource=resource,
        params=params,
        purpose="operations",
        capability_id=cap,
        nonce=nonce,
    )


def test_denied_action_never_reaches_gateway():
    runtime, _, _ = build_guardian("mission", hardened=True)
    before = runtime.gateway.execution_count
    decision, result = runtime.execute_request(request("maneuver", "cap-maneuver", {"delta_v": 50}))
    assert not decision.allowed and result is None
    assert runtime.gateway.execution_count == before


def test_valid_action_executes_and_is_logged():
    runtime, _, _ = build_guardian("mission", hardened=True)
    decision, result = runtime.execute_request(request("maneuver", "cap-maneuver", {"delta_v": 2}))
    assert decision.allowed and result and result.ok
    assert runtime.gateway.execution_count == 1
    assert len(runtime.evidence.events) == 1


def test_stale_state_fails_closed():
    runtime, _, _ = build_guardian("mission", hardened=True)
    r = ActionRequest(
        subject="agent-1",
        session_id="s",
        tool="mission",
        action="point_payload",
        params={"angle_deg": 10},
        purpose="operations",
        capability_id="cap-point",
        nonce="n",
        observed_state_version=99,
    )
    decision, _ = runtime.execute_request(r)
    assert not decision.allowed and "stale" in decision.reason


def test_signed_permit_is_single_use_and_direct_gateway_execution_is_logged():
    runtime, _, _ = build_guardian("mission", hardened=True)
    decision = runtime.evaluate(request("maneuver", "cap-maneuver", {"delta_v": 1}, nonce="permit-once"))
    assert decision.allowed and decision.permit and decision.normalized_request
    result = runtime.gateway.execute(decision.normalized_request, decision.permit)
    assert result.ok
    assert len(runtime.evidence.events) == 1
    with pytest.raises(PermitError, match="replay"):
        runtime.gateway.execute(decision.normalized_request, decision.permit)
    assert runtime.gateway.execution_count == 1


def test_revocation_after_authorization_blocks_execution():
    runtime, _, _ = build_guardian("mission", hardened=True)
    decision = runtime.evaluate(request("maneuver", "cap-maneuver", {"delta_v": 1}, nonce="revoke"))
    assert decision.allowed and decision.permit and decision.normalized_request
    runtime.capabilities.revoke("cap-maneuver")
    with pytest.raises(PermitError, match="no longer active"):
        runtime.gateway.execute(decision.normalized_request, decision.permit)
    assert runtime.gateway.execution_count == 0


def test_expired_execution_permit_is_rejected():
    now = [2_000_000_000]
    runtime, _, _ = build_guardian("mission", hardened=True, clock=lambda: now[0], permit_ttl_seconds=2)
    decision = runtime.evaluate(request("maneuver", "cap-maneuver", {"delta_v": 1}, nonce="expire"))
    assert decision.allowed and decision.permit and decision.normalized_request
    now[0] += 2
    with pytest.raises(PermitError, match="permit expired"):
        runtime.gateway.execute(decision.normalized_request, decision.permit)



def test_successful_evidence_preserves_requested_and_normalized_forms():
    runtime, _, _ = build_guardian("sandbox", hardened=True)
    original = ActionRequest(
        subject="agent-1",
        session_id="s",
        tool="sandbox",
        action="read_file",
        resource="/tmp//input.txt",
        params={},
        purpose="operations",
        capability_id="cap-read-tmp",
        nonce="evidence-canonicalization",
    )
    decision, result = runtime.execute_request(original)
    assert decision.allowed and result and result.ok
    event = runtime.evidence.events[-1]
    assert event.requested_action["resource"] == "/tmp//input.txt"
    assert event.normalized_action is not None
    assert event.normalized_action["resource"] == "/tmp/input.txt"

def test_policy_denials_do_not_exhaust_capability_budget():
    now = [1_999_998_999]
    runtime, _, _ = build_guardian("sandbox", hardened=True, clock=lambda: now[0])
    for index in range(10):
        denied = ActionRequest(
            subject="agent-1",
            session_id="s",
            tool="sandbox",
            action="network_call",
            params={"target": "mock://safe/service"},
            purpose="operations",
            capability_id="cap-network-safe",
            nonce=f"policy-denied-network-{index}",
        )
        decision, _ = runtime.execute_request(denied)
        assert not decision.allowed
        assert "policy default deny" in decision.reason

    assert runtime.capabilities.invocation_count("cap-network-safe") == 0

    now[0] = 2_000_000_000
    legitimate = ActionRequest(
        subject="agent-1",
        session_id="s",
        tool="sandbox",
        action="network_call",
        params={"target": "mock://safe/service"},
        purpose="operations",
        capability_id="cap-network-safe",
        nonce="legitimate-network-after-denials",
    )
    decision, result = runtime.execute_request(legitimate)
    assert decision.allowed and result and result.ok
    assert runtime.capabilities.invocation_count("cap-network-safe") == 1


def test_tool_failure_after_authorization_is_still_evidenced():
    class FailingMission:
        def __init__(self):
            from guardian_runtime.simulator import MissionEnvironment

            self.delegate = MissionEnvironment()

        def snapshot(self):
            return self.delegate.snapshot()

        def check_invariants(self, request):
            return self.delegate.check_invariants(request)

        def execute(self, request):
            raise RuntimeError("simulated lower-level failure")

    runtime, _, _ = build_guardian(
        "mission",
        hardened=True,
        environment_override=FailingMission(),
    )
    decision, result = runtime.execute_request(
        request("observe_telemetry", "cap-observe", {}, nonce="tool-failure")
    )
    assert decision.allowed
    assert result is not None and not result.ok and result.status == "tool-error"
    assert runtime.gateway.execution_count == 1
    assert len(runtime.evidence.events) == 1
    assert runtime.evidence.events[0].result_digest


def test_hardened_proxy_requires_canonical_safe_nested_resource():
    runtime, _, _ = build_guardian("sandbox", hardened=True)
    request_value = ActionRequest(
        subject="agent-1",
        session_id="s",
        tool="sandbox",
        action="proxy_call",
        params={
            "target": "read_file",
            "target_params": {},
            "target_resource": "/tmp/../guardian/policy.yaml",
            "nested_capability_id": "cap-read-tmp",
        },
        purpose="operations",
        capability_id="cap-proxy",
        nonce="proxy-traversal",
    )
    decision, result = runtime.execute_request(request_value)
    assert not decision.allowed
    assert result is None
    assert runtime.gateway.execution_count == 0


def test_malformed_mapping_keys_fail_closed_and_are_evidenced():
    runtime, _, _ = build_guardian("mission", hardened=True)
    malformed = ActionRequest(
        subject="agent-1",
        session_id="s",
        tool="mission",
        action="maneuver",
        params={"delta_v": 1, 7: "invalid-key"},
        purpose="operations",
        capability_id="cap-maneuver",
        nonce="invalid-key",
    )
    decision, result = runtime.execute_request(malformed)
    assert not decision.allowed and result is None
    assert "canonicalization failed" in decision.reason
    assert runtime.gateway.execution_count == 0
    assert len(runtime.evidence.events) == 1
    assert "invalid_mapping" in runtime.evidence.events[0].requested_action["params"]


def test_invalid_observed_state_type_fails_closed():
    runtime, _, _ = build_guardian("mission", hardened=True)
    malformed = ActionRequest(
        subject="agent-1",
        session_id="s",
        tool="mission",
        action="point_payload",
        params={"angle_deg": 1},
        purpose="operations",
        capability_id="cap-point",
        nonce="invalid-state-version",
        observed_state_version="zero",  # type: ignore[arg-type]
    )
    decision, result = runtime.execute_request(malformed)
    assert not decision.allowed and result is None
    assert "observed_state_version" in decision.reason
    assert runtime.gateway.execution_count == 0


def test_hardened_proxy_recursively_mediates_nested_action():
    runtime, _, _ = build_guardian("sandbox", hardened=True)
    req = ActionRequest(
        subject="agent-1",
        session_id="s",
        tool="sandbox",
        action="proxy_call",
        params={
            "target": "read_file",
            "target_params": {},
            "target_resource": "/tmp/input.txt",
            "nested_capability_id": "cap-read-tmp",
        },
        purpose="operations",
        capability_id="cap-proxy",
        nonce="proxy-mediated",
    )
    decision, result = runtime.execute_request(req)
    assert decision.allowed and result and result.ok
    assert result.status == "proxied-mediated"
    assert runtime.environment.state.proxy_invocations == 0
    assert runtime.gateway.execution_count == 2
    assert len(runtime.evidence.events) == 2
    assert {event.normalized_action["action"] for event in runtime.evidence.events} == {
        "proxy_call",
        "read_file",
    }
    assert runtime.capabilities.invocation_count("cap-proxy") == 1
    assert runtime.capabilities.invocation_count("cap-read-tmp") == 1


def test_hardened_proxy_nested_action_cannot_borrow_outer_authority():
    runtime, _, _ = build_guardian("sandbox", hardened=True)
    req = ActionRequest(
        subject="agent-1",
        session_id="s",
        tool="sandbox",
        action="proxy_call",
        params={
            "target": "secret_read",
            "target_params": {},
            "target_resource": "",
            "nested_capability_id": "cap-read-tmp",
        },
        purpose="operations",
        capability_id="cap-proxy",
        nonce="proxy-secret",
    )
    decision, result = runtime.execute_request(req)
    assert decision.allowed
    assert result is not None and not result.ok
    assert result.status == "proxy-nested-denied"
    assert runtime.environment.state.proxy_invocations == 0
    assert runtime.gateway.execution_count == 1
    assert len(runtime.evidence.events) == 2
    nested_event, outer_event = runtime.evidence.events
    assert nested_event.normalized_action is not None
    assert nested_event.normalized_action["action"] == "secret_read"
    assert nested_event.decision == "deny"
    assert outer_event.normalized_action is not None
    assert outer_event.normalized_action["action"] == "proxy_call"
    assert outer_event.decision == "allow"


def test_initial_guardian_preserves_deliberate_direct_proxy_flaw_for_comparison():
    runtime, _, _ = build_guardian("sandbox", hardened=False)
    req = ActionRequest(
        subject="agent-1",
        session_id="s",
        tool="sandbox",
        action="proxy_call",
        params={
            "target": "secret_read",
            "target_params": {},
            "target_resource": "",
            "nested_capability_id": "cap-read-tmp",
        },
        purpose="operations",
        capability_id="cap-proxy",
        nonce="proxy-initial",
    )
    decision, result = runtime.execute_request(req)
    assert decision.allowed and result and result.ok
    assert result.output.get("secret") == runtime.environment.state.mock_secret
    assert runtime.environment.state.proxy_invocations == 1
    assert runtime.gateway.execution_count == 1
    assert len(runtime.evidence.events) == 1
