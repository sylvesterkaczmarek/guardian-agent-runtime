from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Barrier, BrokenBarrierError, Event

import pytest

from guardian_runtime.evidence import verify_evidence_bundle
from guardian_runtime.factory import build_guardian
from guardian_runtime.simulator import MissionEnvironment, SandboxEnvironment
from guardian_runtime.tools import PermitError
from guardian_runtime.types import ActionRequest


def sandbox_request(action="read_file", capability="cap-read-tmp", **kwargs):
    return ActionRequest(
        subject="agent-1",
        session_id="s",
        tool="sandbox",
        action=action,
        resource="/tmp/input.txt",
        purpose="operations",
        capability_id=capability,
        nonce="execution-integrity",
        **kwargs,
    )


def assert_valid_evidence(runtime):
    assert verify_evidence_bundle(
        runtime.evidence.export_bundle(policy_version=runtime.policy.version),
        runtime.public_key,
        expected_policy_version=runtime.policy.version,
        expected_manifest_hash=runtime.runtime_manifest_hash,
    ) == (True, "evidence bundle valid")


def rendezvous_if_concurrent(barrier):
    # An unlocked implementation lets both callers pass the decision before either
    # commits. A serial implementation safely times out the first rendezvous.
    try:
        barrier.wait(timeout=0.3)
    except BrokenBarrierError:
        pass


def test_concurrent_replay_executes_one_time(monkeypatch):
    runtime, _, _ = build_guardian("sandbox", hardened=True)
    decision = runtime.evaluate(sandbox_request())
    assert decision.permit is not None and decision.normalized_request is not None
    original_check = runtime.environment.check_invariants
    barrier = Barrier(2)

    def pause_after_checks(request):
        checked = original_check(request)
        rendezvous_if_concurrent(barrier)
        return checked

    monkeypatch.setattr(runtime.environment, "check_invariants", pause_after_checks)

    def execute():
        try:
            return runtime.gateway.execute(decision.normalized_request, decision.permit).status
        except PermitError as exc:
            return str(exc)

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(execute) for _ in range(2)]
        results = [future.result(timeout=5) for future in futures]

    assert results.count("read") == 1
    assert sum("replay" in result for result in results) == 1
    assert runtime.gateway.execution_count == 1
    assert len(runtime.evidence.events) == 1
    assert_valid_evidence(runtime)


def test_concurrent_authorization_cannot_overbook_rate_limit(monkeypatch):
    runtime, _, _ = build_guardian("sandbox", hardened=True)
    request = sandbox_request(
        "network_call", "cap-network-safe", params={"target": "mock://safe/service"}
    )
    for index in range(4):
        assert runtime.evaluate(replace(request, nonce=f"reserved-{index}")).allowed

    original_evaluate = runtime.policy.evaluate
    barrier = Barrier(2)

    def pause_after_policy(*args, **kwargs):
        checked = original_evaluate(*args, **kwargs)
        rendezvous_if_concurrent(barrier)
        return checked

    monkeypatch.setattr(runtime.policy, "evaluate", pause_after_policy)
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(runtime.evaluate, replace(request, nonce=f"racing-{i}")) for i in range(2)]
        decisions = [future.result(timeout=5) for future in futures]

    assert sum(decision.allowed for decision in decisions) == 1
    assert runtime.capabilities.invocation_count("cap-network-safe") == 5


def test_caller_mutation_after_hash_check_cannot_change_execution(monkeypatch):
    runtime, _, _ = build_guardian("sandbox", hardened=True)
    decision = runtime.evaluate(sandbox_request("actuator_set", "cap-actuator", params={"value": 1}))
    assert decision.permit is not None and decision.normalized_request is not None
    checked = Event()
    mutated = Event()
    original_check = runtime.environment.check_invariants

    def pause_after_checks(request):
        result = original_check(request)
        checked.set()
        assert mutated.wait(timeout=5)
        return result

    monkeypatch.setattr(runtime.environment, "check_invariants", pause_after_checks)
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(runtime.gateway.execute, decision.normalized_request, decision.permit)
        assert checked.wait(timeout=5)
        decision.normalized_request.params["value"] = 999
        mutated.set()
        result = future.result(timeout=5)

    assert result.ok
    assert runtime.environment.state.actuator == 1
    event = runtime.evidence.events[0]
    assert event.normalized_action["params"]["value"] == 1
    assert event.requested_action["params"]["value"] == 1
    assert_valid_evidence(runtime)


def test_original_request_evidence_is_captured_when_authorized():
    runtime, _, _ = build_guardian("sandbox", hardened=True)
    params = {"content": "authorised content"}
    request = replace(
        sandbox_request("write_file", "cap-write-tmp", params=params), resource="/tmp//input.txt"
    )
    decision = runtime.evaluate(request)
    params["content"] = "changed after authorization"
    runtime.gateway.execute(decision.normalized_request, decision.permit)

    event = runtime.evidence.events[0]
    assert event.requested_action["params"]["content"] == "authorised content"
    assert event.requested_action["resource"] == "/tmp//input.txt"
    assert runtime.environment.state.files["/tmp/input.txt"] == "authorised content"
    assert_valid_evidence(runtime)


def test_tool_permission_exception_after_side_effect_is_audited(monkeypatch):
    runtime, _, _ = build_guardian("sandbox", hardened=True)

    def partial_failure(request):
        runtime.environment.state.actuator = 1
        runtime.environment.state.version += 1
        raise PermitError("tool failed after writing")

    monkeypatch.setattr(runtime.environment, "execute", partial_failure)
    decision, result = runtime.execute_request(sandbox_request())

    assert decision.allowed
    assert result is not None and not result.ok and result.status == "tool-error"
    assert result.state_version == 1
    assert runtime.gateway.execution_count == 1
    assert len(runtime.evidence.events) == 1
    assert runtime.evidence.events[0].decision == "allow"
    assert runtime._permit_requests == {}
    assert_valid_evidence(runtime)


@pytest.mark.parametrize("exception", [KeyboardInterrupt, SystemExit])
def test_tool_interruption_is_evidenced_and_propagated(monkeypatch, exception):
    runtime, _, _ = build_guardian("sandbox", hardened=True)
    request = sandbox_request()
    decision = runtime.evaluate(request)

    def interrupted(request):
        runtime.environment.state.version += 1
        raise exception()

    monkeypatch.setattr(runtime.environment, "execute", interrupted)
    with pytest.raises(exception):
        runtime.gateway.execute(decision.normalized_request, decision.permit)

    assert runtime.gateway.execution_count == 1
    assert len(runtime.evidence.events) == 1
    assert runtime.evidence.events[0].decision == "allow"
    assert runtime._permit_requests == {}
    assert_valid_evidence(runtime)
    with pytest.raises(PermitError, match="replay"):
        runtime.gateway.execute(decision.normalized_request, decision.permit)


def test_nested_tool_failure_is_not_reported_as_authorization_denial(monkeypatch):
    runtime, _, _ = build_guardian("sandbox", hardened=True)

    def fail(request):
        raise OSError("read failed")

    monkeypatch.setattr(runtime.environment, "execute", fail)
    request = sandbox_request("proxy_call", "cap-proxy", params={
        "target": "read_file",
        "target_params": {},
        "target_resource": "/tmp/input.txt",
        "nested_capability_id": "cap-read-tmp",
    })
    decision, result = runtime.execute_request(request)

    assert decision.allowed and result is not None and not result.ok
    assert result.status == "proxy-nested-failed"
    assert result.output["error_type"] == "OSError"
    assert runtime.gateway.execution_count == 2
    assert len(runtime.evidence.events) == 2
    assert_valid_evidence(runtime)


@pytest.mark.parametrize("delta_v", [True, 10**400, -(10**400)], ids=["boolean", "huge-positive", "huge-negative"])
def test_malformed_scheduled_maneuver_is_denied_and_evidenced(delta_v):
    runtime, _, _ = build_guardian("mission", hardened=True)
    request = ActionRequest(
        subject="agent-1", session_id="s", tool="mission", action="schedule_activity",
        params={"activity": "maneuver", "activity_params": {"delta_v": delta_v}},
        purpose="operations", capability_id="cap-schedule", nonce="invalid-schedule",
    )

    decision, result = runtime.execute_request(request)

    assert not decision.allowed and result is None
    assert runtime.environment.state.scheduled == []
    assert runtime.gateway.execution_count == 0
    assert len(runtime.evidence.events) == 1
    assert_valid_evidence(runtime)


@pytest.mark.parametrize("action, parameter", [
    ("maneuver", "delta_v"), ("point_payload", "angle_deg"), ("change_power", "allocation"),
])
@pytest.mark.parametrize("value", [True, float("nan"), float("inf"), 10**400], ids=["boolean", "nan", "infinity", "huge"])
def test_mission_numeric_invariants_reject_invalid_values_without_overflow(action, parameter, value):
    request = replace(sandbox_request(), tool="mission", action=action, params={parameter: value})
    assert MissionEnvironment().check_invariants(request)[0] is False


def test_actuator_invariant_rejects_boolean():
    request = sandbox_request("actuator_set", "cap-actuator", params={"value": True})
    assert SandboxEnvironment().check_invariants(request)[0] is False


@pytest.mark.parametrize("ttl", [True, False, 0, -1, 0.5, float("nan"), float("inf"), "5"])
def test_invalid_permit_lifetime_is_rejected(ttl):
    with pytest.raises(ValueError, match="positive integer"):
        build_guardian("sandbox", hardened=True, permit_ttl_seconds=ttl)


@pytest.mark.parametrize("timestamp", [True, -1, 1.5, float("nan"), float("inf"), None])
def test_invalid_clock_does_not_reserve_authority(timestamp):
    runtime, _, _ = build_guardian("sandbox", hardened=True, clock=lambda: timestamp)
    with pytest.raises(ValueError, match="non-negative integer"):
        runtime.evaluate(sandbox_request())
    assert runtime.capabilities.invocation_count("cap-read-tmp") == 0
    assert runtime._permit_requests == {}


def test_invalid_gateway_clock_rejects_without_tool_execution(monkeypatch):
    runtime, _, _ = build_guardian("sandbox", hardened=True)
    decision = runtime.evaluate(sandbox_request())
    monkeypatch.setattr(runtime.gateway, "_clock", lambda: float("nan"))
    with pytest.raises(PermitError, match="non-negative integer"):
        runtime.gateway.execute(decision.normalized_request, decision.permit)
    assert runtime.gateway.execution_count == 0


def test_expired_pending_requests_are_released_without_refunding_authority():
    clock = [2_000_000_000]
    runtime, _, _ = build_guardian("sandbox", hardened=True, clock=lambda: clock[0])
    decision = runtime.evaluate(sandbox_request())
    assert len(runtime._permit_requests) == 1
    clock[0] += 5
    fresh = runtime.evaluate(replace(sandbox_request(), nonce="fresh"))
    assert fresh.allowed
    assert list(runtime._permit_requests) == [fresh.permit.sequence]
    assert runtime.capabilities.invocation_count("cap-read-tmp") == 2
    with pytest.raises(PermitError, match="expired"):
        runtime.gateway.execute(decision.normalized_request, decision.permit)


def test_revocation_waits_for_in_flight_execution(monkeypatch):
    runtime, _, _ = build_guardian("sandbox", hardened=True)
    decision = runtime.evaluate(sandbox_request())
    checked = Event()
    resume = Event()
    revoking = Event()
    original_check = runtime.environment.check_invariants

    def pause_after_checks(request):
        result = original_check(request)
        checked.set()
        assert resume.wait(timeout=5)
        return result

    def revoke():
        revoking.set()
        runtime.capabilities.revoke("cap-read-tmp")

    monkeypatch.setattr(runtime.environment, "check_invariants", pause_after_checks)
    with ThreadPoolExecutor(max_workers=2) as executor:
        execution = executor.submit(runtime.gateway.execute, decision.normalized_request, decision.permit)
        assert checked.wait(timeout=5)
        revocation = executor.submit(revoke)
        assert revoking.wait(timeout=5)
        try:
            with pytest.raises(TimeoutError):
                revocation.result(timeout=0.1)
        finally:
            resume.set()
        assert execution.result(timeout=5).ok
        revocation.result(timeout=5)

    assert runtime.capabilities.status("cap-read-tmp", 2_000_000_000)[0] is False
    assert not runtime.evaluate(replace(sandbox_request(), nonce="after-revoke")).allowed
    assert_valid_evidence(runtime)
