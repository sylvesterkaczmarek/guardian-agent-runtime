from pathlib import Path

import pytest

from guardian_runtime.factory import build_guardian
from guardian_runtime.policy import (
    Policy,
    PolicyEngine,
    PolicyError,
    PolicyRule,
    PolicyRuntimeState,
    RateLimit,
    ResourceBudget,
)
from guardian_runtime.types import ActionRequest, RuntimeState


def _request(action="actuator_set", subject="agent-1", params=None, nonce="n"):
    return ActionRequest(
        subject=subject,
        session_id="s",
        tool="sandbox",
        action=action,
        params=params or {"value": 1},
        purpose="operations",
        capability_id="cap-actuator",
        nonce=nonce,
    )


def test_policy_parser_rejects_unknown_fields(tmp_path: Path):
    path = tmp_path / "bad.yaml"
    path.write_text("version: v1\ndefault: deny\nunknown: true\nrules: []\n", encoding="utf-8")
    with pytest.raises(PolicyError, match="unknown policy fields"):
        PolicyEngine.from_file(path)


def test_reference_policy_rate_limit_is_enforced():
    runtime, _, _ = build_guardian("sandbox", hardened=True)
    for index in range(5):
        request = ActionRequest(
            subject="agent-1",
            session_id="s",
            tool="sandbox",
            action="network_call",
            params={"target": "mock://safe/service"},
            purpose="operations",
            capability_id="cap-network-safe",
            nonce=f"n-{index}",
        )
        decision, result = runtime.execute_request(request)
        assert decision.allowed and result and result.ok
    sixth = ActionRequest(
        subject="agent-1",
        session_id="s",
        tool="sandbox",
        action="network_call",
        params={"target": "mock://safe/service"},
        purpose="operations",
        capability_id="cap-network-safe",
        nonce="n-6",
    )
    decision, result = runtime.execute_request(sixth)
    assert not decision.allowed and result is None
    assert "rate limit" in decision.reason


def test_emergency_stop_policy_blocks_non_safe_actions():
    runtime, _, _ = build_guardian("mission", hardened=True)
    enter = ActionRequest(
        subject="agent-1",
        session_id="s",
        tool="mission",
        action="enter_safe_mode",
        purpose="operations",
        capability_id="cap-safe-mode",
        nonce="safe",
    )
    assert runtime.execute_request(enter)[0].allowed
    point = ActionRequest(
        subject="agent-1",
        session_id="s",
        tool="mission",
        action="point_payload",
        params={"angle_deg": 1},
        purpose="operations",
        capability_id="cap-point",
        nonce="point-after-safe",
    )
    decision, _ = runtime.execute_request(point)
    assert not decision.allowed
    assert "emergency-stop" in decision.reason


def test_policy_runtime_supports_sequence_separation_budget_and_escalation():
    policy = Policy(
        version="test",
        default="deny",
        rules=(
            PolicyRule("allow-step-a", "allow", tool="sandbox", action="step_a"),
            PolicyRule(
                "allow-step-b",
                "allow",
                tool="sandbox",
                action="step_b",
                separation_of_duty_after=("sandbox:step_a",),
                resource_budget=ResourceBudget("energy", "cost", 5.0),
                rate_limit=RateLimit(2, 60),
            ),
            PolicyRule("escalate-admin", "escalate", tool="sandbox", action="admin"),
        ),
    )
    engine = PolicyEngine(policy)
    runtime = PolicyRuntimeState()
    state = RuntimeState(0, {})
    step_a = _request(action="step_a", params={})
    allowed, _, rule_id = engine.evaluate(step_a, state, now=10, runtime=runtime)
    assert allowed
    engine.record_authorization(rule_id, step_a, now=10, runtime=runtime)

    same_subject = _request(action="step_b", subject="agent-1", params={"cost": 1})
    allowed, reason, _ = engine.evaluate(same_subject, state, now=11, runtime=runtime)
    assert not allowed and "separation of duty" in reason

    other_subject = _request(action="step_b", subject="controller-1", params={"cost": 3})
    allowed, _, rule_id = engine.evaluate(other_subject, state, now=11, runtime=runtime)
    assert allowed
    engine.record_authorization(rule_id, other_subject, now=11, runtime=runtime)

    too_expensive = _request(action="step_b", subject="controller-2", params={"cost": 3})
    allowed, reason, _ = engine.evaluate(too_expensive, state, now=12, runtime=runtime)
    assert not allowed and "resource budget" in reason

    admin = _request(action="admin", params={})
    allowed, reason, _ = engine.evaluate(admin, state, now=12, runtime=runtime)
    assert not allowed and "escalation required" in reason


def test_policy_parser_rejects_string_purpose_and_sequence_fields(tmp_path: Path):
    bad_purpose = tmp_path / "bad-purpose.yaml"
    bad_purpose.write_text(
        "version: v1\ndefault: deny\nrules:\n"
        "  - id: r1\n    effect: allow\n    purpose: operations\n",
        encoding="utf-8",
    )
    with pytest.raises(PolicyError, match="purpose must be a sequence"):
        PolicyEngine.from_file(bad_purpose)

    bad_sequence = tmp_path / "bad-sequence.yaml"
    bad_sequence.write_text(
        "version: v1\ndefault: deny\nrules:\n"
        "  - id: r1\n    effect: allow\n    forbidden_after: sandbox:write\n",
        encoding="utf-8",
    )
    with pytest.raises(PolicyError, match="sequence constraints must be sequences"):
        PolicyEngine.from_file(bad_sequence)


def test_policy_parser_rejects_duplicate_yaml_keys(tmp_path: Path):
    path = tmp_path / "duplicate.yaml"
    path.write_text(
        "version: v1\ndefault: deny\ndefault: allow\nrules: []\n",
        encoding="utf-8",
    )
    with pytest.raises(PolicyError, match="ambiguous policy YAML"):
        PolicyEngine.from_file(path)


def test_policy_temporal_window_and_forbidden_sequence_are_enforced():
    policy = Policy(
        version="test-temporal-sequence",
        default="deny",
        rules=(
            PolicyRule("allow-prepare", "allow", tool="sandbox", action="prepare"),
            PolicyRule(
                "allow-commit",
                "allow",
                tool="sandbox",
                action="commit",
                not_before=10,
                expires_at=20,
                forbidden_after=("sandbox:prepare",),
            ),
        ),
    )
    engine = PolicyEngine(policy)
    runtime = PolicyRuntimeState()
    state = RuntimeState(0, {})
    commit = _request(action="commit", params={})

    assert not engine.evaluate(commit, state, now=9, runtime=runtime)[0]
    allowed, _, rule_id = engine.evaluate(commit, state, now=10, runtime=runtime)
    assert allowed and rule_id == "allow-commit"
    assert not engine.evaluate(commit, state, now=20, runtime=runtime)[0]

    prepare = _request(action="prepare", params={})
    allowed, _, prepare_rule = engine.evaluate(prepare, state, now=11, runtime=runtime)
    assert allowed
    engine.record_authorization(prepare_rule, prepare, now=11, runtime=runtime)
    allowed, reason, _ = engine.evaluate(commit, state, now=12, runtime=runtime)
    assert not allowed and "forbidden action sequence" in reason


def test_policy_parser_accepts_canonical_resource_constraint(tmp_path: Path):
    path = tmp_path / "canonical.yaml"
    path.write_text(
        "version: v1\ndefault: deny\nrules:\n"
        "  - id: proxy\n    effect: allow\n    tool: sandbox\n    action: proxy_call\n"
        "    params:\n      target_resource:\n        required: true\n        canonical_resource: true\n",
        encoding="utf-8",
    )
    engine = PolicyEngine.from_file(path)
    assert engine.version == "v1"
