"""Synthetic boundary regressions from the November implementation audit."""

from dataclasses import replace

import pytest

from guardian_runtime.capabilities import Capability, CapabilityStore, capability_is_subset
from guardian_runtime.crypto import deterministic_private_key
from guardian_runtime.evidence import verify_evidence_bundle
from guardian_runtime.guardian import GuardianRuntime
from guardian_runtime.manifest import sign_manifest, verify_manifest
from guardian_runtime.policy import Policy, PolicyEngine, PolicyRule, RateLimit, ResourceBudget
from guardian_runtime.simulator import SandboxEnvironment
from guardian_runtime.tools import PermitError
from guardian_runtime.types import ActionRequest, RuntimeState, ToolResult

KEY = deterministic_private_key("runtime-integrity-regression-only")


def request(**changes):
    return replace(
        ActionRequest(
            "agent", "review", "sandbox", "read_file", resource="/tmp/input.txt", capability_id="c", nonce="n"
        ),
        **changes,
    )


def runtime(*, rules=(), default="allow", environment=None, constraints=None):
    clock = [100]
    monitor = GuardianRuntime(
        capabilities=CapabilityStore([Capability("c", "agent", "sandbox", "*", constraints=constraints or {})]),
        policy=PolicyEngine(Policy("review-policy", default, tuple(rules))),
        environment=environment or SandboxEnvironment(),
        signing_key=KEY,
        runtime_manifest_hash="a" * 64,
        clock=lambda: clock[0],
    )
    return monitor, clock


@pytest.mark.parametrize("access", ["input", "get", "clone"])
def test_capability_constraints_are_owned_snapshots(access):
    constraints = {"value": {"max": 1, "enum": [0, 1]}}
    store = CapabilityStore([Capability("c", "agent", "sandbox", "*", constraints=constraints)])
    target = (
        constraints
        if access == "input"
        else (store.get("c") if access == "get" else store.clone().get("c")).constraints
    )
    target["value"]["max"] = 10
    target["value"]["enum"].append(5)
    assert not store.validate(request(params={"value": 5}), 100, consume=False)[0]
    assert store.validate(request(params={"value": 1}), 100, consume=False)[0]


@pytest.mark.parametrize("access", ["input", "property"])
@pytest.mark.parametrize("field", ["param_constraints", "state_constraints"])
def test_policy_constraints_are_owned_snapshots(access, field):
    constraints = {"value": {"max": 1}}
    rule = PolicyRule("r", "allow", **{field: constraints})
    engine = PolicyEngine(Policy("v", "deny", (rule,)))
    target = constraints if access == "input" else getattr(engine.policy.rules[0], field)
    target["value"]["max"] = 10
    assert not engine.evaluate(request(params={"value": 5}), RuntimeState(0, {"value": 5}), now=100)[0]


@pytest.mark.parametrize("value", [True, False, {"x": True}, [True]])
def test_capability_enum_keeps_boolean_and_numeric_values_distinct(value):
    number = 0 if value is False else {"x": 1} if isinstance(value, dict) else [1] if isinstance(value, list) else 1
    store = CapabilityStore([Capability("c", "agent", "sandbox", "*", constraints={"value": {"enum": [number]}})])
    assert not store.validate(request(params={"value": value}), 100, consume=False)[0]
    assert store.validate(request(params={"value": number}), 100, consume=False)[0]


@pytest.mark.parametrize(
    ("operator", "value"),
    [
        (op, value)
        for op in ("eq", "in", "literal")
        for value in (True, {"nested": True}, [True])
        if not (op == "literal" and isinstance(value, dict))
    ],
)
def test_policy_comparisons_preserve_json_boolean_types(operator, value):
    number = {"nested": 1} if isinstance(value, dict) else [1] if isinstance(value, list) else 1
    constraint = number if operator == "literal" else {operator: [number] if operator == "in" else number}
    engine = PolicyEngine(Policy("v", "deny", (PolicyRule("r", "allow", param_constraints={"v": constraint}),)))
    assert not engine.evaluate(request(params={"v": value}), RuntimeState(0, {}))[0]
    assert engine.evaluate(request(params={"v": number}), RuntimeState(0, {}))[0]


def test_delegation_enum_cannot_substitute_boolean_for_integer():
    parent = Capability("p", "agent", "sandbox", "*", constraints={"v": {"enum": [1]}}, delegation_depth=1)
    child = replace(
        parent, capability_id="child", parent_id="p", delegation_depth=0, constraints={"v": {"enum": [True]}}
    )
    assert not capability_is_subset(child, parent)


@pytest.mark.parametrize("access", ["events", "append", "export", "bundle"])
def test_audit_readers_cannot_mutate_internal_signed_events(access):
    monitor, _ = runtime()
    decision, result = monitor.execute_request(request())
    if access == "append":
        event = monitor.evidence.append(
            timestamp=100, request=request(), decision=decision, policy_version=monitor.policy.version, result=result
        )
        event.requested_action["params"]["changed"] = 1
    elif access == "events":
        monitor.evidence.events[0].normalized_action["params"]["changed"] = 1
    elif access == "export":
        monitor.evidence.export()[0]["requested_action"]["params"]["changed"] = 1
    else:
        monitor.evidence.export_bundle(policy_version=monitor.policy.version)["events"][0]["requested_action"][
            "params"
        ]["changed"] = 1
    assert verify_evidence_bundle(
        monitor.evidence.export_bundle(policy_version=monitor.policy.version), monitor.public_key
    )[0]


def test_signing_manifest_detaches_nested_input():
    original = {"policy": {"versions": [1]}}
    signed = sign_manifest(original, KEY)
    original["policy"]["versions"].append(2)
    assert verify_manifest(signed, KEY.public_key())
    assert signed.manifest["policy"]["versions"] == [1]


@pytest.mark.parametrize("execution_time", [101, 102])
def test_permit_does_not_outlive_allow_rule(execution_time):
    monitor, clock = runtime(default="deny", rules=[PolicyRule("r", "allow", expires_at=101)])
    decision = monitor.evaluate(request())
    assert decision.allowed
    assert decision.permit.expires_at == 101
    clock[0] = execution_time
    with pytest.raises(PermitError):
        monitor.gateway.execute(decision.normalized_request, decision.permit)
    assert monitor.gateway.execution_count == 0


@pytest.mark.parametrize("effect", ["deny", "escalate"])
def test_future_restriction_is_rechecked_before_execution(effect):
    monitor, clock = runtime(rules=[PolicyRule("later", effect, not_before=101)])
    decision = monitor.evaluate(request())
    assert decision.allowed
    clock[0] = 101
    with pytest.raises(PermitError, match="policy"):
        monitor.gateway.execute(decision.normalized_request, decision.permit)
    assert monitor.gateway.execution_count == 0


def test_execution_recheck_does_not_reserve_budget_twice():
    monitor, _ = runtime(
        default="deny",
        constraints={"cost": {}},
        rules=[PolicyRule("r", "allow", rate_limit=RateLimit(1, 10), resource_budget=ResourceBudget("b", "cost", 1))],
    )
    decision, result = monitor.execute_request(request(params={"cost": 1}))
    assert decision.allowed and result.ok
    assert monitor.capabilities.invocation_count("c") == 1
    assert monitor.policy_runtime.resource_usage["b"] == 1
    assert len(monitor.policy_runtime.rule_hits["r"]) == 1


@pytest.mark.parametrize(
    "bad",
    [
        None,
        {},
        ToolResult("yes", "bad"),
        ToolResult(True, ""),
        ToolResult(True, "bad", output=[]),
        ToolResult(True, "bad", output={"value": float("nan")}),
        ToolResult(True, "bad", state_version=True),
    ],
)
def test_malformed_tool_result_is_failed_and_audited_without_retry(bad):
    class BadOutput(SandboxEnvironment):
        def execute(self, proposed):
            self.state.version += 1
            return bad

    monitor, _ = runtime(environment=BadOutput())
    decision, result = monitor.execute_request(request())
    assert decision.allowed and result is not None and result.ok is False
    assert result.status == "invalid-tool-result"
    assert len(monitor.evidence.events) == 1
    assert monitor.evidence.events[0].result_digest
    assert verify_evidence_bundle(
        monitor.evidence.export_bundle(policy_version=monitor.policy.version), monitor.public_key
    )[0]
    with pytest.raises(PermitError, match="replay"):
        monitor.gateway.execute(decision.normalized_request, decision.permit)
    assert monitor.gateway.execution_count == 1


def test_valid_tool_output_is_detached_from_producer():
    output = {"nested": [1]}

    class Output(SandboxEnvironment):
        def execute(self, proposed):
            return ToolResult(True, "read", output=output)

    monitor, _ = runtime(environment=Output())
    _, result = monitor.execute_request(request())
    output["nested"].append(2)
    assert result.output == {"nested": [1]}


def test_mapping_constraints_cannot_hide_invalid_fields_when_snapshotted():
    from types import MappingProxyType
    from guardian_runtime.capabilities import CapabilityError
    from guardian_runtime.policy import PolicyError

    hidden = MappingProxyType({"unsupported": "would otherwise be ignored"})
    with pytest.raises(CapabilityError):
        CapabilityStore([Capability("c", "agent", "sandbox", "*", constraints={"v": hidden})])
    with pytest.raises(PolicyError):
        PolicyEngine(Policy("v", "deny", (PolicyRule("r", "allow", param_constraints={"v": hidden}),)))


def test_policy_rejects_one_shot_rules_iterator():
    from guardian_runtime.policy import PolicyError

    with pytest.raises(PolicyError, match="sequence"):
        PolicyEngine(Policy("v", "allow", iter([PolicyRule("r", "deny")])))


def test_policy_replacement_cannot_reuse_older_permit():
    monitor, _ = runtime()
    decision = monitor.evaluate(request())
    monitor.policy = PolicyEngine(Policy("new-version", "allow", ()))
    with pytest.raises(PermitError, match="version"):
        monitor.gateway.execute(decision.normalized_request, decision.permit)
    assert monitor.gateway.execution_count == 0


@pytest.mark.parametrize("operator", ["forbid", "not_in", "neq"])
def test_negative_constraints_retain_numeric_equivalence_but_not_boolean_aliases(operator):
    if operator == "forbid":
        store = CapabilityStore([Capability("c", "agent", "sandbox", "*", constraints={"v": {"forbid": [1]}})])
        evaluate = lambda value: store.validate(request(params={"v": value}), 100, consume=False)[0]
    else:
        constraint = {operator: [1] if operator == "not_in" else 1}
        engine = PolicyEngine(Policy("v", "deny", (PolicyRule("r", "allow", param_constraints={"v": constraint}),)))
        evaluate = lambda value: engine.evaluate(request(params={"v": value}), RuntimeState(0, {}))[0]
    assert evaluate(True)
    assert not evaluate(1)
    assert not evaluate(1.0)
