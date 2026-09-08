from dataclasses import replace
from fractions import Fraction
from threading import Event, Thread
import sys

import pytest

from guardian_runtime.canonical import CanonicalizationError, canonical_json, canonicalize_request
from guardian_runtime.capabilities import Capability, CapabilityError, CapabilityStore, capability_is_subset
from guardian_runtime.factory import build_guardian
from guardian_runtime.policy import Policy, PolicyEngine, PolicyError, PolicyRule, PolicyRuntimeState, RateLimit, ResourceBudget
from guardian_runtime.types import ActionRequest, RuntimeState


def _capability(**changes):
    return replace(Capability("cap", "agent", "sandbox", "action", constraints={"cost": {}}), **changes)


def _request(**changes):
    return replace(ActionRequest("agent", "session", "sandbox", "action", params={"cost": 1}, capability_id="cap", nonce="n"), **changes)


def _budget_engine(limit):
    return PolicyEngine(Policy("v1", "deny", (PolicyRule("allow", "allow", resource_budget=ResourceBudget("energy", "cost", limit)),)))


@pytest.mark.parametrize("field", ["not_before", "expires_at", "max_invocations", "delegation_depth"])
@pytest.mark.parametrize("value", [float("nan"), float("inf"), True, 1.5])
def test_capability_time_and_counter_fields_require_integers(field, value):
    with pytest.raises(CapabilityError, match=f"{field} must be an integer"):
        CapabilityStore([_capability(**{field: value})])


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
@pytest.mark.parametrize("constraint", ["min", "max", "enum"])
def test_capability_constraints_reject_non_finite_configuration(value, constraint):
    bound = [value] if constraint == "enum" else value
    with pytest.raises(CapabilityError, match="non-finite"):
        CapabilityStore([_capability(constraints={"cost": {constraint: bound}})])


def test_capability_sequence_cannot_be_a_string():
    with pytest.raises(CapabilityError, match="purpose must be a sequence"):
        CapabilityStore([_capability(purpose="operations")])


@pytest.mark.parametrize("now", [float("nan"), float("inf"), True, 1.5, -1])
def test_invalid_clocks_cannot_bypass_capability_or_policy_checks(now):
    store = CapabilityStore([_capability()])
    assert not store.status("cap", now)[0]
    assert not store.validate(_request(), now)[0]
    assert store.invocation_count("cap") == 0
    engine = _budget_engine(10)
    state = PolicyRuntimeState()
    assert not engine.evaluate(_request(), RuntimeState(0, {}), now=now, runtime=state)[0]
    with pytest.raises(PolicyError, match="policy time"):
        engine.record_authorization("allow", _request(), now=now, runtime=state)
    assert state == PolicyRuntimeState()


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_direct_capability_validation_rejects_non_finite_values(value):
    store = CapabilityStore([_capability(constraints={"cost": {"min": 0, "max": 5}})])
    assert not store.validate(_request(params={"cost": value}), 10)[0]
    assert store.invocation_count("cap") == 0


@pytest.mark.parametrize(("literal", "boolean"), [(0, False), (0.0, False), (1, True), (1.0, True)])
def test_literal_delegation_preserves_numeric_parent_exclusion_of_booleans(literal, boolean):
    parent = _capability(constraints={"cost": {"min": 0, "max": 1}}, delegation_depth=1)
    child = replace(parent, capability_id="child", parent_id="cap", delegation_depth=0, constraints={"cost": literal})
    store = CapabilityStore([parent, child])
    request = _request(capability_id="child", params={"cost": boolean})
    assert not store.validate(request, 10)[0]
    assert store.validate(replace(request, params={"cost": literal}), 10)[0]


@pytest.mark.parametrize(("parent_value", "child_value"), [(0, False), (False, 0), (1, True), (True, 1)])
def test_literal_delegation_does_not_exchange_boolean_and_numeric_authority(parent_value, child_value):
    parent = _capability(constraints={"cost": parent_value}, delegation_depth=1)
    child = replace(parent, capability_id="child", parent_id="cap", delegation_depth=0, constraints={"cost": child_value})
    assert not capability_is_subset(child, parent)


def test_capability_transaction_lock_serialises_revocation():
    store = CapabilityStore([_capability()])
    entered = Event()
    finished = Event()

    def revoke():
        entered.set()
        store.revoke("cap")
        finished.set()

    with store.transaction_lock:
        worker = Thread(target=revoke)
        worker.start()
        assert entered.wait(2)
        assert not finished.wait(0.05)
        assert store.status("cap", 10)[0]
    worker.join(2)
    assert not worker.is_alive()
    assert finished.is_set()
    assert not store.status("cap", 10)[0]


@pytest.mark.parametrize("limit", [float("nan"), float("inf"), float("-inf"), True])
def test_policy_rejects_invalid_budget_limits(limit):
    with pytest.raises(PolicyError, match="resource_budget limit"):
        _budget_engine(limit)


@pytest.mark.parametrize("changes", [
    {"param_constraints": {"cost": {"unknown": 1}}},
    {"state_constraints": {"power": {"min": float("nan")}}},
    {"purpose": "operations"},
    {"not_before": float("nan")},
    {"rate_limit": RateLimit(float("nan"), 10)},
    {"rate_limit": RateLimit(1, True)},
])
def test_direct_policy_construction_validates_rules(changes):
    with pytest.raises(PolicyError):
        PolicyEngine(Policy("v1", "deny", (PolicyRule("allow", "allow", **changes),)))


def test_state_constraint_cannot_hide_invalid_param_constraint_in_yaml(tmp_path):
    config = tmp_path / "policy.yaml"
    config.write_text(
        "version: v1\nrules:\n  - id: allow\n    effect: allow\n"
        "    params:\n      cost:\n        unknown: 1\n"
        "    state:\n      cost:\n        min: 0\n", encoding="utf-8",
    )
    with pytest.raises(PolicyError, match="unknown constraint"):
        PolicyEngine.from_file(config)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf"), True, -1])
def test_invalid_budget_cost_does_not_mutate_authority_state(value):
    engine = _budget_engine(100)
    state = PolicyRuntimeState()
    request = _request(params={"cost": value})
    assert not engine.evaluate(request, RuntimeState(0, {}), runtime=state)[0]
    with pytest.raises(PolicyError, match="invalid resource budget cost"):
        engine.record_authorization("allow", request, now=10, runtime=state)
    assert state == PolicyRuntimeState()


def test_budget_does_not_round_away_small_costs_after_large_usage():
    engine = _budget_engine(2**53)
    state = PolicyRuntimeState()
    first = _request(params={"cost": 2**53})
    assert engine.evaluate(first, RuntimeState(0, {}), runtime=state)[0]
    engine.record_authorization("allow", first, now=10, runtime=state)
    assert not engine.evaluate(_request(), RuntimeState(0, {}), runtime=state)[0]
    assert state.resource_usage["energy"] == 2**53


def test_budget_accounts_for_decimal_costs_exactly_and_clones_them():
    engine = _budget_engine(0.3)
    state = PolicyRuntimeState()
    for cost in (0.1, 0.2):
        request = _request(params={"cost": cost})
        assert engine.evaluate(request, RuntimeState(0, {}), runtime=state)[0]
        engine.record_authorization("allow", request, now=10, runtime=state)
    assert state.resource_usage["energy"] == Fraction(3, 10)
    assert state.clone().resource_usage == state.resource_usage
    assert not engine.evaluate(_request(params={"cost": 0.000001}), RuntimeState(0, {}), runtime=state)[0]


def test_huge_budget_cost_is_rejected_without_float_overflow():
    engine = _budget_engine(1)
    assert not engine.evaluate(_request(params={"cost": 10**400}), RuntimeState(0, {}))[0]


def test_yaml_budget_preserves_large_integer_limit(tmp_path):
    config = tmp_path / "policy.yaml"
    limit = 2**53 + 3
    config.write_text(
        "version: v1\nrules:\n  - id: allow\n    effect: allow\n"
        f"    resource_budget:\n      key: energy\n      cost_param: cost\n      max_total: {limit}\n",
        encoding="utf-8",
    )
    engine = PolicyEngine.from_file(config)
    assert engine.evaluate(_request(params={"cost": limit}), RuntimeState(0, {}))[0]
    assert not engine.evaluate(_request(params={"cost": limit + 1}), RuntimeState(0, {}))[0]


@pytest.mark.parametrize("field", ["subject", "session_id", "tool", "action", "resource", "purpose", "capability_id", "nonce"])
def test_request_rejects_unencodable_unicode_identifiers(field):
    with pytest.raises(CanonicalizationError, match="Unicode scalar"):
        canonicalize_request(_request(**{field: "bad\ud800"}))


@pytest.mark.parametrize("value", ["\ud800", {"\udfff": "value"}, {"nested": ["\ud800"]}])
def test_json_rejects_unencodable_unicode_recursively(value):
    with pytest.raises(CanonicalizationError, match="Unicode scalar"):
        canonical_json(value)


def test_invalid_unicode_request_is_denied_before_capability_consumption():
    runtime, _, _ = build_guardian("sandbox", hardened=True)
    request = ActionRequest("agent-1", "s", "sandbox", "write_file", resource="/tmp/test", params={"content": "\ud800"}, purpose="operations", capability_id="cap-write-tmp", nonce="unicode")
    decision = runtime.evaluate(request)
    assert not decision.allowed
    assert "canonicalization failed" in decision.reason
    assert runtime.capabilities.invocation_count("cap-write-tmp") == 0


def test_oversized_integer_is_denied_before_capability_consumption():
    limit = sys.get_int_max_str_digits()
    if limit == 0:
        pytest.skip("interpreter integer digit limit is disabled")
    with pytest.raises(CanonicalizationError, match="JSON digit limit"):
        canonicalize_request(_request(params={"cost": 10**limit}))


@pytest.mark.parametrize("field", ["params", "context"])
def test_deep_request_is_denied_before_capability_consumption(field):
    value = "x"
    for _ in range(500):
        value = {"nested": value}
    runtime, _, _ = build_guardian("sandbox", hardened=True)
    request = ActionRequest("agent-1", "s", "sandbox", "write_file", resource="/tmp/deep", params={"content": "x"}, purpose="operations", capability_id="cap-write-tmp", nonce="deep")
    request = replace(request, **{field: {"content": value}})
    decision = runtime.evaluate(request)
    assert not decision.allowed
    assert "nesting exceeds" in decision.reason
    assert runtime.capabilities.invocation_count("cap-write-tmp") == 0


def test_cyclic_json_fails_with_a_canonicalisation_error():
    value = {}
    value["cycle"] = value
    with pytest.raises(CanonicalizationError, match="nesting exceeds"):
        canonical_json(value)
